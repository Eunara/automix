"""
utils.py — Shared utilities for chkr checker modules and web app.

Centralises: session builders, proxy config, BIN lookup, identity helpers,
             address pools, product discovery, string helpers.
"""

import json
import random
import re
import secrets
from collections import OrderedDict

import requests
import urllib3

urllib3.disable_warnings()

REQUEST_TIMEOUT = 30

# ── Browser User-Agents ───────────────────────────────────────────────────────

BROWSER_UAs = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
]



def random_ua() -> str:
    """Return a random browser user-agent string."""
    return random.choice(BROWSER_UAs)


# ── Proxy / Session builders ──────────────────────────────────────────────────

PROXIES: dict = {
    "proxyverse": {
        "host": "proxy.proxyverse.io:9200",
        "auth": "country-us:431583b3-a951-4697-a852-652946d45187",
    },
    "scrapeless": {
        "host": "gw-us.scrapeless.io:8789",
        "auth": "5B1530171B49-proxy-country_US-r_1m-s_U90LanQB2r:trfnAxRM",
    },
}


def get_proxy(name: str = None) -> dict:
    if name and name != "rotate":
        p = PROXIES[name]
    else:
        p = random.choice(list(PROXIES.values()))
    url = f"http://{p['auth']}@{p['host']}"
    return {"http": url, "https": url}


def build_plain_session() -> requests.Session:
    """Plain session without proxy — for local API calls."""
    s = requests.Session()
    s.headers.clear()
    s.verify = False
    return s


def build_session(proxy: str = None) -> requests.Session:
    """Session with named proxy pre-configured."""
    s = requests.Session()
    s.headers.clear()
    s.proxies.update(get_proxy(proxy))
    s.verify = False
    return s


def build_session_from_str(proxy_str: str) -> requests.Session:
    """Build a session from a raw proxy string supplied by the user.

    Accepted formats:
      host:port
      user:pass@host:port
      protocol://user:pass@host:port
    """
    s = requests.Session()
    s.headers.clear()
    p = proxy_str.strip()
    if p and not re.match(r"^https?://", p):
        p = "http://" + p
    s.proxies.update({"http": p, "https": p})
    s.verify = False
    return s


# ── BIN lookup ────────────────────────────────────────────────────────────────


def iso_to_flag(iso: str) -> str:
    iso = iso.upper()
    return chr(127397 + ord(iso[0])) + chr(127397 + ord(iso[1]))


def fetch_bin_info(bin6: str) -> str:
    """Fetch compact BIN info from binx.vip.
    Returns e.g. 'VISA CREDIT · Chase · US 🇺🇸' or '' on failure.
    """
    d = fetch_bin_dict(bin6)
    if not d:
        return ""
    brand   = d.get("brand", "")
    cat     = d.get("type", "")
    bank    = d.get("bank", "")
    country = d.get("iso_code_2", "")
    flag    = iso_to_flag(country) if country else ""
    parts   = [
        x for x in [
            brand + (" " + cat if cat else ""),
            bank,
            country + " " + flag,
        ]
        if x.strip()
    ]
    return " · ".join(parts)


def fetch_bin_dict(bin6: str) -> dict:
    """Fetch raw BIN data dict from binx.vip.
    Returns dict with keys: brand, type, category, bank, country_name,
    iso_code_2 — or {} on failure.
    """
    try:
        s = requests.Session()
        s.headers.update({"Accept": "application/json"})
        s.verify = False
        r = s.get(f"https://api.binx.vip/api/bins/{bin6}", timeout=8)
        d = r.json().get("data") or {}
        if d.get("iso_code_2"):
            return d
    except Exception:
        pass
    return {}


# ── String / card helpers ─────────────────────────────────────────────────────


def get_str(text: str, start: str, end: str) -> str:
    """Extract substring between two delimiter strings."""
    try:
        return text.split(start, 1)[1].split(end, 1)[0]
    except (IndexError, AttributeError):
        return ""


def detect_card_type(cc: str) -> str:
    """Return VI / MC / AE / DI based on card number first digit."""
    first = cc[0] if cc else "4"
    if first == "3":
        return "AE"
    elif first == "5":
        return "MC"
    elif first == "6":
        return "DI"
    return "VI"


def session_id() -> str:
    """Generate a UUID-shaped random session identifier."""
    return "{}-{}-{}-{}-{}".format(
        secrets.token_hex(4),
        secrets.token_hex(2),
        secrets.token_hex(2),
        secrets.token_hex(2),
        secrets.token_hex(6),
    )


def convert_year(y: str) -> str:
    """Expand 2-digit year to 4-digit (e.g. '26' → '2026')."""
    y = str(y).strip()
    return "20" + y if len(y) == 2 and y.isdigit() else y


def parse_domain(raw: str) -> str:
    """Strip protocol / path / query / fragment and return bare hostname."""
    raw = raw.strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    return raw.strip()


# ── Fallback identity ─────────────────────────────────────────────────────────

_FALLBACK_IDENTITY = {
    "fname":        "Joelle",
    "lname":        "McVicker",
    "full_name":    "Joelle McVicker",
    "email":        "joelleyo@hotmail.com",
    "password":     "SysRq123@@@",
    "phone":        "3216147391",
    "user_agent":   BROWSER_UAs[0],
    "street":       "148 KRISTI DR",
    "city":         "Satellite Beach",
    "zip":          "32937",
    "state":        "FL",
    "state_full":   "Florida",
    "country":      "US",
    "country_full": "United States",
}


def fetch_identity(plain_session: requests.Session = None) -> dict:
    """Fetch a random US identity from the local eonxgen API.
    Falls back to _FALLBACK_IDENTITY if the API is unavailable.
    """
    if plain_session is None:
        plain_session = build_plain_session()
    try:
        r = plain_session.get("http://127.0.0.1:8001/api?nat=us", timeout=10)
        data = r.json()
        if data and "person" in data and "address" in data:
            person = data["person"]
            addr   = data["address"]
            return {
                "fname":        person["first_name"],
                "lname":        person["last_name"],
                "full_name":    f"{person['first_name']} {person['last_name']}",
                "email":        person["email"],
                "password":     person.get("password", "SysRq123@@@"),
                "phone":        addr["phone"],
                "user_agent":   person.get("user-agent", BROWSER_UAs[0]),
                "region_id":    addr.get("region_id", ""),
                "street":       addr["street"],
                "city":         addr["city"],
                "zip":          addr["postcode"],
                "state":        addr["state"],
                "state_full":   addr["full_state"],
                "country":      "US",
                "country_full": "United States",
            }
    except Exception:
        pass
    return dict(_FALLBACK_IDENTITY)


# ── Name / email generators ───────────────────────────────────────────────────

_FIRST_NAMES = [
    "John", "Kyla", "Sarah", "Michael", "Emma", "James", "Olivia", "William", "Ava", "Benjamin",
    "Isabella", "Jacob", "Lily", "Daniel", "Mia", "Alexander", "Charlotte", "Samuel", "Sophia", "Matthew",
    "Amelia", "David", "Chloe", "Luke", "Ella", "Henry", "Grace", "Andrew", "Natalie", "Ethan",
    "Harper", "Jack", "Scarlett", "Ryan", "Abigail", "Noah", "Leah", "Joshua", "Zoe", "Caleb",
    "Alice", "Nathan", "Hannah", "Isaac", "Victoria", "Mason", "Audrey", "Elijah", "Evelyn", "Dylan",
    "Madison", "Aaron", "Lucy", "Thomas", "Ruby", "Christopher", "Penelope", "George", "Logan", "Ellie",
]

_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor",
    "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin", "Thompson", "Garcia", "Martinez", "Roberts",
    "Walker", "Perez", "Young", "Allen", "King", "Wright", "Scott", "Green", "Adams", "Baker",
    "Gonzalez", "Nelson", "Carter", "Mitchell", "Evans", "Collins", "Stewart", "Sanchez", "Morales", "Murphy",
    "Cook", "Rogers", "Morgan", "Bell", "Cooper", "Reed", "Bailey", "Gomez", "Lambert", "Parker",
    "Watson", "Brooks", "Kelly", "Sanders", "Price", "Bennett", "Wood", "Barnes", "Ross", "Hughes",
]

_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "icloud.com", "zoho.com",
    "aol.com", "protonmail.com", "hotmail.com", "mail.com", "live.com",
    "fastmail.com", "gmx.com", "ymail.com", "tutanota.com", "inbox.com",
]


def _generate_random_name() -> tuple:
    """Return (first_name, last_name) picked randomly."""
    return random.choice(_FIRST_NAMES), random.choice(_LAST_NAMES)


def _generate_random_email(fname: str, lname: str) -> str:
    """Generate a plausible random email from a name."""
    num    = random.randint(100, 999)
    domain = random.choice(_EMAIL_DOMAINS)
    return f"{fname.lower()}.{lname.lower()}{num}@{domain}"


# ── Country-based address pools ───────────────────────────────────────────────

ADDRESS_POOLS: dict = {
    "GB": [
        {"street": "10 Downing Street",          "city": "London",        "zip": "SW1A 2AA", "state": "",    "phone": "+44 20 7925 0918"},
        {"street": "221B Baker Street",          "city": "London",        "zip": "NW1 6XE",  "state": "",    "phone": "+44 20 7224 3688"},
        {"street": "160 Piccadilly",             "city": "London",        "zip": "W1J 9EB",  "state": "",    "phone": "+44 20 7493 4944"},
        {"street": "30 St Mary Axe",             "city": "London",        "zip": "EC3A 8BF", "state": "",    "phone": "+44 20 7626 1600"},
        {"street": "14 Regent Street",           "city": "London",        "zip": "SW1Y 4PH", "state": "",    "phone": "+44 20 7930 0800"},
    ],
    "AU": [
        {"street": "123 George Street",          "city": "Sydney",        "zip": "2000",  "state": "NSW",  "phone": "+61 2 1234 5678"},
        {"street": "456 Collins Street",         "city": "Melbourne",     "zip": "3000",  "state": "VIC",  "phone": "+61 3 8765 4321"},
        {"street": "789 Queen Street",           "city": "Brisbane",      "zip": "4000",  "state": "QLD",  "phone": "+61 7 9876 5432"},
        {"street": "202 Murray Street",          "city": "Perth",         "zip": "6000",  "state": "WA",   "phone": "+61 8 8765 4321"},
        {"street": "303 Hobart Road",            "city": "Hobart",        "zip": "7000",  "state": "TAS",  "phone": "+61 3 1234 9876"},
    ],
    "CA": [
        {"street": "123 Main Street",            "city": "Toronto",       "zip": "M5H 2N2", "state": "Ontario",           "phone": "(416) 555-0123"},
        {"street": "456 Maple Avenue",           "city": "Vancouver",     "zip": "V6E 1B5", "state": "British Columbia",  "phone": "(604) 555-7890"},
        {"street": "789 King Street",            "city": "Montreal",      "zip": "H3A 1J9", "state": "Quebec",            "phone": "(514) 555-3456"},
        {"street": "101 Wellington Street",      "city": "Ottawa",        "zip": "K1A 0A9", "state": "Ontario",           "phone": "(613) 555-6789"},
    ],
    "NZ": [
        {"street": "248 Princes Street",         "city": "Grafton",       "zip": "1010",  "state": "Auckland",   "phone": "(028) 8784-059"},
        {"street": "75 Queen Street",            "city": "Auckland",      "zip": "1010",  "state": "Auckland",   "phone": "(029) 1234-567"},
        {"street": "153 Featherston Street",     "city": "Wellington",    "zip": "6011",  "state": "Wellington", "phone": "(022) 3333-444"},
    ],
    "SG": [
        {"street": "10 Anson Road",              "city": "Singapore",     "zip": "079903", "state": "Central Region", "phone": "(+65) 6221-1234"},
        {"street": "1 Raffles Place",            "city": "Singapore",     "zip": "048616", "state": "Central Region", "phone": "(+65) 6532-5678"},
        {"street": "400 Orchard Road",           "city": "Singapore",     "zip": "238875", "state": "Central Region", "phone": "(+65) 6738-1122"},
    ],
    "MY": [
        {"street": "No 56, Jalan Bukit Bintang", "city": "Kuala Lumpur", "zip": "55100", "state": "Wilayah Persekutuan", "phone": "+60 3-1234 5678"},
        {"street": "No 78, Jalan Ampang",        "city": "Kuala Lumpur", "zip": "50450", "state": "Wilayah Persekutuan", "phone": "+60 3-8765 4321"},
        {"street": "45, Jalan Merdeka",          "city": "George Town",  "zip": "10200", "state": "Penang",              "phone": "+60 4-222 3333"},
    ],
    "PH": [
        {"street": "1234 Makati Ave",            "city": "Makati",        "zip": "1200",  "state": "Metro Manila",  "phone": "+63 2 1234 5678"},
        {"street": "5678 Bonifacio Drive",       "city": "Taguig",        "zip": "1634",  "state": "Metro Manila",  "phone": "+63 2 8765 4321"},
        {"street": "4321 Quezon Blvd",           "city": "Quezon City",   "zip": "1100",  "state": "Metro Manila",  "phone": "+63 2 3344 5566"},
    ],
    "NL": [
        {"street": "1 Dam Square",               "city": "Amsterdam",     "zip": "1012 JS", "state": "North Holland", "phone": "(+31) 20-555-1234"},
        {"street": "50 Binnenrotte",             "city": "Rotterdam",     "zip": "3011 HC", "state": "South Holland", "phone": "(+31) 10-234-5678"},
        {"street": "5 Domplein",                 "city": "Utrecht",       "zip": "3512 JC", "state": "Utrecht",       "phone": "(+31) 30-555-7890"},
    ],
    "ZA": [
        {"street": "10 Adderley Street",         "city": "Cape Town",     "zip": "8000",  "state": "Western Cape",   "phone": "(+27) 21-123-4567"},
        {"street": "150 Rivonia Road",           "city": "Sandton",       "zip": "2196",  "state": "Gauteng",        "phone": "(+27) 11-234-5678"},
        {"street": "45 Florida Road",            "city": "Durban",        "zip": "4001",  "state": "KwaZulu-Natal",  "phone": "(+27) 31-345-6789"},
    ],
    "HK": [
        {"street": "1 Queen's Road Central",     "city": "Central",       "zip": "",      "state": "Hong Kong Island", "phone": "(+852) 2523-1234"},
        {"street": "15 Salisbury Road",          "city": "Tsim Sha Tsui", "zip": "",      "state": "Kowloon",          "phone": "(+852) 2312-3456"},
        {"street": "88 Gloucester Road",         "city": "Wan Chai",      "zip": "",      "state": "Hong Kong Island", "phone": "(+852) 2598-5678"},
    ],
    "TH": [
        {"street": "123 Sukhumvit Road",         "city": "Bangkok",       "zip": "10110", "state": "Bangkok",    "phone": "(+66) 2-123-4567"},
        {"street": "456 Silom Road",             "city": "Bangkok",       "zip": "10500", "state": "Bangkok",    "phone": "(+66) 2-234-5678"},
        {"street": "789 Nimmanhemin Road",       "city": "Chiang Mai",    "zip": "50200", "state": "Chiang Mai", "phone": "(+66) 53-345-678"},
    ],
    "JP": [
        {"street": "1 Chome-1-2 Oshiage",        "city": "Sumida City",   "zip": "131-0045", "state": "Tokyo", "phone": "+81 3-1234-5678"},
        {"street": "2-3-4 Shinjuku",             "city": "Shinjuku",      "zip": "160-0022", "state": "Tokyo", "phone": "+81 3-8765-4321"},
        {"street": "3 Chome-5-6 Akihabara",      "city": "Chiyoda City",  "zip": "101-0021", "state": "Tokyo", "phone": "+81 3-2345-6789"},
    ],
    "US": [
        {"street": "350 Fifth Avenue",           "city": "New York",      "zip": "10118", "state": "NY", "phone": "+1 212-736-3100"},
        {"street": "1 Infinite Loop",            "city": "Cupertino",     "zip": "95014", "state": "CA", "phone": "+1 408-996-1010"},
        {"street": "160 Spear Street",           "city": "San Francisco", "zip": "94105", "state": "CA", "phone": "+1 415-555-0199"},
        {"street": "1 Microsoft Way",            "city": "Redmond",       "zip": "98052", "state": "WA", "phone": "+1 425-882-8080"},
        {"street": "1600 Pennsylvania Avenue NW","city": "Washington",    "zip": "20500", "state": "DC", "phone": "+1 202-456-1111"},
    ],
}


def get_country_for_domain(domain: str) -> str:
    """Return ISO-2 country code based on domain TLD."""
    d = domain.lower()
    if d.endswith(".co.uk") or d.endswith(".org.uk") or d.endswith(".me.uk"):
        return "GB"
    if d.endswith(".com.au") or d.endswith(".net.au") or d.endswith(".org.au"):
        return "AU"
    if d.endswith(".ca"):
        return "CA"
    if d.endswith(".co.nz") or d.endswith(".net.nz"):
        return "NZ"
    if d.endswith(".sg"):
        return "SG"
    if d.endswith(".my"):
        return "MY"
    if d.endswith(".ph"):
        return "PH"
    if d.endswith(".nl"):
        return "NL"
    if d.endswith(".co.za"):
        return "ZA"
    if d.endswith(".hk"):
        return "HK"
    if d.endswith(".th"):
        return "TH"
    if d.endswith(".jp"):
        return "JP"
    return "US"


def get_address_for_country(country: str) -> dict:
    """Return a random address dict for the given ISO-2 country code."""
    pool = ADDRESS_POOLS.get(country, ADDRESS_POOLS["US"])
    return random.choice(pool)


def get_billing_identity(domain: str) -> dict:
    """Return a billing identity dict for a given domain.

    Strategy: try eonxgen first (US identity); if it is unavailable,
    fall back to the country address pool derived from the domain TLD.
    Name and email are always freshly randomised regardless of source.
    """
    fname, lname = _generate_random_name()
    email        = _generate_random_email(fname, lname)

    # Try eonxgen
    identity = fetch_identity()

    if identity.get("fname") != _FALLBACK_IDENTITY["fname"]:
        # eonxgen returned real data — override name/email for freshness
        identity["fname"]     = fname
        identity["lname"]     = lname
        identity["full_name"] = f"{fname} {lname}"
        identity["email"]     = email
        return identity

    # Fallback: country pool
    country = get_country_for_domain(domain)
    addr    = get_address_for_country(country)
    return {
        "fname":    fname,
        "lname":    lname,
        "email":    email,
        "phone":    addr["phone"],
        "street":   addr["street"],
        "city":     addr["city"],
        "zip":      addr["zip"],
        "state":    addr["state"],
        "country":  country,
        "password": f"Pass{random.randint(1000, 9999)}!",
    }


# ── Product discovery ─────────────────────────────────────────────────────────

_PRODUCT_CACHE: OrderedDict = OrderedDict()
_PRODUCT_CACHE_MAX = 500


def _cache_put(domain: str, product_id: str) -> None:
    """Insert into LRU product cache, evicting oldest entry when full."""
    if len(_PRODUCT_CACHE) >= _PRODUCT_CACHE_MAX:
        _PRODUCT_CACHE.popitem(last=False)
    _PRODUCT_CACHE[domain] = product_id


def discover_product_id(session: requests.Session, domain: str) -> str:
    """Auto-discover a purchasable product_id from a WooCommerce store.

    Tries /shop/, /, /store/, /products/ in order.
    Caches up to 500 results per server process (LRU eviction).
    Returns product_id string, or "" if nothing found.
    """
    if domain in _PRODUCT_CACHE:
        _PRODUCT_CACHE.move_to_end(domain)
        return _PRODUCT_CACHE[domain]

    ua    = random_ua()
    paths = ["/shop/", "/", "/store/", "/products/"]
    for path in paths:
        try:
            r = session.get(
                f"https://{domain}{path}",
                headers={"User-Agent": ua, "Upgrade-Insecure-Requests": "1"},
                timeout=REQUEST_TIMEOUT,
            )
            html = r.text

            m = re.search(r'data-product_id=["\']?(\d+)["\']?', html)
            if m:
                _cache_put(domain, m.group(1))
                return m.group(1)

            m = re.search(r'[?&]add-to-cart=(\d+)', html)
            if m:
                _cache_put(domain, m.group(1))
                return m.group(1)

            m = re.search(r'["\']postid["\']\s*:\s*(\d+)', html)
            if m:
                _cache_put(domain, m.group(1))
                return m.group(1)

        except Exception:
            continue

    return ""
