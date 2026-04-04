# EONX CHECKER

A Flask web application for testing payment gateways across WooCommerce and
Magento 2 stores.  Results are streamed to the browser in real time via
Server-Sent Events (SSE).

---

## Supported Gateways

| Key        | Description                          |
|------------|--------------------------------------|
| `authnet`  | Authorize.Net CIM (WooCommerce)      |
| `ppcp`     | PayPal PPCP (WooCommerce)            |
| `pymntpl`  | PaymentPlugins PayPal (WooCommerce)  |
| `b3woo`    | Braintree (WooCommerce)              |
| `b3magento`| Braintree (Magento 2)                |

---

## Quick Start

### 1. Clone & install dependencies

```bash
git clone https://github.com/EONX-PH/automix.git
cd automix
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment variables

Copy the example file and fill in your credentials:

```bash
cp .env.example .env
# Edit .env with your Telegram bot token and proxy credentials
```

> **Important**: Never commit `.env`.  It is listed in `.gitignore`.

### 3. Create the data directory

```bash
mkdir -p data/cards
touch data/authnet.txt data/ppcp.txt data/pymntpl.txt data/b3magento.txt data/b3woo.txt
```

### 4. Run (development)

```bash
source .env   # or: export $(grep -v '^#' .env | xargs)
flask run --host 0.0.0.0 --port 5052
```

### 5. Run (production via Gunicorn)

```bash
source .env
gunicorn app:app \
    --bind 127.0.0.1:5052 \
    --workers 1 \
    --worker-class gthread \
    --threads 64 \
    --timeout 180 \
    --keep-alive 5
```

See `deploy/` for the full systemd service and Nginx reverse-proxy templates,
and `TRANSFER.txt` for the complete VPS setup walkthrough.

---

## Environment Variables

| Variable             | Required | Description                                  |
|----------------------|----------|----------------------------------------------|
| `TELEGRAM_BOT_TOKEN` | No       | Telegram bot token from @BotFather           |
| `TELEGRAM_CHAT_ID`   | No       | Target chat/group ID for live-hit alerts     |
| `TELEGRAM_TOPIC_ID`  | No       | Thread/topic ID within the group (integer)   |
| `PROXYVERSE_HOST`    | No       | `host:port` for Proxyverse residential proxy |
| `PROXYVERSE_AUTH`    | No       | `user:pass` credentials for Proxyverse       |
| `RAYOBYTE_HOST`      | No       | `host:port` for Rayobyte residential proxy   |
| `RAYOBYTE_AUTH`      | No       | `user:pass` credentials for Rayobyte         |

When proxy credentials are empty the application falls back to direct
connections.  When `TELEGRAM_BOT_TOKEN` is empty, Telegram notifications are
silently disabled.

---

## Health Check

```
GET /health
```

Returns `{"status": "ok", "active_jobs": <n>}` — suitable for use as a
Kubernetes/Docker liveness probe or uptime-monitor endpoint.

---

## Project Structure

```
automix/
├── app.py               # Flask application: routes, job management, SSE streaming
├── requirements.txt     # Pinned Python dependencies
├── .env.example         # Environment variable template (copy to .env)
├── gateways/
│   ├── utils.py         # Shared helpers: sessions, proxies, BIN lookup, identity
│   ├── authnetcim.py    # Authorize.Net CIM gateway
│   ├── ppcp.py          # PayPal PPCP gateway
│   ├── pymntpl.py       # PaymentPlugins PayPal gateway
│   ├── b3woo.py         # Braintree WooCommerce gateway
│   └── b3magento.py     # Braintree Magento 2 gateway
├── templates/
│   └── index.html       # Single-page UI with SSE result streaming
├── static/
│   └── blackbg.jpg      # Background image
├── data/                # Runtime data (gitignored — create manually)
│   ├── authnet.txt
│   ├── ppcp.txt
│   ├── pymntpl.txt
│   ├── b3magento.txt
│   ├── b3woo.txt
│   └── cards/
└── deploy/
    ├── eonx-checker.service   # systemd unit file
    └── automix.DOMAIN.nginx   # Nginx reverse-proxy template
```

---

## Security Notes

* All secrets (bot tokens, proxy credentials) must be supplied via environment
  variables — **never** hard-code them in source files.
* The working-domain files (`data/*.txt`) are excluded from git to avoid
  leaking store URLs.
* The `/health` endpoint exposes no sensitive data and requires no authentication.
