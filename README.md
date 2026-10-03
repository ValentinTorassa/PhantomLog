# 🕵️ PhantomLog

A tiny Flask click-tracker for **authorized** phishing-simulation and
security-awareness exercises. Generate a unique tracking link per target, and
when someone opens it, PhantomLog records the click (timestamp, id, IP,
user-agent) and shows it on a password-protected dashboard.

## What it does

- Generates a unique link per user (`/log?id=<uuid>`).
- Logs who clicked, from which IP and with what device.
- Shows logs and generated links on a dark-mode web dashboard.
- Dashboard is behind HTTP Basic auth; the tracking endpoint stays public.

## Routes

| Route        | Auth   | Purpose                                  |
|--------------|--------|------------------------------------------|
| `/`          | admin  | Dashboard: view logs and generated links |
| `/generate`  | admin  | Create a new tracking link (POST)        |
| `/log?id=…`  | public | Tracking endpoint (records a click, 204) |

## Run locally

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# Configure admin credentials (see "Configuration" below)
export ADMIN_USER=admin
export ADMIN_PASSWORD_HASH="$(python -c 'from werkzeug.security import generate_password_hash as g; import getpass; print(g(getpass.getpass()))')"

python app.py   # dev server on http://0.0.0.0:5000
```

`logs.csv` and `links.csv` are created on first run inside `DATA_DIR`.

## Configuration

All configuration is via environment variables (see `.env.example`):

| Variable              | Required | Default        | Notes                                             |
|-----------------------|----------|----------------|---------------------------------------------------|
| `ADMIN_USER`          | no       | `admin`        | Dashboard username (HTTP Basic).                  |
| `ADMIN_PASSWORD_HASH` | **yes**  | —              | Werkzeug password hash. No default; see below.    |
| `DATA_DIR`            | no       | app directory  | Where `logs.csv` / `links.csv` live.              |

There is **no default password**. Until `ADMIN_PASSWORD_HASH` is set, the
dashboard returns `503`; the public `/log` endpoint keeps working. Credentials
are checked with a constant-time comparison. Generate a hash with:

```bash
python -c "from werkzeug.security import generate_password_hash as g; import getpass; print(g(getpass.getpass()))"
```

## Deploy

A `Procfile` is included, so any Procfile-based host (Render, Railway, etc.)
works out of the box:

```
web: gunicorn app:app
```

Set `ADMIN_USER`, `ADMIN_PASSWORD_HASH` and (optionally) `DATA_DIR` in the host's
environment, and a persistent disk for `DATA_DIR` if you want logs to survive
restarts. **Always serve behind HTTPS** — HTTP Basic credentials are otherwise
sent in the clear.

## Tests

```bash
pip install -r requirements.txt
pytest -q
```

CI runs the same suite on every push and pull request (see
`.github/workflows/ci.yml`).

## Used as a lab in Open Security Labs

PhantomLog's code is also the environment for the lab
[Medir una simulación de phishing sin vigilar a nadie](https://securitylabs.valentorassa.com/labs/ciberseguridad/medir-simulacion-phishing/)
("Measuring a phishing simulation without surveilling anyone") in
[Open-Security-Labs](https://github.com/ValentinTorassa/Open-Security-Labs).
The copy there lives under
[`entornos/ciberseguridad/medir-simulacion-phishing/phantomlog/`](https://github.com/ValentinTorassa/Open-Security-Labs/tree/main/entornos/ciberseguridad/medir-simulacion-phishing)
and adds, for teaching: opt-in `ProxyFix` behind `TRUSTED_PROXIES`, an HTTP
`method` column in the log, UTC timestamps, and tests for each change. The lab
covers authorization, aggregate-only reporting, filtering scanner and
link-preview clicks, and the `remote_addr`-behind-a-proxy pitfall. That repo's
environment README explains every change.

## Ethics & scope

PhantomLog is for **authorized** security-awareness testing only — exercises you
or your client have explicit written permission to run. Do not use it to track,
deceive or profile anyone without authorization.

- **Data collected:** timestamp, the `id` from the link, source IP and
  User-Agent of each click. No cookies, no payloads, no page contents.
- **Retention:** data lives in plain CSV files under `DATA_DIR`. Treat it as
  personal data: restrict access, delete it when the exercise ends, and keep it
  only as long as the engagement requires.
