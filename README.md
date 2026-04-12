# Jabali Terminal

Browser-based root shell for [Jabali Panel](https://github.com/shukiv/jabali-panel),
powered by [xterm.js](https://xtermjs.org/).

> **Security notice**: this addon hands a **root** PTY to an authenticated
> admin through the browser. Every session requires fresh re-auth + 2FA, is
> IP-bound, expires in ≤60s token TTL + 1hr hard cap, and is fully audited.
> See [docs/SECURITY.md](docs/SECURITY.md) before enabling on production.

## Install (via Jabali Panel)

Server Settings → Addons → **Terminal** → Install.

## Install (manual)

```bash
curl -fsSL https://raw.githubusercontent.com/shukiv/jabali-terminal/main/install.sh | sudo bash
```

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/shukiv/jabali-terminal/main/install.sh | sudo bash -s -- --uninstall
```

## Architecture

- **Daemon** (`daemon/`, Python 3.12+, asyncio) — runs as root, listens on
  `/run/jabali-terminal/jabali-terminal.sock` (`root:www-data` 0660). Routes:
  - `GET  /health`
  - `POST /api/v1/session` — HMAC-signed mint request, returns a 60s
    single-use token (SEC-REV-5 strict-order verification, SEC-REV-1
    SQLite nonce store).
  - `GET  /api/v1/sessions` + `/api/v1/sessions/{name}/transcript` —
    read-only audit index for the Sessions page.
  - `GET  /terminal/ws` — nginx proxies `wss://host/terminal-ws` here.
    Handshake-challenge auth (SEC-REV-2): challenge → HMAC response →
    token → PTY attach. No token ever in URL.
- **Panel plugin** (`panel/`) — Filament plugin autodiscovered by
  `class_exists()` in `AdminPanelProvider`. Two pages: Terminal (xterm.js
  view + re-auth modal) and Sessions (last 100 transcripts). Dedicated
  `POST /jabali-admin/terminal/session` route does the re-auth; rate
  limited at 3/min per (admin, ip) and locked out after 5 failed attempts
  for 15 minutes.

## Status

Steps 1–9 of `~/projects/jabali/plans/jabali-terminal-addon.md` complete.
Remaining:

- **Step 10** — end-to-end install → use → uninstall on a fresh LXC
  (documented in `docs/E2E_TEST_REPORT.md` when done).
- **Step 11** — release tag + docs refresh.
