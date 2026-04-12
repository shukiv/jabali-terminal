# Changelog

All notable changes to jabali-terminal are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses semantic versioning for tags.

## [0.1.0] — 2026-04-12

First release. Browser-based root shell for Jabali Panel. Architecture
mirrors jabali-security: Python daemon over a unix socket behind nginx,
Filament plugin with `class_exists()` autodiscovery, marker-guarded
install.sh that never touches `AdminPanelProvider.php`.

### Added

- **Daemon** (`daemon/`, Python 3.12+, asyncio)
  - `GET /health`, `POST /api/v1/session`, `GET /api/v1/sessions[/{name}/transcript]`,
    `GET /terminal/ws` — all served over `root:www-data` 0660 unix socket
  - 104-byte tokens (admin_id, ip, issued_at, expires_at, nonce, HMAC-SHA256)
    with 60s TTL, single-use via SQLite-backed nonce store (SEC-REV-1)
  - Handshake-challenge WS auth (SEC-REV-2): token never in URL
  - Strict verification order: expiry → nonce → IP → HMAC (SEC-REV-5)
  - Request-HMAC verification on `POST /api/v1/session` with 30s clock-skew
    window (defense-in-depth over socket filesystem ACL)
  - Per-session audit log `<date>_<admin>_<session_id>.log`, HMAC-sealed
    on close (SEC-REV-4), unclosed logs sealed on daemon restart (SEC-REV-10)
  - Idle timeout fires only when both stdin AND stdout are quiet (SEC-REV-3),
    hard 1h cap enforced daemon-side (SEC-REV-9)
  - 4KB paste cap enforced server-side (defense-in-depth over the UI cap)
- **Panel plugin** (`panel/`, Filament)
  - `JabaliTerminalPlugin` autodiscovered via `class_exists()` — no
    `AdminPanelProvider.php` sed
  - `Pages/Terminal` renders the xterm.js UI; `Pages/Sessions` is a
    read-only audit index of the last 100 transcripts
  - `Http/Controllers/TerminalSessionController` handles re-auth at
    `POST /jabali-admin/terminal/session`. Fresh password + 2FA required
    per session (no opt-out). Rate limit 3/min per (admin, ip); 5 failed
    attempts in 15 min trigger a hard lockout
  - `PreventFramingMiddleware` pins `X-Frame-Options: DENY` and merges
    `frame-ancestors 'none'` into any existing CSP (SEC-REV-8)
  - xterm.js bundle computes the challenge HMAC with Web Crypto (no
    third-party JS crypto), scrubs the token from closure memory after
    the auth frame is sent
- **install.sh**
  - Python venv + pip install, systemd unit, sudoers, logrotate
  - Marker-guarded nginx include (`# === JABALI-TERMINAL NGINX {BEGIN,END} ===`)
    with nginx -t validation + rollback on failure
  - `jq`-based npm dep merge into the panel's `package.json`, triggers
    `npm install && npm run build` only when deps actually changed
  - Symmetrical uninstall that removes every installed artifact without
    touching `AdminPanelProvider.php`
- **Tests**
  - Python unit tests for auth, audit, config, nonce store
  - PHP feature test `TerminalAuthTest` covering the auth surface of
    the dedicated session route
  - `tests/e2e_socket.py` drives the daemon end-to-end over the unix
    socket (handshake, PTY, IP binding, replay, transcript seal)

### Documentation

- `docs/SECURITY.md` — threat model and control catalogue
- `docs/E2E_TEST_REPORT.md` — Step 10 results on 10.0.3.13

### Known limitations

- One-session-per-user enforcement is described in `docs/SECURITY.md`
  but not enforced yet in `ws_handler`.
- Idle-timeout E2E is verified by code review + unit tests; no live
  5-minute gate test ran.
- `install.sh` uses `npm install` rather than `npm ci` (addon dep merge
  mutates the panel's lockfile); long term the addon JS should ship as
  its own npm package.
