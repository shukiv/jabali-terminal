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

## Status

Scaffold stage (Step 1). Full build tracked in
`~/projects/jabali/plans/jabali-terminal-addon.md`.
