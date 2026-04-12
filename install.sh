#!/bin/bash
# Jabali Terminal — install / uninstall script
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/shukiv/jabali-terminal/main/install.sh | sudo bash
#   sudo bash install.sh --uninstall
#
# IMPORTANT: This addon exposes a root shell in the browser. Do not modify
# auth flow, PTY spawn, or audit logging without a code-review note explaining
# why the change is safe. See docs/SECURITY.md.
set -euo pipefail

# Constants are referenced in functions filled during Step 4 and Step 8 of the
# construction plan. Silencing "unused" warnings while the scaffold is in place.
# shellcheck disable=SC2034
REPO_URL="https://github.com/shukiv/jabali-terminal.git"
REPO_BRANCH="main"
INSTALL_DIR="/usr/local/jabali-terminal"
CONFIG_DIR="/etc/jabali-terminal"
LOG_DIR="/var/log/jabali-terminal"
DATA_DIR="/var/lib/jabali-terminal"
RUN_DIR="/run/jabali-terminal"
SERVICE_NAME="jabali-terminal"
PANEL_DIR="/var/www/jabali"
PANEL_APP_DIR="${PANEL_DIR}/app/JabaliTerminal"
PANEL_VIEW_DIR="${PANEL_DIR}/resources/views/filament/admin/pages"
PANEL_ROUTES_FILE="${PANEL_DIR}/routes/admin.php"
NGINX_SNIPPET="/etc/nginx/snippets/jabali-terminal.conf"

# Marker-guarded injection (SEC-REV-7) — replace between BEGIN/END rather than append.
ROUTE_BEGIN="# === JABALI-TERMINAL ROUTES BEGIN ==="
ROUTE_END="# === JABALI-TERMINAL ROUTES END ==="
NGINX_BEGIN="# === JABALI-TERMINAL NGINX BEGIN ==="
NGINX_END="# === JABALI-TERMINAL NGINX END ==="

# ── Helpers ────────────────────────────────────────────────────────────────

red()    { echo -e "\033[0;31m$*\033[0m"; }
green()  { echo -e "\033[0;32m$*\033[0m"; }
yellow() { echo -e "\033[0;33m$*\033[0m"; }
cyan()   { echo -e "\033[0;36m$*\033[0m"; }
bold()   { echo -e "\033[1m$*\033[0m"; }

# Spinner — runs in background, killed by stop_spinner
_spinner_pid=""
_spinner_flag=""

start_spinner() {
    local label="$1"
    _spinner_flag=$(mktemp /tmp/.jabali-term-spinner-XXXXXX)
    (
        local frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
        local n=${#frames[@]} i=0
        tput civis 2>/dev/null || true
        while [ -f "$_spinner_flag" ]; do
            printf "\r\033[0;36m[%s]\033[0m %s " "${frames[i % n]}" "$label" >&2
            i=$((i + 1))
            sleep 0.08
        done
    ) &
    _spinner_pid=$!
}

stop_spinner() {
    local success="${1:-true}"
    local label="$2"
    rm -f "$_spinner_flag" 2>/dev/null
    if [ -n "$_spinner_pid" ]; then
        wait "$_spinner_pid" 2>/dev/null || true
        _spinner_pid=""
    fi
    tput cnorm 2>/dev/null || true
    if [ "$success" = "true" ]; then
        printf "\r\033[0;32m[✓]\033[0m %s\n" "$label" >&2
    else
        printf "\r\033[0;31m[✗]\033[0m %s\n" "$label" >&2
    fi
}

run_with_spinner() {
    local label="$1"; shift
    start_spinner "$label"
    local log_file
    log_file=$(mktemp /tmp/jabali-term-XXXXXX.log)
    local rc=0
    "$@" > "$log_file" 2>&1 || rc=$?
    if [ $rc -eq 0 ]; then
        stop_spinner true "$label"
    else
        stop_spinner false "$label"
        yellow "    Last output:"
        tail -5 "$log_file" | sed 's/^/    /'
    fi
    rm -f "$log_file"
    return $rc
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        red "Error: this script must be run as root."
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-}"
        OS_NAME="${PRETTY_NAME:-$OS_ID}"
    else
        OS_ID="unknown"
        OS_VERSION=""
        OS_NAME="Unknown Linux"
    fi
    export OS_ID OS_VERSION OS_NAME
}

detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    else
        echo "unknown"
    fi
}

pkg_install() {
    local pkg_mgr
    pkg_mgr="$(detect_pkg_manager)"
    case "$pkg_mgr" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
        dnf) dnf install -y -q "$@" ;;
        yum) yum install -y -q "$@" ;;
        *)
            red "Error: cannot detect package manager (apt/dnf/yum). Install manually: $*"
            exit 1
            ;;
    esac
}

section()  { echo ""; yellow "=== $* ==="; }
done_ok()  { green "[✓] $*"; }

# ── Uninstall ──────────────────────────────────────────────────────────────

do_uninstall() {
    require_root
    yellow "Uninstalling Jabali Terminal..."

    # TODO(Step 4): stop/disable service, remove systemd unit, logrotate, venv.
    # TODO(Step 8): remove panel plugin files and marker-guarded route/nginx blocks.

    green "Jabali Terminal has been removed (scaffold stub; logic added in Step 4 + Step 8)."
}

# ── Install ────────────────────────────────────────────────────────────────

do_install() {
    require_root
    echo ""
    yellow "  Jabali Terminal — Installer"
    yellow "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    section "Detecting System"
    detect_os
    echo "  OS: $OS_NAME (id=$OS_ID, version=${OS_VERSION:-n/a})"

    # TODO(Step 4): install deps, create dirs, venv, config, systemd unit, logrotate, CLI symlink.
    # TODO(Step 8): deploy panel plugin files + marker-guarded routes + nginx snippet.

    green "Jabali Terminal scaffold install complete (bodies filled in Step 4 + Step 8)."
}

# ── Dispatch ──────────────────────────────────────────────────────────────

main() {
    case "${1:-install}" in
        --uninstall|uninstall)
            do_uninstall
            ;;
        --help|-h|help)
            cat <<EOF
Jabali Terminal installer

Usage:
  sudo bash install.sh                Install (default)
  sudo bash install.sh --uninstall    Remove everything
  sudo bash install.sh --help         Show this message
EOF
            ;;
        install|"")
            do_install
            ;;
        *)
            red "Unknown argument: $1"
            exit 2
            ;;
    esac
}

main "$@"
