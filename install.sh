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

safe_rmdir() {
    local path="$1"
    [ -e "$path" ] || return 0
    if command -v trash &>/dev/null; then
        trash "$path" 2>/dev/null || rm -rf "$path"
    else
        rm -rf "$path"
    fi
}

do_uninstall() {
    require_root
    yellow "Uninstalling Jabali Terminal..."

    # Warn before removing audit transcripts — they are forensic evidence.
    if [ -d "$LOG_DIR/sessions" ] && [ -n "$(ls -A "$LOG_DIR/sessions" 2>/dev/null)" ]; then
        yellow "  Audit transcripts in $LOG_DIR/sessions/ will be deleted."
        yellow "  Press Ctrl-C within 5s to abort and preserve them."
        sleep 5 || { red "Aborted. Logs preserved."; exit 130; }
    fi

    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true
    done_ok "Service removed"

    rm -f "/etc/logrotate.d/${SERVICE_NAME}"
    rm -f "/usr/local/bin/${SERVICE_NAME}"
    rm -f "/etc/bash_completion.d/${SERVICE_NAME}"
    done_ok "CLI + logrotate removed"

    safe_rmdir "$INSTALL_DIR"
    safe_rmdir "$CONFIG_DIR"
    safe_rmdir "$DATA_DIR"
    safe_rmdir "$LOG_DIR"
    done_ok "Install, config, data, and log dirs removed"

    # Panel plugin is removed by the panel-side uninstall step (Step 8).
    # Do not sed AdminPanelProvider.php here — that was the jabali-security
    # regression learned on 2026-04-12.
    yellow "  Note: panel plugin (if installed) is removed via Server Settings"
    yellow "        -> Addons -> Terminal -> Uninstall."

    green "Jabali Terminal has been removed."
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

    section "Installing System Dependencies"
    run_with_spinner "Installing python3 + openssl + jq" \
        pkg_install python3 python3-venv python3-pip openssl jq git ca-certificates

    if [ "$(python3 -c 'import sys; print(sys.version_info >= (3,12))' 2>/dev/null)" != "True" ]; then
        red "Error: Python 3.12+ is required. Found: $(python3 --version 2>&1)"
        red "Install Python 3.12 (e.g. deadsnakes PPA on Ubuntu 22.04) then re-run."
        exit 1
    fi
    done_ok "Python $(python3 --version 2>&1)"

    section "Creating Directories"
    install -d -m 0755 -o root -g root "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"
    # Audit logs are private to root — SEC-REV-4.
    install -d -m 0700 -o root -g root "$LOG_DIR" "$LOG_DIR/sessions"
    # $RUN_DIR is created by systemd via RuntimeDirectory= in the unit file.
    done_ok "Dirs created"

    section "Fetching Source"
    # Dev mode: if the script is being run from inside a checkout, skip clone.
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$script_dir/install.sh" ] && [ -d "$script_dir/daemon" ]; then
        if [ "$script_dir" != "$INSTALL_DIR" ]; then
            run_with_spinner "Copying source to $INSTALL_DIR" \
                bash -c "cp -a '$script_dir/.' '$INSTALL_DIR/'"
        else
            done_ok "Source already at $INSTALL_DIR (dev mode)"
        fi
    elif [ -d "$INSTALL_DIR/.git" ]; then
        run_with_spinner "Updating existing checkout" \
            bash -c "cd '$INSTALL_DIR' && git fetch --quiet && git reset --hard 'origin/$REPO_BRANCH' --quiet"
    else
        run_with_spinner "Cloning from $REPO_URL" \
            git clone --depth 1 --branch "$REPO_BRANCH" --quiet "$REPO_URL" "$INSTALL_DIR"
    fi

    section "Installing Python Daemon"
    if [ -f "$INSTALL_DIR/daemon/pyproject.toml" ]; then
        run_with_spinner "Creating venv" \
            python3 -m venv "$INSTALL_DIR/venv"
        run_with_spinner "Upgrading pip" \
            "$INSTALL_DIR/venv/bin/pip" install --upgrade --quiet pip
        run_with_spinner "Installing daemon (editable)" \
            "$INSTALL_DIR/venv/bin/pip" install --quiet -e "$INSTALL_DIR/daemon"
    else
        yellow "  daemon/pyproject.toml missing — skipping pip install (pre-Step 3 scaffold)."
    fi

    section "Generating Secrets"
    local conf="$CONFIG_DIR/jabali-terminal.conf"
    if [ -f "$conf" ] && \
       grep -qE '^hmac_secret="[0-9a-f]{64,}"' "$conf" && \
       grep -qE '^audit_hmac_secret="[0-9a-f]{64,}"' "$conf"; then
        done_ok "Existing config preserved (idempotent re-install)"
    else
        local hmac_secret audit_secret
        hmac_secret="$(openssl rand -hex 32)"
        audit_secret="$(openssl rand -hex 32)"
        # Copy the example then substitute the two empty values. Never echo secrets.
        install -m 0640 -o root -g root \
            "$INSTALL_DIR/configs/jabali-terminal.conf.example" "$conf"
        sed -i \
            -e "s|^hmac_secret=\"\"|hmac_secret=\"${hmac_secret}\"|" \
            -e "s|^audit_hmac_secret=\"\"|audit_hmac_secret=\"${audit_secret}\"|" \
            "$conf"
        unset hmac_secret audit_secret
        done_ok "Config written with fresh secrets at $conf"
    fi

    section "Installing systemd Unit"
    install -m 0644 "$INSTALL_DIR/configs/jabali-terminal.service" \
        "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    done_ok "systemd unit installed"

    section "Installing Logrotate"
    if [ -f "$INSTALL_DIR/configs/logrotate.d/jabali-terminal" ]; then
        install -m 0644 "$INSTALL_DIR/configs/logrotate.d/jabali-terminal" \
            "/etc/logrotate.d/${SERVICE_NAME}"
        done_ok "Logrotate config installed"
    fi

    section "Installing CLI"
    if [ -f "$INSTALL_DIR/bin/jabali-terminal" ]; then
        install -m 0755 "$INSTALL_DIR/bin/jabali-terminal" \
            "/usr/local/bin/${SERVICE_NAME}"
        done_ok "CLI symlink at /usr/local/bin/${SERVICE_NAME}"
    fi
    if [ -f "$INSTALL_DIR/completions/jabali-terminal.bash" ]; then
        install -d -m 0755 /etc/bash_completion.d
        install -m 0644 "$INSTALL_DIR/completions/jabali-terminal.bash" \
            "/etc/bash_completion.d/${SERVICE_NAME}"
    fi

    section "Starting Service"
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    if systemctl start "$SERVICE_NAME"; then
        # Poll up to 10s for active state.
        local i=0
        while [ $i -lt 10 ]; do
            if systemctl is-active --quiet "$SERVICE_NAME"; then
                done_ok "Service active"
                break
            fi
            sleep 1; i=$((i+1))
        done
        if ! systemctl is-active --quiet "$SERVICE_NAME"; then
            red "Service failed to become active. Last journal lines:"
            journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
            exit 1
        fi
    else
        red "systemctl start $SERVICE_NAME failed."
        journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
        exit 1
    fi

    section "Done"
    echo ""
    green "  Jabali Terminal daemon installed."
    cyan  "  Socket:    $RUN_DIR/${SERVICE_NAME}.sock"
    cyan  "  Config:    $CONFIG_DIR/jabali-terminal.conf"
    cyan  "  Audit log: $LOG_DIR/sessions/"
    cyan  "  CLI:       jabali-terminal status | logs | sessions"
    echo ""
    yellow "  Panel integration is installed separately via"
    yellow "  Jabali Panel -> Server Settings -> Addons -> Terminal."
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
