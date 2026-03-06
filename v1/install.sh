#!/usr/bin/env bash
# install.sh — ZWYRM AntiVirus v2.0 Installer
set -euo pipefail

ZWYRM_VERSION="2.0"
INSTALL_DIR="$HOME/.zwyrm"

# ── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET} $*"; }
err()  { echo -e "  ${RED}✗${RESET} $*"; }
info() { echo -e "  ${CYAN}→${RESET} $*"; }

echo -e "\n${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║        ZWYRM AntiVirus v${ZWYRM_VERSION} — Installation              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Python check ───────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    err "Python 3 is required but not found."
    echo "    Ubuntu/Debian : sudo apt-get install python3 python3-pip"
    echo "    Fedora/RHEL   : sudo dnf install python3 python3-pip"
    echo "    Arch          : sudo pacman -S python python-pip"
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJ=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MIN=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "$PY_MAJ" -lt 3 ] || { [ "$PY_MAJ" -eq 3 ] && [ "$PY_MIN" -lt 7 ]; }; then
    err "Python 3.7+ is required. Found Python ${PY_VER}."
    exit 1
fi
ok "Python ${PY_VER}"

# ── Root warning ───────────────────────────────────────────────────────────
if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    warn "Running as root. User-mode installation is safer."
    read -rp "  Continue as root? [y/N] " ROOT_REPLY
    [[ "$ROOT_REPLY" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }
fi

# ── Source directory check ─────────────────────────────────────────────────
if [ ! -f "zwyrm.py" ]; then
    err "zwyrm.py not found. Run install.sh from the ZWYRM project directory."
    exit 1
fi

# ── Directory structure ────────────────────────────────────────────────────
echo -e "\n${BOLD}Creating directory structure…${RESET}"
for d in "" /core /modules /cli /utils /database /database/yara_rules /logs /quarantine /backups; do
    mkdir -p "${INSTALL_DIR}${d}"
done
ok "Directories created under $INSTALL_DIR"

# ── Copy files ─────────────────────────────────────────────────────────────
echo -e "\n${BOLD}Copying files…${RESET}"

copy_if_exists() {
    local src="$1" dst="$2"
    if [ -f "$src" ]; then
        cp -f "$src" "$dst"
        ok "$(basename "$src")"
    fi
}

copy_if_exists zwyrm.py         "$INSTALL_DIR/zwyrm.py"
copy_if_exists config.yaml      "$INSTALL_DIR/config.yaml"
copy_if_exists requirements.txt "$INSTALL_DIR/requirements.txt"
copy_if_exists README.md        "$INSTALL_DIR/README.md"
copy_if_exists LICENSE.md       "$INSTALL_DIR/LICENSE.md"
copy_if_exists zwyrm.png        "$INSTALL_DIR/zwyrm.png"

# Core modules
for f in core/scanner.py core/detector.py core/quarantine.py core/updater.py; do
    [ -f "$f" ] && cp -f "$f" "$INSTALL_DIR/$f" && ok "$f"
done
touch "$INSTALL_DIR/core/__init__.py"

# Extension modules
for f in modules/realtime.py modules/scheduler.py; do
    [ -f "$f" ] && cp -f "$f" "$INSTALL_DIR/$f" && ok "$f"
done
touch "$INSTALL_DIR/modules/__init__.py"

# CLI
[ -f "cli/interface.py" ] && cp -f cli/interface.py "$INSTALL_DIR/cli/interface.py" && ok "cli/interface.py"
touch "$INSTALL_DIR/cli/__init__.py"

# Utils
for f in utils/config.py utils/logger.py; do
    [ -f "$f" ] && cp -f "$f" "$INSTALL_DIR/$f" && ok "$f"
done
touch "$INSTALL_DIR/utils/__init__.py"

# ── Database initialisation ────────────────────────────────────────────────
echo -e "\n${BOLD}Initialising databases…${RESET}"

DB_DIR="$INSTALL_DIR/database"

[ -f "$DB_DIR/signatures.db" ] || \
    echo '{"md5_hashes":{},"sha256_hashes":{},"string_patterns":[],"yara_rules":[]}' \
    > "$DB_DIR/signatures.db" && ok "signatures.db"

[ -f "$DB_DIR/whitelist.db" ] || echo '[]' > "$DB_DIR/whitelist.db" && ok "whitelist.db"

[ -f "$DB_DIR/last_update.json" ] || \
    echo '{"timestamp":null,"source":"initial","signatures_added":0,"signatures_removed":0,"version":"2.0"}' \
    > "$DB_DIR/last_update.json" && ok "last_update.json"

# ── Log files ─────────────────────────────────────────────────────────────
for log in zwyrm.log scans.log threats.log audit.log; do
    touch "$INSTALL_DIR/logs/$log"
done
ok "Log files initialised"

# ── Permissions ────────────────────────────────────────────────────────────
chmod 750 "$INSTALL_DIR/quarantine" "$INSTALL_DIR/logs" "$INSTALL_DIR/backups"
chmod 640 "$INSTALL_DIR/database"/*.db "$INSTALL_DIR/database"/*.json 2>/dev/null || true
chmod +x "$INSTALL_DIR/zwyrm.py"
ok "Permissions set"

# ── Python dependencies ────────────────────────────────────────────────────
echo -e "\n${BOLD}Installing Python dependencies…${RESET}"

PIP3=$(command -v pip3 || command -v pip || echo "")
if [ -z "$PIP3" ]; then
    warn "pip not found. Attempting to install…"
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y python3-pip
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3-pip
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm python-pip
    else
        err "Could not install pip. Install manually then re-run."
        exit 1
    fi
    PIP3=$(command -v pip3 || command -v pip)
fi

if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    "$PIP3" install --user -q -r "$INSTALL_DIR/requirements.txt" \
        && ok "Core dependencies installed" \
        || warn "Some dependencies failed. Run: pip install -r $INSTALL_DIR/requirements.txt"
fi

# ── Optional dependency checks ─────────────────────────────────────────────
echo -e "\n${BOLD}Checking optional dependencies…${RESET}"
for pkg_check in "yara:yara-python:YARA rule matching" \
                 "pefile:pefile:PE file analysis" \
                 "magic:python-magic:File type detection" \
                 "pyinotify:pyinotify:Real-time monitoring"; do
    IFS=: read -r mod pip_name desc <<< "$pkg_check"
    python3 -c "import $mod" 2>/dev/null \
        && ok "$desc ($mod)" \
        || warn "$desc not available → pip install $pip_name"
done

# ── Symlink ────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}Creating command symlink…${RESET}"
SYMLINK_CREATED=false

# Try /usr/local/bin first (system-wide, needs sudo)
if sudo ln -sf "$INSTALL_DIR/zwyrm.py" /usr/local/bin/zwyrm 2>/dev/null; then
    ok "Symlink: /usr/local/bin/zwyrm"
    SYMLINK_CREATED=true
else
    # Fall back to ~/.local/bin (user-local)
    mkdir -p "$HOME/.local/bin"
    if ln -sf "$INSTALL_DIR/zwyrm.py" "$HOME/.local/bin/zwyrm" 2>/dev/null; then
        ok "Symlink: ~/.local/bin/zwyrm"
        warn "Make sure ~/.local/bin is in your PATH:"
        info "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
        SYMLINK_CREATED=true
    else
        warn "Could not create symlink. Use alias instead:"
        info "  alias zwyrm='python3 $INSTALL_DIR/zwyrm.py'"
    fi
fi

# ── Desktop entry (optional) ──────────────────────────────────────────────
read -rp $'\nCreate desktop entry? [y/N] ' DESK_REPLY || DESK_REPLY="n"
if [[ "$DESK_REPLY" =~ ^[Yy]$ ]]; then
    DESK_DIR="$HOME/.local/share/applications"
    mkdir -p "$DESK_DIR"
    cat > "$DESK_DIR/zwyrm-antivirus.desktop" <<EOF
[Desktop Entry]
Name=ZWYRM AntiVirus
Comment=Linux Security Framework v${ZWYRM_VERSION}
Exec=bash -c "zwyrm info; read"
Icon=${INSTALL_DIR}/zwyrm.png
Terminal=true
Type=Application
Categories=System;Security;
Keywords=antivirus;security;malware;scanner;
EOF
    ok "Desktop entry created"
fi

# ── Completion ─────────────────────────────────────────────────────────────
echo -e "\n${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              INSTALLATION COMPLETE ✓                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "  📦 Install dir : $INSTALL_DIR"
echo -e "  📝 Config      : $INSTALL_DIR/config.yaml"
echo -e "  📊 Logs        : $INSTALL_DIR/logs/"
echo -e "  🔒 Quarantine  : $INSTALL_DIR/quarantine/"
echo ""
echo -e "${BOLD}Quick Start:${RESET}"
echo "  zwyrm info                  → System status"
echo "  zwyrm update                → Download virus signatures"
echo "  zwyrm scan ~/Downloads      → Scan a directory"
echo "  zwyrm scan -r ~/Downloads   → Scan and auto-quarantine"
echo "  zwyrm quarantine --list     → List quarantined files"
echo "  zwyrm realtime --start      → Real-time protection"
echo ""
echo -e "${YELLOW}💡 Tip: Run 'zwyrm update' first to download the latest signatures!${RESET}"
echo ""
