#!/bin/bash
# =============================================================================
#  ProxyHunter Auth Server — One-Click Installer
#  For Hetzner Ubuntu 22.04 LTS (or 20.04)
#
#  Run as root:
#    wget -O install_auth.sh https://YOUR_URL/install_auth.sh
#    chmod +x install_auth.sh
#    ./install_auth.sh
#
#  Or paste directly into Hetzner Cloud Console:
#    bash <(curl -s https://YOUR_URL/install_auth.sh)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'

INSTALL_DIR="/opt/proxyhunter-auth"
SERVICE_NAME="proxyhunter-auth"
PORT=5000
VENV_DIR="$INSTALL_DIR/venv"

# ── Header ────────────────────────────────────────────────────────────────────
clear
echo ""
echo -e "${CYAN}=================================================================${NC}"
echo -e "${CYAN}  ProxyHunter Auth Server — Installer${NC}"
echo -e "${CYAN}  Hetzner Ubuntu 22.04 Edition${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo ""
echo -e "  Install dir  : ${INSTALL_DIR}"
echo -e "  Service      : ${SERVICE_NAME}"
echo -e "  Port         : ${PORT}"
echo ""
read -p "  Proceed with installation? [y/N]: " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "  Cancelled."
    exit 0
fi

# ── Detect script location ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Check root ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root.${NC}"
    echo "  Run: sudo bash $0"
    exit 1
fi

# ── Step 1: System packages ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}[1/8] Updating system packages...${NC}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv curl ufw

PYTHON=$(which python3)
echo -e "       Python: $($PYTHON --version)"

# ── Step 2: Create install directory ─────────────────────────────────────────
echo ""
echo -e "${GREEN}[2/8] Creating install directory...${NC}"
mkdir -p "$INSTALL_DIR"
echo -e "       Created: $INSTALL_DIR"

# ── Step 3: Get public IP ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}[3/8] Detecting public IP...${NC}"
PUBLIC_IP=$(curl -s https://api.ipify.org || echo "YOUR_SERVER_IP")
echo -e "       ${CYAN}Public IP: $PUBLIC_IP${NC}"

# ── Step 4: Copy auth_server.py ──────────────────────────────────────────────
echo ""
echo -e "${GREEN}[4/8] Copying service files...${NC}"

if [[ -f "$SCRIPT_DIR/auth_server.py" ]]; then
    cp "$SCRIPT_DIR/auth_server.py" "$INSTALL_DIR/auth_server.py"
    echo "       auth_server.py copied from local directory"
else
    echo -e "${RED}[ERROR] auth_server.py not found next to installer!${NC}"
    echo "  Place auth_server.py in the same folder as this script."
    exit 1
fi

# ── Step 5: Generate config ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}[5/8] Generating configuration...${NC}"

ADMIN_PW=$(tr -dc 'A-Za-z0-9!@#$%' </dev/urandom | head -c 16)
SECRET_KEY=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 64)
LIC_SECRET="PH4_$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)_2025_V4"

cat > "$INSTALL_DIR/auth_config.json" << EOF
{
  "admin_username":  "admin",
  "admin_password":  "$ADMIN_PW",
  "secret_key":      "$SECRET_KEY",
  "db_path":         "$INSTALL_DIR/auth.db",
  "port":            $PORT,
  "host":            "0.0.0.0",
  "license_secret":  "$LIC_SECRET",
  "max_hwid_resets": 3,
  "backup_interval": 3600,
  "allowed_ips":     []
}
EOF

echo "       Config written (credentials generated)"

# ── Step 6: Virtual environment + packages ────────────────────────────────────
echo ""
echo -e "${GREEN}[6/8] Setting up Python virtual environment...${NC}"
$PYTHON -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet flask
echo "       flask installed"

# ── Step 7: Systemd service ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}[7/8] Creating systemd service...${NC}"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=ProxyHunter Auth Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python auth_server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start  "$SERVICE_NAME"
sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "       ${GREEN}Service is RUNNING${NC}"
else
    echo -e "       ${YELLOW}Service may not be running. Check: journalctl -u $SERVICE_NAME${NC}"
fi

# ── Step 8: Firewall ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}[8/8] Configuring firewall (ufw)...${NC}"
ufw allow ssh    --add 2>/dev/null || true
ufw allow $PORT/tcp comment "ProxyHunter Auth" 2>/dev/null || true
ufw --force enable 2>/dev/null || true
echo "       Port $PORT opened"

# ── Save summary ──────────────────────────────────────────────────────────────
SUMMARY_FILE="$INSTALL_DIR/install_summary.txt"
cat > "$SUMMARY_FILE" << EOF
ProxyHunter Auth Server — Install Summary
==========================================
Installed   : $(date '+%Y-%m-%d %H:%M:%S')
Server IP   : $PUBLIC_IP
Port        : $PORT
Install Dir : $INSTALL_DIR
DB File     : $INSTALL_DIR/auth.db
Log         : journalctl -u $SERVICE_NAME -f

ADMIN PANEL:
  URL      : http://$PUBLIC_IP:$PORT/admin
  Username : admin
  Password : $ADMIN_PW

LICENSE SECRET (put this in admin_keygen.py AND gui_app.py):
  $LIC_SECRET

API (for bots):
  Base URL : http://$PUBLIC_IP:$PORT/api/
  API Key  : $(python3 -c "import hashlib; print(hashlib.sha256('$SECRET_KEY'.encode()).hexdigest()[:32])")

SERVICE MANAGEMENT:
  Status  : systemctl status $SERVICE_NAME
  Restart : systemctl restart $SERVICE_NAME
  Logs    : journalctl -u $SERVICE_NAME -f
  Stop    : systemctl stop $SERVICE_NAME
EOF

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}=================================================================${NC}"
echo -e "${GREEN}   INSTALLATION COMPLETE${NC}"
echo -e "${GREEN}=================================================================${NC}"
echo ""
echo -e "   ${CYAN}Admin Panel : http://$PUBLIC_IP:$PORT/admin${NC}"
echo -e "   ${BOLD}Username    : admin${NC}"
echo -e "   ${YELLOW}Password    : $ADMIN_PW${NC}"
echo ""
echo -e "   ${YELLOW}LICENSE SECRET (add to your bot and admin_keygen.py):${NC}"
echo -e "   ${CYAN}$LIC_SECRET${NC}"
echo ""
echo -e "   ${BOLD}IMPORTANT — DO THESE STEPS:${NC}"
echo -e "   1. Save the password above somewhere safe"
echo -e "   2. Copy the LICENSE SECRET into gui_app.py (_LK_SECRET)"
echo -e "   3. Copy it into admin_keygen.py (_LK_SECRET)"
echo -e "   4. Set your bot's auth server URL in Settings"
echo ""
echo -e "   Full summary saved to: $SUMMARY_FILE"
echo -e "${GREEN}=================================================================${NC}"
echo ""
