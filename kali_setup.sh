#!/usr/bin/env bash
# ============================================================
# OWASP WSTG Framework - Kali Linux Setup Script
# Installs framework + ProjectDiscovery tools + security tools
# Author: scp2801
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; }

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     OWASP WSTG Framework - Kali Linux Setup             ║"
echo "║     github.com/scp2801/owaspwstg-framework              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Update Kali ────────────────────────────────────────────
info "Updating Kali package lists..."
sudo apt-get update -qq 2>/dev/null || warning "apt update failed"

# ── Install Python deps ───────────────────────────────────
info "Installing Python3 and pip..."
sudo apt-get install -y -qq python3 python3-pip python3-venv python3-dev \
    libssl-dev libffi-dev build-essential 2>/dev/null
success "Python dependencies installed"

# ── Install Go (required for ProjectDiscovery tools) ──────
if ! command -v go &>/dev/null; then
    info "Installing Go..."
    GO_VERSION="1.22.0"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    success "Go ${GO_VERSION} installed"
else
    success "Go $(go version | awk '{print $3}') already installed"
fi

export PATH=$PATH:/usr/local/go/bin:~/go/bin

# ── Install ProjectDiscovery Tools ────────────────────────
info "Installing ProjectDiscovery security tools..."

TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/ffuf/ffuf/v2@latest"
)

for tool in "${TOOLS[@]}"; do
    tool_name=$(echo "$tool" | awk -F'/' '{print $NF}' | cut -d'@' -f1)
    info "Installing $tool_name..."
    go install -v "$tool" 2>/dev/null && \
        success "$tool_name installed" || \
        warning "$tool_name failed to install"
done

# ── Update Nuclei templates ───────────────────────────────
if command -v nuclei &>/dev/null; then
    info "Updating Nuclei templates..."
    nuclei -update-templates 2>/dev/null && success "Nuclei templates updated" || warning "Nuclei template update failed"
fi

# ── Install apt-based tools ───────────────────────────────
info "Installing additional tools via apt..."
KALI_TOOLS="nmap sqlmap dnsutils curl wget git"
sudo apt-get install -y -qq $KALI_TOOLS 2>/dev/null && \
    success "Additional tools installed" || warning "Some tools failed"

# ── Setup Python environment ──────────────────────────────
info "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
success "Python environment ready"

# ── Install Playwright ────────────────────────────────────
info "Installing Playwright (screenshot engine)..."
playwright install chromium --with-deps 2>/dev/null && \
    success "Playwright ready" || warning "Playwright install failed (screenshots disabled)"

# ── Create dirs ───────────────────────────────────────────
mkdir -p reports screenshots logs payloads wordlists
touch reports/.gitkeep screenshots/.gitkeep logs/.gitkeep
chmod +x main.py

# ── Summary ───────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║       Kali Linux Setup Complete! 🔴🐉                   ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Show tool availability
echo -e "  ${CYAN}Tool Availability:${NC}"
TOOLS_CHECK="subfinder httpx nuclei katana ffuf naabu nmap sqlmap"
for t in $TOOLS_CHECK; do
    if command -v "$t" &>/dev/null; then
        echo -e "    ${GREEN}✓${NC} $t"
    else
        echo -e "    ${RED}✗${NC} $t (not found)"
    fi
done

echo ""
echo -e "  ${CYAN}Commands:${NC}"
echo -e "    source venv/bin/activate"
echo -e "    python3 main.py scan example.com"
echo -e "    python3 main.py scan example.com --profile deep"
echo ""
echo -e "  ${YELLOW}⚠  For authorized security testing only!${NC}"
echo ""
