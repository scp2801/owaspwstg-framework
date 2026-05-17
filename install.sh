#!/usr/bin/env bash
# ============================================================
# OWASP WSTG Bug Bounty Framework - Universal Linux Installer
# Author: scp2801
# GitHub: https://github.com/scp2801/owaspwstg-framework
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║     OWASP WSTG Bug Bounty Framework - Installer         ║"
    echo "║     github.com/scp2801/owaspwstg-framework              ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

banner

# ── Check Python version ───────────────────────────────────
info "Checking Python version..."
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 11 ]; then
        success "Python $PYTHON_VERSION found"
    else
        warning "Python $PYTHON_VERSION found. Python 3.11+ recommended."
    fi
else
    error "Python3 not found. Please install Python 3.11+"
fi

# ── Detect OS ─────────────────────────────────────────────
info "Detecting OS..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME=$NAME
    info "OS: $OS_NAME"
else
    OS_NAME="Unknown Linux"
fi

# ── Install system dependencies ───────────────────────────
info "Installing system dependencies..."

if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        python3-pip python3-venv python3-dev \
        libssl-dev libffi-dev build-essential \
        curl wget git nmap dnsutils \
        2>/dev/null || warning "Some system packages failed to install"
    success "APT packages installed"

elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm \
        python python-pip openssl \
        curl wget git nmap \
        2>/dev/null || warning "Some pacman packages failed"
    success "Pacman packages installed"

elif command -v dnf &>/dev/null; then
    sudo dnf install -y \
        python3 python3-pip python3-devel \
        openssl-devel libffi-devel \
        curl wget git nmap \
        2>/dev/null || warning "Some dnf packages failed"
    success "DNF packages installed"

else
    warning "Unknown package manager. Please install dependencies manually."
fi

# ── Create virtual environment ────────────────────────────
info "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
success "Virtual environment created: ./venv"

# ── Upgrade pip ───────────────────────────────────────────
info "Upgrading pip..."
pip install --upgrade pip setuptools wheel -q
success "pip upgraded"

# ── Install Python packages ───────────────────────────────
info "Installing Python dependencies..."
pip install -r requirements.txt -q 
success "Python dependencies installed"

# ── Install Playwright browsers ───────────────────────────
info "Installing Playwright browsers (for screenshots)..."
if python3 -c "import playwright" &>/dev/null 2>&1; then
    playwright install chromium --with-deps 2>/dev/null && \
        success "Playwright Chromium installed" || \
        warning "Playwright browser install failed. Screenshots disabled."
else
    warning "Playwright not available. Screenshots will be disabled."
fi

# ── Create required directories ───────────────────────────
info "Creating directory structure..."
mkdir -p reports screenshots logs payloads wordlists
touch reports/.gitkeep screenshots/.gitkeep logs/.gitkeep
success "Directories created"

# ── Make main.py executable ───────────────────────────────
chmod +x main.py
success "main.py is now executable"

# ── Verify installation ───────────────────────────────────
info "Verifying installation..."
source venv/bin/activate
python3 -c "import aiohttp, rich, typer, openpyxl, yaml, loguru; print('OK')" && \
    success "Core packages verified" || \
    error "Package verification failed. Run: pip install -r requirements.txt"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║            Installation Complete! 🎉                    ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Activate venv:${NC}  source venv/bin/activate"
echo -e "  ${CYAN}Run scan:${NC}       python3 main.py scan example.com"
echo -e "  ${CYAN}Check deps:${NC}     python3 main.py check"
echo -e "  ${CYAN}Help:${NC}           python3 main.py --help"
echo ""
echo -e "  ${YELLOW}⚠  For authorized security testing only!${NC}"
echo ""
