#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
# OWASP WSTG Framework - Termux (Android) Setup Script
# Optimized for Android/Termux environment
# Author: scp2801
# ============================================================

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

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     OWASP WSTG Framework - Termux Setup                 ║"
echo "║     github.com/scp2801/owaspwstg-framework              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

warning "Termux Mode: Screenshots will be DISABLED"
warning "Playwright is NOT supported on Termux"
info "All other features will work normally"
echo ""

# ── Storage Permission ────────────────────────────────────
info "Setting up storage access..."
if [ ! -d ~/storage ]; then
    warning "Requesting storage permission..."
    termux-setup-storage 2>/dev/null || warning "Storage setup failed (run 'termux-setup-storage' manually)"
    sleep 2
fi

# ── Update Termux ─────────────────────────────────────────
info "Updating Termux packages..."
pkg update -y 2>/dev/null || warning "pkg update failed"

# ── Install core packages ─────────────────────────────────
info "Installing core packages..."
pkg install -y \
    python \
    python-pip \
    git \
    curl \
    wget \
    dnsutils \
    nmap \
    openssl \
    libffi \
    clang \
    make \
    2>/dev/null || warning "Some packages failed"
success "Core packages installed"

# ── Install Go for ProjectDiscovery tools ────────────────
if ! command -v go &>/dev/null; then
    info "Installing Go..."
    pkg install -y golang 2>/dev/null && \
        success "Go installed" || warning "Go install failed"
fi

# ── Install ProjectDiscovery tools ───────────────────────
if command -v go &>/dev/null; then
    info "Installing subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && \
        success "subfinder installed" || warning "subfinder failed"

    info "Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && \
        success "httpx installed" || warning "httpx failed"
fi

# ── Upgrade pip ───────────────────────────────────────────
info "Upgrading pip..."
pip install --upgrade pip 2>/dev/null
success "pip upgraded"

# ── Install Python requirements (Termux-safe) ─────────────
info "Installing Python dependencies (Termux-optimized)..."

# Install packages that work on Termux
SAFE_PACKAGES=(
    "aiohttp"
    "aiofiles"
    "typer"
    "rich"
    "loguru"
    "PyYAML"
    "beautifulsoup4"
    "lxml"
    "dnspython"
    "requests"
    "openpyxl"
    "pandas"
    "Jinja2"
    "python-dateutil"
    "colorama"
    "tqdm"
)

for pkg in "${SAFE_PACKAGES[@]}"; do
    pip install "$pkg" -q 2>/dev/null && \
        echo -e "  ${GREEN}✓${NC} $pkg" || \
        echo -e "  ${YELLOW}⚠${NC} $pkg (failed, continuing)"
done

# Skip playwright on Termux
warning "Skipping Playwright (not supported on Termux)"
warning "Screenshot features will be automatically disabled"

# ── Create directory structure ────────────────────────────
info "Creating directories..."
mkdir -p reports screenshots logs payloads wordlists
touch reports/.gitkeep screenshots/.gitkeep logs/.gitkeep

# ── Setup storage symlinks ────────────────────────────────
if [ -d ~/storage/shared ]; then
    info "Creating storage symlinks..."
    ln -sf ~/storage/shared/owaspwstg-reports reports/shared 2>/dev/null || true
    success "Storage symlinks created"
fi

chmod +x main.py 2>/dev/null || true

# ── Verify ───────────────────────────────────────────────
info "Verifying installation..."
python3 -c "
import sys
packages = ['aiohttp', 'rich', 'typer', 'openpyxl', 'yaml', 'loguru']
missing = []
for p in packages:
    try:
        __import__(p)
        print(f'  ✓ {p}')
    except ImportError:
        missing.append(p)
        print(f'  ✗ {p} MISSING')

if missing:
    print(f'Missing: {missing}')
    sys.exit(1)
print('Core packages OK')
"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║       Termux Setup Complete! 📱                          ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Enabled features:${NC}"
echo -e "    ${GREEN}✓${NC} Subdomain enumeration"
echo -e "    ${GREEN}✓${NC} DNS enumeration"
echo -e "    ${GREEN}✓${NC} Live host detection"
echo -e "    ${GREEN}✓${NC} Web crawling"
echo -e "    ${GREEN}✓${NC} Vulnerability scanning"
echo -e "    ${GREEN}✓${NC} Report generation"
echo -e "    ${YELLOW}⚠${NC} Screenshots (disabled)"
echo ""
echo -e "  ${CYAN}Commands:${NC}"
echo -e "    python3 main.py scan example.com --no-screenshots"
echo -e "    python3 main.py recon example.com"
echo -e "    python3 main.py check"
echo ""
echo -e "  ${YELLOW}⚠  For authorized security testing only!${NC}"
echo ""
