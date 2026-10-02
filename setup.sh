#!/usr/bin/env bash
# setup.sh — Bootstrap the Red Team Logic Scanner
# 
# Prerequisites:
#   • Python 3.11+
#   • Node.js 20+ (for the Playwright MCP server)
#   • npm / npx
#
# Run once:  chmod +x setup.sh && ./setup.sh

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ── Check prerequisites ───────────────────────────────────────────────────────

info "Checking prerequisites…"

command -v python3 >/dev/null 2>&1 || error "Python 3 not found. Install from python.org"
command -v node    >/dev/null 2>&1 || error "Node.js not found. Install from nodejs.org (v20+)"
command -v npx     >/dev/null 2>&1 || error "npx not found. Install Node.js v20+"

PYTHON_VERSION=$(python3 -c 'import sys; print(sys.version_info[:2] >= (3, 11))')
if [ "$PYTHON_VERSION" != "True" ]; then
    error "Python 3.11+ required. Found: $(python3 --version)"
fi

NODE_VERSION=$(node -e "console.log(parseInt(process.version.slice(1)) >= 20)")
if [ "$NODE_VERSION" != "true" ]; then
    warn "Node.js v20+ recommended. Found: $(node --version)"
fi

# ── Python environment ────────────────────────────────────────────────────────

info "Creating Python virtual environment…"
python3 -m venv venv

info "Activating venv and installing Python dependencies…"
source venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# ── Node.js: Playwright MCP server ───────────────────────────────────────────

info "Installing Playwright MCP server (this downloads Chromium ~170MB)…"
npx --yes @playwright/mcp@latest --version 2>/dev/null \
    && info "Playwright MCP already installed." \
    || npx @playwright/mcp@latest install-deps 2>&1 | tail -5

# Install Chromium browser binary
info "Installing Playwright browser binaries…"
npx playwright install chromium 2>&1 | tail -3

# ── Data directories ──────────────────────────────────────────────────────────

info "Creating data directories…"
mkdir -p data/chroma_db reports

# ── .env setup ────────────────────────────────────────────────────────────────

if [ ! -f .env ]; then
    cp .env.example .env
    warn ".env created from template. Fill in your API keys before running."
else
    info ".env already exists — skipping."
fi

# ── Verify MCP server starts ──────────────────────────────────────────────────

info "Smoke-testing Playwright MCP server…"
timeout 5 npx @playwright/mcp@latest --version >/dev/null 2>&1 \
    && info "Playwright MCP server OK." \
    || warn "Could not verify MCP server — check Node.js installation."

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Setup complete!                             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  1. Edit .env with your Gemini + Groq API keys."
echo "  2. Start an authorised test target:"
echo "       docker run -p 3000:3000 bkimminich/juice-shop"
echo "  3. Activate venv and run:"
echo "       source venv/bin/activate"
echo "       python main.py --target http://localhost:3000"
echo ""
warn "⚠️  Only scan systems you OWN or have WRITTEN PERMISSION to test."
