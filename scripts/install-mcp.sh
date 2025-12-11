#!/bin/bash
#
# Install Chrome MCP Server to Claude Code
#
# This script adds the Chrome MCP server to your Claude Code configuration.
# Run this from the chrome-mcp/v2 directory.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if Claude Code is available
if ! command -v claude &> /dev/null; then
    log_error "Claude Code CLI not found. Please install it first."
    exit 1
fi

# Build if needed
if [ ! -f "$PROJECT_DIR/dist/index.js" ]; then
    log_info "Building Chrome MCP server..."
    cd "$PROJECT_DIR"
    npm install
    npm run build
fi

# Check if already installed
if claude mcp list 2>/dev/null | grep -q "chrome-mcp"; then
    log_warn "Chrome MCP server is already installed"
    read -p "Do you want to reinstall? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    claude mcp remove chrome-mcp 2>/dev/null || true
fi

# Add MCP server to Claude Code
log_info "Adding Chrome MCP server to Claude Code..."

claude mcp add chrome-mcp \
    --scope project \
    -- node "$PROJECT_DIR/dist/index.js"

log_info "Chrome MCP server installed successfully!"
echo ""
echo "Available tools:"
echo "  - health         : Check Chrome connection"
echo "  - navigate       : Navigate to URL"
echo "  - get_tabs       : List Chrome tabs"
echo "  - click_element  : Click element by selector"
echo "  - click          : Click at coordinates"
echo "  - type           : Type text"
echo "  - get_text       : Get element text"
echo "  - get_page_info  : Get page information"
echo "  - get_page_state : Get page state"
echo "  - scroll         : Scroll page"
echo "  - screenshot     : Take screenshot"
echo "  - wait_for_element: Wait for element"
echo "  - evaluate       : Execute JavaScript"
echo "  - fill           : Fill form field"
echo ""
echo "Make sure Chrome is running with:"
echo "  google-chrome --remote-debugging-port=9222"
