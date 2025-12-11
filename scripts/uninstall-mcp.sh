#!/bin/bash
#
# Uninstall Chrome MCP Server from Claude Code
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Check if installed
if ! claude mcp list 2>/dev/null | grep -q "chrome-mcp"; then
    log_warn "Chrome MCP server is not installed"
    exit 0
fi

log_info "Removing Chrome MCP server from Claude Code..."

claude mcp remove chrome-mcp

log_info "Chrome MCP server removed successfully!"
