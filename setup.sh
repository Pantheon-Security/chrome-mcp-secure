#!/bin/bash
#
# Chrome MCP v2 - One-Command Setup for Claude Code
#
# This script:
# 1. Installs dependencies and builds the project
# 2. Registers the MCP server with Claude Code
# 3. Updates your project's CLAUDE.md (non-destructive)
# 4. Verifies Chrome connection
#
# Usage:
#   ./setup.sh              # Full setup
#   ./setup.sh --uninstall  # Remove from Claude Code
#   ./setup.sh --check      # Check status only
#
# Based on lxe/chrome-mcp, redesigned by Pantheon Security
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_NAME="chrome-mcp-secure"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Logging functions
log_info() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step() { echo -e "${BLUE}[→]${NC} $1"; }

print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║     🌐 Chrome MCP v2.1.0 - Browser Automation for AI      ║"
    echo "║                                                            ║"
    echo "║     Persistent connections • Post-quantum encryption       ║"
    echo "║     Secure credential vault • Profile isolation           ║"
    echo "║     Based on lxe/chrome-mcp • By Pantheon Security        ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if Chrome is running with debugging
check_chrome() {
    local port="${CHROME_PORT:-9222}"
    if curl -s "http://localhost:$port/json/version" > /dev/null 2>&1; then
        local version=$(curl -s "http://localhost:$port/json/version" | grep -o '"Browser":"[^"]*"' | cut -d'"' -f4)
        log_info "Chrome detected: $version"
        return 0
    else
        return 1
    fi
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)       echo "unknown" ;;
    esac
}

OS_TYPE=$(detect_os)

# Find Chrome executable (cross-platform)
find_chrome() {
    local chrome_paths=()

    case "$OS_TYPE" in
        macos)
            chrome_paths=(
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
                "/Applications/Chromium.app/Contents/MacOS/Chromium"
                "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"
                "$HOME/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
            )
            ;;
        linux)
            chrome_paths=(
                "google-chrome"
                "google-chrome-stable"
                "chromium"
                "chromium-browser"
                "/usr/bin/google-chrome"
                "/usr/bin/chromium"
                "/usr/bin/chromium-browser"
                "/snap/bin/chromium"
                "/opt/google/chrome/chrome"
            )
            ;;
        windows)
            chrome_paths=(
                "/c/Program Files/Google/Chrome/Application/chrome.exe"
                "/c/Program Files (x86)/Google/Chrome/Application/chrome.exe"
                "$LOCALAPPDATA/Google/Chrome/Application/chrome.exe"
            )
            ;;
    esac

    for path in "${chrome_paths[@]}"; do
        if [ -x "$path" ] || command -v "$path" &> /dev/null 2>&1; then
            echo "$path"
            return 0
        fi
    done

    return 1
}

# Start Chrome with debugging enabled (cross-platform)
start_chrome() {
    local port="${CHROME_PORT:-9222}"
    local chrome_bin

    # Check if already running
    if check_chrome; then
        return 0
    fi

    # Find Chrome
    chrome_bin=$(find_chrome)
    if [ -z "$chrome_bin" ]; then
        log_error "Chrome not found. Please install Google Chrome or Chromium."
        case "$OS_TYPE" in
            macos)  log_info "Install from: https://www.google.com/chrome/" ;;
            linux)  log_info "Install with: sudo apt install google-chrome-stable" ;;
            windows) log_info "Install from: https://www.google.com/chrome/" ;;
        esac
        return 1
    fi

    log_step "Starting Chrome with remote debugging on port $port..."

    # Use a dedicated profile to avoid conflicts with existing Chrome sessions
    local profile_dir="${CHROME_PROFILE_DIR:-$HOME/.chrome-mcp-profile}"

    # Start Chrome based on OS
    case "$OS_TYPE" in
        macos)
            # macOS needs special handling - use open command or direct execution
            if [[ "$chrome_bin" == *".app"* ]]; then
                # Extract the app bundle path
                local app_path="${chrome_bin%/Contents/MacOS/*}"
                open -a "$app_path" --args \
                    --remote-debugging-port="$port" \
                    --user-data-dir="$profile_dir" \
                    --no-first-run \
                    --no-default-browser-check \
                    --disable-background-timer-throttling \
                    --disable-backgrounding-occluded-windows \
                    --disable-renderer-backgrounding \
                    "about:blank" &
            else
                "$chrome_bin" \
                    --remote-debugging-port="$port" \
                    --user-data-dir="$profile_dir" \
                    --no-first-run \
                    --no-default-browser-check \
                    --disable-background-timer-throttling \
                    --disable-backgrounding-occluded-windows \
                    --disable-renderer-backgrounding \
                    "about:blank" \
                    > /dev/null 2>&1 &
            fi
            ;;
        *)
            # Linux and Windows (via Git Bash/WSL)
            "$chrome_bin" \
                --remote-debugging-port="$port" \
                --user-data-dir="$profile_dir" \
                --no-first-run \
                --no-default-browser-check \
                --disable-background-timer-throttling \
                --disable-backgrounding-occluded-windows \
                --disable-renderer-backgrounding \
                "about:blank" \
                > /dev/null 2>&1 &
            ;;
    esac

    local chrome_pid=$!
    echo $chrome_pid > "$SCRIPT_DIR/.chrome-mcp.pid"

    # Wait for Chrome to start (max 10 seconds)
    local count=0
    while [ $count -lt 20 ]; do
        if check_chrome 2>/dev/null; then
            log_info "Chrome started (PID: $chrome_pid)"
            return 0
        fi
        sleep 0.5
        count=$((count + 1))
    done

    log_error "Chrome failed to start within timeout"
    return 1
}

# Stop Chrome that we started
stop_chrome() {
    local pid_file="$SCRIPT_DIR/.chrome-mcp.pid"

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            log_step "Stopping Chrome (PID: $pid)..."
            kill "$pid" 2>/dev/null
            rm -f "$pid_file"
            log_info "Chrome stopped"
        else
            rm -f "$pid_file"
        fi
    else
        log_warn "No Chrome PID file found (Chrome may not have been started by this script)"
    fi
}

# Check if MCP is already installed
is_installed() {
    claude mcp list 2>/dev/null | grep -q "$MCP_NAME"
}

# Build the project
build_project() {
    log_step "Building Chrome MCP..."
    cd "$SCRIPT_DIR"

    if [ ! -d "node_modules" ]; then
        log_step "Installing dependencies..."
        npm install --silent
    fi

    if [ ! -f "dist/index.js" ] || [ "src/index.ts" -nt "dist/index.js" ]; then
        npm run build --silent
    fi

    log_info "Build complete"
}

# Install to Claude Code
install_mcp() {
    log_step "Registering with Claude Code..."

    # Remove if exists (clean reinstall)
    if is_installed; then
        claude mcp remove "$MCP_NAME" > /dev/null 2>&1 || true
    fi

    # Add the MCP server (user scope so it's available everywhere)
    claude mcp add "$MCP_NAME" \
        --scope user \
        -- node "$SCRIPT_DIR/dist/index.js"

    log_info "MCP server registered: $MCP_NAME"
}

# Uninstall from Claude Code
uninstall_mcp() {
    log_step "Removing from Claude Code..."

    if is_installed; then
        claude mcp remove "$MCP_NAME"
        log_info "MCP server removed"
    else
        log_warn "MCP server not installed"
    fi
}

# Update CLAUDE.md non-destructively
update_claude_md() {
    local target_dir="${1:-.}"
    local claude_md="$target_dir/CLAUDE.md"
    local marker="<!-- CHROME-MCP-START -->"
    local end_marker="<!-- CHROME-MCP-END -->"

    local chrome_section="$marker
## Chrome MCP - Browser Automation

Chrome MCP is available for browser automation tasks.

### Quick Reference
\`\`\`
# Check connection
mcp__chrome-mcp__health()

# Navigate
mcp__chrome-mcp__navigate({ url: \"https://example.com\" })

# Get page info
mcp__chrome-mcp__get_page_info()

# Click element
mcp__chrome-mcp__click_element({ selector: \"#button\" })

# Type text
mcp__chrome-mcp__type({ text: \"Hello\" })

# Screenshot
mcp__chrome-mcp__screenshot()
\`\`\`

### Requirements
Chrome must be running with: \`google-chrome --remote-debugging-port=9222\`

$end_marker"

    if [ -f "$claude_md" ]; then
        # Check if section already exists
        if grep -q "$marker" "$claude_md"; then
            log_info "CLAUDE.md already has Chrome MCP section"
            return 0
        fi

        # Append to existing file
        echo "" >> "$claude_md"
        echo "$chrome_section" >> "$claude_md"
        log_info "Updated CLAUDE.md with Chrome MCP section"
    else
        # Create new file
        echo "# Project Instructions" > "$claude_md"
        echo "" >> "$claude_md"
        echo "$chrome_section" >> "$claude_md"
        log_info "Created CLAUDE.md with Chrome MCP section"
    fi
}

# Show status
show_status() {
    echo ""
    echo -e "${BOLD}Status:${NC}"

    # MCP registration
    if is_installed; then
        log_info "MCP server: Registered"
    else
        log_error "MCP server: Not registered"
    fi

    # Chrome connection
    if check_chrome; then
        : # Already logged
    else
        log_warn "Chrome: Not running with debugging"
        echo -e "        Start with: ${CYAN}google-chrome --remote-debugging-port=9222${NC}"
    fi

    # Build status
    if [ -f "$SCRIPT_DIR/dist/index.js" ]; then
        log_info "Build: Ready"
    else
        log_warn "Build: Not built (run setup.sh)"
    fi
}

# Main setup flow
do_setup() {
    print_banner

    # Step 1: Build
    build_project

    # Step 2: Install to Claude Code
    install_mcp

    # Step 3: Auto-start Chrome if not running
    echo ""
    if ! check_chrome 2>/dev/null; then
        start_chrome
    fi

    # Step 4: Show available tools
    echo ""
    echo -e "${BOLD}Browser Tools:${NC}"
    echo "  health, navigate, get_tabs, click_element, click, type,"
    echo "  get_text, get_page_info, get_page_state, scroll, screenshot,"
    echo "  wait_for_element, evaluate, fill, bypass_cert_and_navigate"
    echo ""
    echo -e "${BOLD}Secure Credential Tools:${NC}"
    echo "  store_credential, list_credentials, get_credential,"
    echo "  delete_credential, update_credential, secure_login,"
    echo "  get_vault_status"
    echo ""
    echo -e "${BOLD}Security Features:${NC}"
    echo "  • Post-quantum encryption (ML-KEM-768 + ChaCha20-Poly1305)"
    echo "  • Credentials encrypted at rest and wiped from memory"
    echo "  • Automatic log masking for sensitive data"
    echo "  • Isolated Chrome profile for secure sessions"
    echo ""

    # Step 5: Quick test hint
    echo -e "${BOLD}Quick Test:${NC}"
    echo -e "  In Claude Code, try: ${CYAN}Use the health tool to check Chrome connection${NC}"
    echo ""

    log_info "Setup complete! Chrome MCP is ready to use."
}

# Parse arguments
case "${1:-}" in
    --uninstall|-u)
        print_banner
        uninstall_mcp
        ;;
    --check|-c)
        print_banner
        show_status
        ;;
    --start-chrome)
        start_chrome
        ;;
    --stop-chrome)
        stop_chrome
        ;;
    --update-claude-md)
        update_claude_md "${2:-.}"
        ;;
    --help|-h)
        print_banner
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  (none)              Full setup - build, install, start Chrome"
        echo "  --uninstall, -u     Remove from Claude Code"
        echo "  --check, -c         Check installation status"
        echo "  --start-chrome      Start Chrome with debugging enabled"
        echo "  --stop-chrome       Stop Chrome instance started by this script"
        echo "  --update-claude-md  Add Chrome MCP section to CLAUDE.md"
        echo "  --help, -h          Show this help"
        echo ""
        echo "Environment Variables:"
        echo "  CHROME_PORT                    Chrome debugging port (default: 9222)"
        echo "  CHROME_PROFILE_DIR             Chrome profile directory (default: ~/.chrome-mcp-profile)"
        echo ""
        echo "Security Environment Variables:"
        echo "  CHROME_MCP_ENCRYPTION_KEY      Base64 encryption key (recommended)"
        echo "  CHROME_MCP_ENCRYPTION_KEY_FILE Path to file containing encryption key"
        echo "  CHROME_MCP_USE_MACHINE_KEY     Use machine-derived key (default: true)"
        echo "  CHROME_MCP_USE_POST_QUANTUM    Enable post-quantum encryption (default: true)"
        echo "  CHROME_MCP_CONFIG_DIR          Config directory (default: ~/.chrome-mcp)"
        echo "  CHROME_MCP_CREDENTIAL_TTL      Credential memory TTL in ms (default: 300000)"
        ;;
    *)
        do_setup
        ;;
esac
