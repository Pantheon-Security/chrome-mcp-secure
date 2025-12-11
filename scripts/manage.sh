#!/bin/bash
#
# Chrome MCP Server Management Script
#
# Usage:
#   ./manage.sh start     - Start the MCP server
#   ./manage.sh stop      - Stop the MCP server
#   ./manage.sh status    - Check server status
#   ./manage.sh health    - Check Chrome connection
#   ./manage.sh logs      - View recent logs
#   ./manage.sh restart   - Restart the server
#
# Environment Variables:
#   CHROME_HOST     - Chrome debugging host (default: localhost)
#   CHROME_PORT     - Chrome debugging port (default: 9222)
#   LOG_LEVEL       - Logging level (default: info)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$PROJECT_DIR/.chrome-mcp.pid"
LOG_DIR="$PROJECT_DIR/logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if server is running
is_running() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Get the PID
get_pid() {
    if [ -f "$PID_FILE" ]; then
        cat "$PID_FILE"
    fi
}

# Start the server
cmd_start() {
    if is_running; then
        log_warn "Server is already running (PID: $(get_pid))"
        return 1
    fi

    log_info "Starting Chrome MCP server..."

    # Ensure log directory exists
    mkdir -p "$LOG_DIR"

    # Check if built
    if [ ! -f "$PROJECT_DIR/dist/index.js" ]; then
        log_info "Building project..."
        cd "$PROJECT_DIR"
        npm run build
    fi

    # Start the server
    cd "$PROJECT_DIR"
    node dist/index.js &
    local pid=$!
    echo $pid > "$PID_FILE"

    # Give it a moment to start
    sleep 1

    if is_running; then
        log_info "Server started (PID: $pid)"
    else
        log_error "Server failed to start"
        rm -f "$PID_FILE"
        return 1
    fi
}

# Stop the server
cmd_stop() {
    if ! is_running; then
        log_warn "Server is not running"
        rm -f "$PID_FILE"
        return 0
    fi

    local pid=$(get_pid)
    log_info "Stopping Chrome MCP server (PID: $pid)..."

    # Send SIGTERM for graceful shutdown
    kill "$pid" 2>/dev/null

    # Wait for process to end
    local count=0
    while kill -0 "$pid" 2>/dev/null && [ $count -lt 10 ]; do
        sleep 1
        count=$((count + 1))
    done

    # Force kill if still running
    if kill -0 "$pid" 2>/dev/null; then
        log_warn "Server didn't stop gracefully, forcing..."
        kill -9 "$pid" 2>/dev/null
    fi

    rm -f "$PID_FILE"
    log_info "Server stopped"
}

# Check server status
cmd_status() {
    if is_running; then
        local pid=$(get_pid)
        log_info "Server is running (PID: $pid)"

        # Check Chrome connection
        local chrome_port="${CHROME_PORT:-9222}"
        if curl -s "http://localhost:$chrome_port/json" > /dev/null 2>&1; then
            log_info "Chrome is accessible on port $chrome_port"
        else
            log_warn "Chrome is not accessible on port $chrome_port"
        fi
    else
        log_info "Server is not running"
    fi
}

# Check Chrome health
cmd_health() {
    local chrome_host="${CHROME_HOST:-localhost}"
    local chrome_port="${CHROME_PORT:-9222}"
    local url="http://$chrome_host:$chrome_port"

    log_info "Checking Chrome at $url..."

    # Check version
    local version=$(curl -s "$url/json/version" 2>/dev/null)
    if [ -n "$version" ]; then
        local browser=$(echo "$version" | grep -o '"Browser":"[^"]*"' | cut -d'"' -f4)
        log_info "Chrome version: $browser"

        # Get tabs
        local tabs=$(curl -s "$url/json" 2>/dev/null | grep -c '"id":')
        log_info "Open tabs: $tabs"
    else
        log_error "Chrome is not accessible"
        log_info "Start Chrome with: google-chrome --remote-debugging-port=$chrome_port"
        return 1
    fi
}

# View logs
cmd_logs() {
    local log_file="$LOG_DIR/audit-$(date +%Y-%m-%d).jsonl"

    if [ -f "$log_file" ]; then
        log_info "Recent log entries:"
        tail -20 "$log_file" | while read line; do
            echo "$line" | python3 -m json.tool 2>/dev/null || echo "$line"
        done
    else
        log_info "No logs found for today"
        log_info "Log directory: $LOG_DIR"
    fi
}

# Restart the server
cmd_restart() {
    cmd_stop
    sleep 1
    cmd_start
}

# Show help
cmd_help() {
    echo "Chrome MCP Server Management"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  start     Start the MCP server"
    echo "  stop      Stop the MCP server"
    echo "  status    Check server and Chrome status"
    echo "  health    Check Chrome connection"
    echo "  logs      View recent audit logs"
    echo "  restart   Restart the server"
    echo "  help      Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  CHROME_HOST   Chrome debugging host (default: localhost)"
    echo "  CHROME_PORT   Chrome debugging port (default: 9222)"
    echo "  LOG_LEVEL     Logging level: debug, info, warn, error"
}

# Main entry point
case "${1:-help}" in
    start)
        cmd_start
        ;;
    stop)
        cmd_stop
        ;;
    status)
        cmd_status
        ;;
    health)
        cmd_health
        ;;
    logs)
        cmd_logs
        ;;
    restart)
        cmd_restart
        ;;
    help|--help|-h)
        cmd_help
        ;;
    *)
        log_error "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
