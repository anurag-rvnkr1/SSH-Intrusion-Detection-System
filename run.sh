#!/bin/bash
#
# SSH IDS Run Script
# Starts the SSH intrusion detection system
#

set -e

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_FILE="$SCRIPT_DIR/config/config.json"
LOG_FILE="$SCRIPT_DIR/logs/ssh-ids.log"
MAIN_SCRIPT="$SCRIPT_DIR/src/main.py"

# Find Python
PYTHON_CMD="python3"
if ! command -v $PYTHON_CMD &> /dev/null; then
    echo "Error: python3 is required but not installed"
    exit 1
fi

# Check if running with proper privileges
check_permissions() {
    # Try to read auth.log
    if [ ! -r "/var/log/auth.log" ] && [ ! -r "/var/log/secure" ]; then
        echo "Warning: Cannot read auth logs with current permissions."
        echo "The IDS may not function properly without sudo access."
        echo ""
        echo "Consider running with: sudo $SCRIPT_DIR/run.sh"
        echo ""
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Display header
show_header() {
    echo "========================================="
    echo "SSH Intrusion Detection System"
    echo "========================================="
    echo "Config: $CONFIG_FILE"
    echo "Log: $LOG_FILE"
    echo ""
    echo "Press Ctrl+C to stop"
    echo "========================================="
    echo ""
}

# Create log directory
mkdir -p "$SCRIPT_DIR/logs"

# Verify config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Check permissions
check_permissions

# Display header
show_header

# Run the application
$PYTHON_CMD "$MAIN_SCRIPT" "$CONFIG_FILE" 2>&1 | tee -a "$LOG_FILE"
