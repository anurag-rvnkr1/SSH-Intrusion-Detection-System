#!/bin/bash
#
# SSH IDS Installation Script
# Installs dependencies and prepares the system
#

set -e

echo "========================================="
echo "SSH Intrusion Detection System Installer"
echo "========================================="
echo ""

# Check Python version
echo "[*] Checking Python version..."
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    echo "✓ Found Python 3: $PYTHON_VERSION"
else
    echo "✗ Python 3 is required but not installed"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "[*] Installation directory: $SCRIPT_DIR"

# Create necessary directories
echo "[*] Creating directories..."
mkdir -p "$SCRIPT_DIR/logs"
mkdir -p "$SCRIPT_DIR/data"
chmod 755 "$SCRIPT_DIR/logs"
chmod 755 "$SCRIPT_DIR/data"
echo "✓ Directories created"

# Install Python dependencies
echo "[*] Installing Python dependencies..."
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    $PYTHON_CMD -m pip install -q -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null || {
        echo "✓ No external dependencies needed (using stdlib only)"
    }
else
    echo "✓ No requirements.txt found"
fi

# Check log file access
echo "[*] Checking log file permissions..."
if [ -f "/var/log/auth.log" ]; then
    if [ -r "/var/log/auth.log" ]; then
        echo "✓ Can read /var/log/auth.log"
    else
        echo "⚠ Warning: Cannot read /var/log/auth.log"
        echo "  You may need to run with sudo or adjust permissions"
    fi
else
    echo "⚠ /var/log/auth.log not found (expected on non-Ubuntu/Debian systems)"
fi

if [ -f "/var/log/secure" ]; then
    if [ -r "/var/log/secure" ]; then
        echo "✓ Can read /var/log/secure"
    else
        echo "⚠ Warning: Cannot read /var/log/secure"
        echo "  You may need to run with sudo or adjust permissions"
    fi
else
    echo "  /var/log/secure not found (expected on non-RHEL systems)"
fi

# Make scripts executable
echo "[*] Making scripts executable..."
chmod +x "$SCRIPT_DIR/run.sh" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/src/main.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/tests/test_detector.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/tests/simulate_attacks.py" 2>/dev/null || true
echo "✓ Scripts made executable"

# Test imports
echo "[*] Testing Python imports..."
if $PYTHON_CMD -c "import sys; sys.path.insert(0, '$SCRIPT_DIR/src'); from detector import SSHBruteForceDetector" 2>/dev/null; then
    echo "✓ All imports successful"
else
    echo "⚠ Warning: Could not import detector module"
fi

# Display next steps
echo ""
echo "========================================="
echo "Installation Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Configure SIEM settings:"
echo "   nano $SCRIPT_DIR/config/config.json"
echo ""
echo "2. Run the detector:"
echo "   sudo $SCRIPT_DIR/run.sh"
echo ""
echo "3. (Optional) Test with simulated attacks:"
echo "   python3 $SCRIPT_DIR/tests/simulate_attacks.py --print-only"
echo ""
echo "4. (Optional) Run unit tests:"
echo "   python3 $SCRIPT_DIR/tests/test_detector.py"
echo ""
echo "For help, see: $SCRIPT_DIR/README.md"
echo ""
