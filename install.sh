#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_CMD="${PYTHON:-python3}"

if ! command -v "$PYTHON_CMD" >/dev/null 2>&1; then
    echo "Error: Python 3.10 or newer is required." >&2
    exit 1
fi

"$PYTHON_CMD" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
    echo "Error: Python 3.10 or newer is required." >&2
    exit 1
}

if [[ ! -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
    "$PYTHON_CMD" -m venv "$SCRIPT_DIR/.venv"
fi
"$SCRIPT_DIR/.venv/bin/python" -m pip install -r "$SCRIPT_DIR/requirements.txt"

echo "Environment ready: $SCRIPT_DIR/.venv"
echo "Run with: $SCRIPT_DIR/run.sh"
echo "This installer does not read or modify system authentication logs."
