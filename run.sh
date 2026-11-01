#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_CMD="$SCRIPT_DIR/.venv/bin/python"
if [[ ! -x "$PYTHON_CMD" ]]; then
    PYTHON_CMD="${PYTHON:-python3}"
fi

cd "$SCRIPT_DIR"
exec "$PYTHON_CMD" -m ssh_ids.src.main --config "$SCRIPT_DIR/ssh_ids/config/config.json" "$@"
