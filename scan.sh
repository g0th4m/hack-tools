#!/bin/bash
# Wrapper: launches the Python toolkit (interactive menu)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/oscp-scan" "$@"
