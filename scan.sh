#!/bin/bash
# Wrapper: avvia il toolkit Python (menu interattivo)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/oscp-scan" "$@"
