#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$BACKEND_ROOT"

pyinstaller --clean --noconfirm "$SCRIPT_DIR/packet_peeper_backend.spec"

echo "Backend binary built at: $BACKEND_ROOT/dist/packet_peeper_backend"
