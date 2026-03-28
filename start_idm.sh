#!/bin/bash
# Lightweight IDM service wrapper.
# Starts the API on the local loopback interface at port 9020 by default.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

exec python3 -m uvicorn src.idm.main:app --host 127.0.0.1 --port 9020 "$@"
