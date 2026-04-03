#!/bin/bash
# Lightweight IDM service wrapper.
# Stops any process already listening on the configured port, then starts the API in the background.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

HOST="${IDM_HOST:-0.0.0.0}"
PORT="${IDM_PORT:-9020}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
LOG_DIR="${SCRIPT_DIR}/logs"
PID_FILE="${LOG_DIR}/idm.pid"
LOG_FILE="${LOG_DIR}/idm_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "${LOG_DIR}"

find_listeners() {
    if command -v lsof >/dev/null 2>&1; then
        lsof -ti tcp:"${PORT}" 2>/dev/null || true
        return
    fi

    if command -v ss >/dev/null 2>&1; then
        ss -ltnp "sport = :${PORT}" 2>/dev/null | awk '
            match($0, /pid=([0-9]+)/, m) { print m[1] }
        ' | sort -u
        return
    fi

    return 0
}

PIDS="$(find_listeners | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
if [ -n "${PIDS}" ]; then
    echo "Port ${PORT} is already in use by: ${PIDS}"
    echo "Stopping existing process(es)..."
    kill ${PIDS} 2>/dev/null || true

    for _ in 1 2 3 4 5; do
        sleep 1
        PIDS="$(find_listeners | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
        if [ -z "${PIDS}" ]; then
            break
        fi
    done

    PIDS="$(find_listeners | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    if [ -n "${PIDS}" ]; then
        echo "Some processes are still alive; forcing termination..."
        kill -9 ${PIDS} 2>/dev/null || true
    fi
fi

if [ -f "${PID_FILE}" ]; then
    OLD_PID="$(cat "${PID_FILE}" 2>/dev/null || true)"
    if [ -n "${OLD_PID}" ] && kill -0 "${OLD_PID}" 2>/dev/null; then
        echo "Stopping previous IDM process from PID file: ${OLD_PID}"
        kill "${OLD_PID}" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            sleep 1
            if ! kill -0 "${OLD_PID}" 2>/dev/null; then
                break
            fi
        done
        if kill -0 "${OLD_PID}" 2>/dev/null; then
            echo "Previous process is still alive; forcing termination..."
            kill -9 "${OLD_PID}" 2>/dev/null || true
        fi
    fi
    rm -f "${PID_FILE}"
fi

echo "Starting IDM service in background..."
nohup "${PYTHON_BIN}" -m uvicorn src.idm.main:app --host "${HOST}" --port "${PORT}" "$@" >>"${LOG_FILE}" 2>&1 &
PID=$!

sleep 1
if ! kill -0 "${PID}" 2>/dev/null; then
    echo "Failed to start IDM service."
    echo "Log file: ${LOG_FILE}"
    tail -n 20 "${LOG_FILE}" 2>/dev/null || true
    exit 1
fi

echo "${PID}" > "${PID_FILE}"
echo "IDM service started with PID ${PID}"
echo "Log file: ${LOG_FILE}"
