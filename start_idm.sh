#!/bin/bash
# Lightweight IDM service wrapper.
# Usage: ./start_idm.sh [start|stop|restart|log|status] [--foreground] [uvicorn args...]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

HOST="${IDM_HOST:-0.0.0.0}"
PORT="${IDM_PORT:-9020}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
LOG_DIR="${SCRIPT_DIR}/logs"
PID_FILE="${LOG_DIR}/idm.pid"
HEALTH_URL="http://127.0.0.1:${PORT}/idm/v1/health"
FOREGROUND="0"
COMMAND="start"

usage() {
    cat <<EOF
Usage: $0 [command] [options] [uvicorn args...]

Commands:
  start      Stop any existing IDM process on the configured port, then start IDM (default)
  stop       Stop the IDM process from the PID file and anything listening on the configured port
  restart    Stop IDM, then start it again
  log        Follow the latest IDM wrapper log file
  status     Show PID/port/health status
  help       Show this help

Options:
  --foreground   Run uvicorn in the foreground and mirror output to a log file

Environment:
  IDM_HOST        Bind host, default: 0.0.0.0
  IDM_PORT        Bind port, default: 9020
  PYTHON_BIN      Python executable, default: python3
  LOG_LINES       Lines shown by log command, default: 100
EOF
}

if [ "${1:-}" = "help" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

case "${1:-}" in
    start|stop|restart|log|logs|status)
        COMMAND="$1"
        shift
        ;;
esac

if [ "${1:-}" = "--foreground" ]; then
    FOREGROUND="1"
    shift
fi

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

listener_pids() {
    find_listeners | tr '\n' ' ' | sed 's/[[:space:]]*$//'
}

latest_log_file() {
    find "${LOG_DIR}" -maxdepth 1 -type f -name 'idm_*.log' -printf '%T@ %p\n' 2>/dev/null \
        | sort -nr \
        | awk 'NR == 1 { sub(/^[^ ]+ /, ""); print }'
}

stop_pid() {
    local pid="$1"
    local label="$2"

    if [ -z "${pid}" ]; then
        return
    fi

    if ! kill -0 "${pid}" 2>/dev/null; then
        return
    fi

    echo "Stopping ${label}: ${pid}"
    kill "${pid}" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        sleep 1
        if ! kill -0 "${pid}" 2>/dev/null; then
            return
        fi
    done

    if kill -0 "${pid}" 2>/dev/null; then
        echo "${label} is still alive; forcing termination..."
        kill -9 "${pid}" 2>/dev/null || true
    fi
}

stop_service() {
    local old_pid=""
    local pids=""
    local stopped="0"

    if [ -f "${PID_FILE}" ]; then
        old_pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
        if [ -n "${old_pid}" ] && kill -0 "${old_pid}" 2>/dev/null; then
            stopped="1"
        fi
        stop_pid "${old_pid}" "previous IDM process from PID file"
        rm -f "${PID_FILE}"
    fi

    pids="$(listener_pids)"
    if [ -n "${pids}" ]; then
        stopped="1"
        echo "Port ${PORT} is in use by: ${pids}"
        echo "Stopping listener process(es)..."
        kill ${pids} 2>/dev/null || true

        for _ in 1 2 3 4 5; do
            sleep 1
            pids="$(listener_pids)"
            if [ -z "${pids}" ]; then
                break
            fi
        done

        pids="$(listener_pids)"
        if [ -n "${pids}" ]; then
            echo "Some listener processes are still alive; forcing termination..."
            kill -9 ${pids} 2>/dev/null || true
        fi
    fi

    if [ "${stopped}" = "1" ]; then
        echo "IDM service stopped."
    else
        echo "No existing IDM process found."
    fi
}

start_service() {
    local log_file="${LOG_DIR}/idm_$(date +%Y%m%d_%H%M%S).log"
    local pid=""
    local health_ok="0"

    stop_service

    if [ "${FOREGROUND}" = "1" ]; then
        echo "Starting IDM service in foreground..."
        echo "Log output will be shown in this terminal and written to: ${log_file}"
        exec "${PYTHON_BIN}" -m uvicorn src.idm.main:app --host "${HOST}" --port "${PORT}" "$@" 2>&1 | tee -a "${log_file}"
    fi

    echo "Starting IDM service in background..."
    nohup "${PYTHON_BIN}" -m uvicorn src.idm.main:app --host "${HOST}" --port "${PORT}" "$@" \
        </dev/null >>"${log_file}" 2>&1 &
    pid=$!
    disown "${pid}" 2>/dev/null || true

    sleep 1
    if ! kill -0 "${pid}" 2>/dev/null; then
        echo "Failed to start IDM service."
        echo "Log file: ${log_file}"
        tail -n 20 "${log_file}" 2>/dev/null || true
        exit 1
    fi

    if command -v curl >/dev/null 2>&1; then
        for _ in 1 2 3 4 5; do
            if curl -fsS "${HEALTH_URL}" >/dev/null 2>&1; then
                health_ok="1"
                break
            fi
            sleep 1
            if ! kill -0 "${pid}" 2>/dev/null; then
                break
            fi
        done
    fi

    echo "${pid}" > "${PID_FILE}"
    echo "IDM service started with PID ${pid}"
    echo "Log file: ${log_file}"
    if [ "${health_ok}" = "1" ]; then
        echo "Health check passed: ${HEALTH_URL}"
    else
        echo "Health check not confirmed yet: ${HEALTH_URL}"
        echo "If the process exits right after this command, the current terminal/runtime may be reaping background jobs."
    fi
}

show_logs() {
    local log_file=""
    local lines="${LOG_LINES:-100}"

    log_file="$(latest_log_file)"
    if [ -z "${log_file}" ]; then
        echo "No IDM log files found in ${LOG_DIR}"
        exit 1
    fi

    echo "Following ${log_file}"
    tail -n "${lines}" -f "${log_file}"
}

show_status() {
    local pid=""
    local pids=""

    if [ -f "${PID_FILE}" ]; then
        pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
        if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
            echo "PID file: ${PID_FILE} -> running PID ${pid}"
        else
            echo "PID file: ${PID_FILE} -> stale or stopped PID ${pid}"
        fi
    else
        echo "PID file: ${PID_FILE} -> missing"
    fi

    pids="$(listener_pids)"
    if [ -n "${pids}" ]; then
        echo "Port ${PORT}: listening PID(s) ${pids}"
    else
        echo "Port ${PORT}: no listener"
    fi

    if command -v curl >/dev/null 2>&1; then
        if curl -fsS "${HEALTH_URL}" >/dev/null 2>&1; then
            echo "Health: OK (${HEALTH_URL})"
        else
            echo "Health: not reachable (${HEALTH_URL})"
        fi
    else
        echo "Health: curl not available"
    fi
}

case "${COMMAND}" in
    start)
        start_service "$@"
        ;;
    stop)
        stop_service
        ;;
    restart)
        start_service "$@"
        ;;
    log|logs)
        show_logs
        ;;
    status)
        show_status
        ;;
    *)
        echo "Unknown command: ${COMMAND}"
        usage
        exit 1
        ;;
esac
