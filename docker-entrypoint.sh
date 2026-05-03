#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${DEFENSECLAW_DATA_DIR:-/root/.defenseclaw}"
OPENCLAW_HOST="${OPENCLAW_HOST:-host-gateway}"
OPENCLAW_PORT="${OPENCLAW_PORT:-18789}"

init_if_needed() {
    if [ ! -f "${DATA_DIR}/config.yaml" ]; then
        echo "[entrypoint] First run — initializing DefenseClaw..."
        NO_LLM_SETUP=1 defenseclaw init --skip-install
        defenseclaw setup gateway \
            --host "${OPENCLAW_HOST}" \
            --port "${OPENCLAW_PORT}" \
            --non-interactive
        defenseclaw setup guardrail \
            --mode "${GUARDRAIL_MODE:-observe}" \
            --non-interactive
    fi
}

case "${1:-start}" in
    start)
        init_if_needed
        echo "[entrypoint] Starting defenseclaw-gateway..."
        defenseclaw-gateway start
        exec defenseclaw-gateway watchdog
        ;;
    init)
        init_if_needed
        ;;
    doctor)
        exec defenseclaw doctor
        ;;
    *)
        exec "$@"
        ;;
esac
