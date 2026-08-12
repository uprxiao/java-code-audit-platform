#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_ROOT="${AUDIT_DATA_ROOT:-${BUNDLE_ROOT}/data}"
PID_FILE="${AUDIT_RUN_ROOT:-${DATA_ROOT}/run}/audit.pid"
APP_JAR="${AUDIT_APP_JAR:-${BUNDLE_ROOT}/app/audit-api.jar}"
PORT="${AUDIT_PORT:-8080}"

if [[ ! -f "${PID_FILE}" ]]; then
  echo "STOPPED"
  exit 3
fi
PID="$(tr -dc '0-9' < "${PID_FILE}")"
COMMAND_LINE="$(ps -p "${PID}" -o command= 2>/dev/null || true)"
if [[ -z "${PID}" || "${COMMAND_LINE}" != *"${APP_JAR}"* ]]; then
  echo "STALE_PID"
  exit 4
fi
if curl --fail --silent "http://127.0.0.1:${PORT}/api/v1/health" >/dev/null; then
  echo "RUNNING pid=${PID} port=${PORT}"
  exit 0
fi
echo "STARTING_OR_DEGRADED pid=${PID} port=${PORT}"
exit 1
