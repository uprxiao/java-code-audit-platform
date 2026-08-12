#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_ROOT="${AUDIT_DATA_ROOT:-${BUNDLE_ROOT}/data}"
PID_FILE="${AUDIT_RUN_ROOT:-${DATA_ROOT}/run}/audit.pid"
APP_JAR="${AUDIT_APP_JAR:-${BUNDLE_ROOT}/app/audit-api.jar}"

if [[ ! -f "${PID_FILE}" ]]; then
  echo "Java Code Audit Platform is not running (no PID file)."
  exit 0
fi
PID="$(tr -dc '0-9' < "${PID_FILE}")"
COMMAND_LINE="$(ps -p "${PID}" -o command= 2>/dev/null || true)"
if [[ -z "${PID}" || "${COMMAND_LINE}" != *"${APP_JAR}"* ]]; then
  mv "${PID_FILE}" "${PID_FILE}.stale.$(date +%s)"
  echo "Removed a stale PID reference; no matching service process was stopped."
  exit 0
fi

kill -TERM "${PID}"
for _ in $(seq 1 120); do
  if ! kill -0 "${PID}" 2>/dev/null; then
    rm -f "${PID_FILE}"
    echo "Java Code Audit Platform stopped."
    exit 0
  fi
  sleep 0.5
done

echo "Graceful shutdown exceeded 60 seconds; sending SIGKILL to the verified service process." >&2
kill -KILL "${PID}"
rm -f "${PID_FILE}"
