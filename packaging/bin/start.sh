#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_JAR="${AUDIT_APP_JAR:-${BUNDLE_ROOT}/app/audit-api.jar}"
DATA_ROOT="${AUDIT_DATA_ROOT:-${BUNDLE_ROOT}/data}"
RUN_ROOT="${AUDIT_RUN_ROOT:-${DATA_ROOT}/run}"
LOG_ROOT="${AUDIT_LOG_ROOT:-${DATA_ROOT}/service-logs}"
PORT="${AUDIT_PORT:-8080}"
PID_FILE="${RUN_ROOT}/audit.pid"
SERVER_LOG="${LOG_ROOT}/audit.log"

platform_id() {
  local kernel machine
  kernel="$(uname -s)"
  machine="$(uname -m)"
  if [[ "${kernel}" == "Darwin" && "${machine}" == "arm64" ]]; then
    echo "darwin-arm64"
  elif [[ "${kernel}" == "Linux" && ( "${machine}" == "x86_64" || "${machine}" == "amd64" ) ]]; then
    echo "linux-x86_64"
  else
    echo "Unsupported V1 platform: ${kernel}/${machine}" >&2
    return 2
  fi
}

require_java17() {
  local feature
  command -v java >/dev/null 2>&1 || { echo "JDK 17 is required." >&2; return 2; }
  feature="$(java -version 2>&1 | awk -F'[\".]' '/version/ {print $2; exit}')"
  [[ "${feature}" == "17" ]] || { echo "JDK 17 is required; found ${feature:-unknown}." >&2; return 2; }
}

require_maven39() {
  local version major minor
  command -v mvn >/dev/null 2>&1 || { echo "Maven 3.9+ is required." >&2; return 2; }
  version="$(mvn --version 2>/dev/null | awk 'NR==1 {print $3}')"
  major="${version%%.*}"
  minor="${version#*.}"
  minor="${minor%%.*}"
  if [[ ! "${major}" =~ ^[0-9]+$ || ! "${minor}" =~ ^[0-9]+$ ]] \
      || (( major < 3 || (major == 3 && minor < 9) )); then
    echo "Maven 3.9+ is required; found ${version:-unknown}." >&2
    return 2
  fi
}

process_matches() {
  local pid="$1" command_line
  kill -0 "${pid}" 2>/dev/null || return 1
  command_line="$(ps -p "${pid}" -o command= 2>/dev/null || true)"
  [[ "${command_line}" == *"${APP_JAR}"* || "${command_line}" == *"${BUNDLE_ROOT}/bin/run.sh"* ]]
}

require_java17
require_maven39
PLATFORM="$(platform_id)"
[[ -f "${APP_JAR}" ]] || { echo "Application JAR is missing: ${APP_JAR}" >&2; exit 2; }
[[ -x "${BUNDLE_ROOT}/tools/${PLATFORM}/semgrep/semgrep/bin/semgrep" ]] \
  || { echo "Semgrep tool pack is missing for ${PLATFORM}." >&2; exit 2; }
[[ -f "${BUNDLE_ROOT}/tools/${PLATFORM}/quick/quick-pack-metadata.json" ]] \
  || { echo "Quick tool pack is missing for ${PLATFORM}." >&2; exit 2; }

mkdir -p "${RUN_ROOT}" "${LOG_ROOT}" "${DATA_ROOT}"
if [[ -f "${PID_FILE}" ]]; then
  EXISTING_PID="$(tr -dc '0-9' < "${PID_FILE}")"
  if [[ -n "${EXISTING_PID}" ]] && process_matches "${EXISTING_PID}"; then
    echo "Java Code Audit Platform is already running (pid=${EXISTING_PID})."
    exit 0
  fi
  mv "${PID_FILE}" "${PID_FILE}.stale.$(date +%s)"
fi

export AUDIT_DATA_ROOT="${DATA_ROOT}"
nohup "${BUNDLE_ROOT}/bin/run.sh" >"${SERVER_LOG}" 2>&1 &
STARTED_PID="$!"
printf '%s\n' "${STARTED_PID}" > "${PID_FILE}"

for _ in $(seq 1 240); do
  if ! process_matches "${STARTED_PID}"; then
    echo "Application exited before it became healthy. See ${SERVER_LOG}." >&2
    tail -n 120 "${SERVER_LOG}" >&2 || true
    exit 4
  fi
  if curl --fail --silent "http://127.0.0.1:${PORT}/api/v1/health" >/dev/null; then
    echo "Java Code Audit Platform started (pid=${STARTED_PID}, port=${PORT}, platform=${PLATFORM})."
    exit 0
  fi
  sleep 0.25
done

echo "Application did not become healthy before the 60 second timeout. See ${SERVER_LOG}." >&2
exit 4
