#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${AUDIT_BASE_URL:-http://127.0.0.1:${AUDIT_PORT:-8080}}"
PROFILE="QUICK"
TIMEOUT_SECONDS="${AUDIT_ACCEPTANCE_TIMEOUT_SECONDS:-7200}"

usage() {
  echo "Usage: $0 [--quick|--standard|--deep] [--base-url URL]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) PROFILE="QUICK" ;;
    --standard) PROFILE="STANDARD" ;;
    --deep) PROFILE="DEEP" ;;
    --base-url)
      shift
      [[ $# -gt 0 ]] || { usage; exit 2; }
      BASE_URL="$1"
      ;;
    *) usage; exit 2 ;;
  esac
  shift
done

for command_name in curl unzip grep sed; do
  command -v "${command_name}" >/dev/null 2>&1 \
    || { echo "Required acceptance command is missing: ${command_name}" >&2; exit 2; }
done
FIXTURE="${BUNDLE_ROOT}/acceptance/java17-acceptance-fixture.zip"
[[ -f "${FIXTURE}" ]] || { echo "Acceptance fixture is missing: ${FIXTURE}" >&2; exit 2; }

WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/java-audit-acceptance.XXXXXX")"
cleanup() { rm -rf "${WORK_ROOT}"; }
trap cleanup EXIT

curl --fail --silent --show-error "${BASE_URL}/api/v1/health" > "${WORK_ROOT}/health.json"
REQUEST="{\"displayName\":\"v1-acceptance\",\"profile\":\"${PROFILE}\",\"mavenProfiles\":[],\"mavenProperties\":{}}"
curl --fail --silent --show-error \
  -F "source=@${FIXTURE};type=application/zip" \
  -F "request=${REQUEST};type=application/json" \
  "${BASE_URL}/api/v1/scans/zip" > "${WORK_ROOT}/create.json"
SCAN_ID="$(sed -n 's/.*\"scanId\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p' "${WORK_ROOT}/create.json")"
[[ "${SCAN_ID}" =~ ^[0-9a-fA-F-]{36}$ ]] \
  || { echo "Could not parse scanId from create response." >&2; cat "${WORK_ROOT}/create.json" >&2; exit 4; }

DEADLINE=$(( $(date +%s) + TIMEOUT_SECONDS ))
while (( $(date +%s) < DEADLINE )); do
  curl --fail --silent --show-error "${BASE_URL}/api/v1/scans/${SCAN_ID}" > "${WORK_ROOT}/scan.json"
  STATUS="$(sed -n 's/.*\"status\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p' "${WORK_ROOT}/scan.json")"
  case "${STATUS}" in
    COMPLETED) break ;;
    COMPLETED_WITH_ERRORS|FAILED|CANCELLED|INTERRUPTED)
      echo "${PROFILE} acceptance scan ended in ${STATUS}." >&2
      cat "${WORK_ROOT}/scan.json" >&2
      exit 5
      ;;
  esac
  sleep 1
done
[[ "${STATUS:-}" == "COMPLETED" ]] \
  || { echo "${PROFILE} acceptance scan timed out after ${TIMEOUT_SECONDS}s." >&2; exit 6; }

curl --fail --silent --show-error \
  "${BASE_URL}/api/v1/scans/${SCAN_ID}/reports/archive" \
  -o "${WORK_ROOT}/report.zip"
unzip -tq "${WORK_ROOT}/report.zip" >/dev/null
unzip -qq "${WORK_ROOT}/report.zip" -d "${WORK_ROOT}/report"
for expected in report.html report.json report.sarif coverage.json manifest.json; do
  [[ -f "${WORK_ROOT}/report/${expected}" ]] \
    || { echo "Report archive is missing ${expected}." >&2; exit 7; }
done
if grep -R -F -q 'AUDIT_CANARY_SECRET_V1_RELEASE_FIXTURE' "${WORK_ROOT}/report"; then
  echo "Acceptance canary leaked into the report archive." >&2
  exit 8
fi
if unzip -Z1 "${WORK_ROOT}/report.zip" | grep -E '(^|/)(workspace|source|target|codeql-db|repository)(/|$)' >/dev/null; then
  echo "Report archive contains a forbidden source/build/cache directory." >&2
  exit 9
fi

echo "${PROFILE} acceptance passed: scanId=${SCAN_ID}, archive verified, canary absent."
