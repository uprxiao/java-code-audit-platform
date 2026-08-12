#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_JAR="${AUDIT_APP_JAR:-${BUNDLE_ROOT}/app/audit-api.jar}"
DATA_ROOT="${AUDIT_DATA_ROOT:-${BUNDLE_ROOT}/data}"
PORT="${AUDIT_PORT:-8080}"

if [[ "${AUDIT_VERIFY_DISTRIBUTION:-true}" == "true" && -f "${BUNDLE_ROOT}/SHA256SUMS" ]]; then
  "${BUNDLE_ROOT}/bin/verify-distribution.sh"
fi

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

command -v java >/dev/null 2>&1 || { echo "JDK 17 is required." >&2; exit 2; }
command -v mvn >/dev/null 2>&1 || { echo "Maven 3.9+ is required." >&2; exit 2; }
JAVA_FEATURE="$(java -version 2>&1 | awk -F'[\".]' '/version/ {print $2; exit}')"
[[ "${JAVA_FEATURE}" == "17" ]] \
  || { echo "JDK 17 is required; found ${JAVA_FEATURE:-unknown}." >&2; exit 2; }
MAVEN_VERSION="$(mvn --version 2>/dev/null | awk 'NR==1 {print $3}')"
MAVEN_MAJOR="${MAVEN_VERSION%%.*}"
MAVEN_MINOR="${MAVEN_VERSION#*.}"
MAVEN_MINOR="${MAVEN_MINOR%%.*}"
if [[ ! "${MAVEN_MAJOR}" =~ ^[0-9]+$ || ! "${MAVEN_MINOR}" =~ ^[0-9]+$ ]] \
    || (( MAVEN_MAJOR < 3 || (MAVEN_MAJOR == 3 && MAVEN_MINOR < 9) )); then
  echo "Maven 3.9+ is required; found ${MAVEN_VERSION:-unknown}." >&2
  exit 2
fi

PLATFORM="$(platform_id)"
[[ -f "${APP_JAR}" ]] || { echo "Application JAR is missing: ${APP_JAR}" >&2; exit 2; }
export AUDIT_DATA_ROOT="${DATA_ROOT}"
export AUDIT_SEMGREP_EXECUTABLE="${AUDIT_SEMGREP_EXECUTABLE:-${BUNDLE_ROOT}/tools/${PLATFORM}/semgrep/semgrep/bin/semgrep}"
export AUDIT_QUICK_TOOL_ROOT="${AUDIT_QUICK_TOOL_ROOT:-${BUNDLE_ROOT}/tools/${PLATFORM}/quick}"
export AUDIT_STANDARD_ANALYSIS_ROOT="${AUDIT_STANDARD_ANALYSIS_ROOT:-${BUNDLE_ROOT}/tools/common/standard-analysis}"
export AUDIT_STANDARD_SUPPLY_ROOT="${AUDIT_STANDARD_SUPPLY_ROOT:-${BUNDLE_ROOT}/tools/${PLATFORM}/standard-supply}"
export AUDIT_VULNERABILITY_DATA_ROOT="${AUDIT_VULNERABILITY_DATA_ROOT:-${BUNDLE_ROOT}/data/databases}"
export AUDIT_CODEQL_EXECUTABLE="${AUDIT_CODEQL_EXECUTABLE:-${BUNDLE_ROOT}/tools/local/codeql-v2.26.2/codeql/codeql}"
export AUDIT_CODEQL_QUERY_ROOT="${AUDIT_CODEQL_QUERY_ROOT:-${BUNDLE_ROOT}/tools/local/codeql-packs}"
export AUDIT_CODEQL_QUERY_SUITE="${AUDIT_CODEQL_QUERY_SUITE:-${AUDIT_CODEQL_QUERY_ROOT}/codeql/java-queries/1.11.7/codeql-suites/java-security-and-quality.qls}"

exec java ${AUDIT_JAVA_OPTS:--Xms512m -Xmx4g -Djava.awt.headless=true} \
  -jar "${APP_JAR}" \
  --server.port="${PORT}" \
  --spring.config.additional-location="optional:file:${BUNDLE_ROOT}/config/application.yaml"
