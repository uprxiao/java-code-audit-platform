#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAR_PATH="${1:-$REPOSITORY_ROOT/backend/audit-api/target/audit-api-0.1.0-SNAPSHOT.jar}"
SEMGREP_EXECUTABLE="${AUDIT_SEMGREP_EXECUTABLE:-$REPOSITORY_ROOT/tools/downloads/bin/semgrep}"
QUICK_TOOL_ROOT="${AUDIT_QUICK_TOOL_ROOT:-$REPOSITORY_ROOT/tools/downloads/tool-pack/$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)/quick}"
SMOKE_PORT="${AUDIT_SMOKE_PORT:-18080}"

if [[ ! -f "$JAR_PATH" ]]; then
  echo "Executable JAR is missing: $JAR_PATH" >&2
  exit 2
fi
if [[ ! -x "$SEMGREP_EXECUTABLE" ]]; then
  echo "Semgrep executable is missing: $SEMGREP_EXECUTABLE" >&2
  exit 2
fi
if [[ ! -f "$QUICK_TOOL_ROOT/quick-pack-metadata.json" ]]; then
  echo "Quick tool pack is missing: $QUICK_TOOL_ROOT" >&2
  exit 2
fi
if ! command -v java >/dev/null 2>&1 || ! command -v javap >/dev/null 2>&1 \
    || ! command -v unzip >/dev/null 2>&1; then
  echo "JDK 17 java/javap and unzip are required." >&2
  exit 2
fi

SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/java-audit-startup.XXXXXX")"
SERVER_LOG="$SMOKE_ROOT/server.log"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$SMOKE_ROOT"
}
trap cleanup EXIT

JAVA_FEATURE="$(java -version 2>&1 | awk -F'[\".]' '/version/ {print $2; exit}')"
if [[ "$JAVA_FEATURE" != "17" ]]; then
  echo "JDK 17 is required, found feature version: $JAVA_FEATURE" >&2
  exit 2
fi

unzip -qq "$JAR_PATH" 'BOOT-INF/classes/io/github/uprxiao/audit/api/AuditApplication.class' \
  -d "$SMOKE_ROOT/classes"
CLASS_MAJOR="$(javap -verbose \
  "$SMOKE_ROOT/classes/BOOT-INF/classes/io/github/uprxiao/audit/api/AuditApplication.class" \
  | awk '/major version:/ {print $3; exit}')"
if [[ "$CLASS_MAJOR" != "61" ]]; then
  echo "Expected Java 17 class major 61, found: $CLASS_MAJOR" >&2
  exit 3
fi

java -jar "$JAR_PATH" \
  --server.port="$SMOKE_PORT" \
  --audit.data-root="$SMOKE_ROOT/data" \
  --audit.storage.minimum-free-bytes=1 \
  --audit.tools.semgrep-executable="$SEMGREP_EXECUTABLE" \
  --audit.tools.quick-root="$QUICK_TOOL_ROOT" \
  --audit.rules.semgrep="$REPOSITORY_ROOT/config/rules/semgrep/java-audit.yaml" \
  --audit.rules.gitleaks="$REPOSITORY_ROOT/config/rules/gitleaks/gitleaks.toml" \
  --audit.rules.pmd="$REPOSITORY_ROOT/config/rules/pmd/java-audit.xml" \
  --audit.rules.checkstyle="$REPOSITORY_ROOT/config/rules/checkstyle/java-audit.xml" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

for _ in $(seq 1 120); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Application exited before becoming healthy." >&2
    sed -n '1,240p' "$SERVER_LOG" >&2
    exit 4
  fi
  if curl --fail --silent "http://127.0.0.1:$SMOKE_PORT/api/v1/health" \
      | grep -q '"startup"'; then
    echo "Executable JAR startup smoke passed on $(uname -s)-$(uname -m), class major=$CLASS_MAJOR."
    exit 0
  fi
  sleep 0.25
done

echo "Application did not become healthy before the smoke timeout." >&2
sed -n '1,240p' "$SERVER_LOG" >&2
exit 4
