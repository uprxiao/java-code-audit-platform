#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEQL_VERSION="2.26.2"
QUERY_PACK_VERSION="1.11.7"
CODEQL_EXECUTABLE="${AUDIT_CODEQL_EXECUTABLE:-$REPOSITORY_ROOT/tools/local/codeql-v$CODEQL_VERSION/codeql/codeql}"
QUERY_SUITE="${AUDIT_CODEQL_QUERY_SUITE:-$REPOSITORY_ROOT/tools/local/codeql-packs/codeql/java-queries/$QUERY_PACK_VERSION/codeql-suites/java-security-and-quality.qls}"
MAVEN_EXECUTABLE="${AUDIT_MAVEN_EXECUTABLE:-$(command -v mvn || true)}"

[[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]] || {
  echo "JAVA_HOME must point to an installed JDK 17" >&2
  exit 2
}
[[ "$($JAVA_HOME/bin/java -version 2>&1 | head -n 1)" == *'17.'* ]] || {
  echo "CodeQL Deep smoke requires JDK 17" >&2
  exit 2
}
[[ -x "$MAVEN_EXECUTABLE" ]] || { echo "Server Maven executable is unavailable" >&2; exit 2; }
[[ -x "$CODEQL_EXECUTABLE" ]] || { echo "CodeQL CLI is unavailable: $CODEQL_EXECUTABLE" >&2; exit 2; }
[[ -f "$QUERY_SUITE" ]] || { echo "CodeQL query suite is unavailable: $QUERY_SUITE" >&2; exit 2; }

"$MAVEN_EXECUTABLE" -q -pl backend/scanner-adapters -am \
  -Dtest=CodeqlAdapterTest#realCodeqlDeepSmokeWhenInstallationIsProvided \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -Daudit.maven.executable="$MAVEN_EXECUTABLE" \
  -Daudit.codeql.executable="$CODEQL_EXECUTABLE" \
  -Daudit.codeql.querySuite="$QUERY_SUITE" \
  test

echo "CodeQL Deep smoke passed: CLI $CODEQL_VERSION, Java queries $QUERY_PACK_VERSION"
