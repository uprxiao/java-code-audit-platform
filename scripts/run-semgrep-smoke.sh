#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLATFORM="darwin-arm64" ;;
  Linux-x86_64) PLATFORM="linux-x86_64" ;;
  *) echo "Unsupported smoke host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

SEMGREP_EXECUTABLE="${AUDIT_SEMGREP_EXECUTABLE:-$REPOSITORY_ROOT/tools/downloads/tool-pack/$PLATFORM/semgrep/semgrep/bin/semgrep}"
SEMGREP_RULES="${AUDIT_SEMGREP_RULES:-$REPOSITORY_ROOT/config/rules/semgrep/java-audit.yaml}"
if [[ ! -x "$SEMGREP_EXECUTABLE" ]]; then
  echo "Semgrep executable is missing: $SEMGREP_EXECUTABLE" >&2
  exit 2
fi

JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 17 2>/dev/null || true)}" \
  "$REPOSITORY_ROOT/mvnw" -B -pl backend/audit-api -am \
  -Dtest=SemgrepAdapterTest,SemgrepZipApiE2ETest \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -Daudit.semgrep.executable="$SEMGREP_EXECUTABLE" \
  -Daudit.semgrep.rules="$SEMGREP_RULES" \
  test
