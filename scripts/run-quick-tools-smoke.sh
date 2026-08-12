#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLATFORM="darwin-arm64" ;;
  Linux-x86_64) PLATFORM="linux-x86_64" ;;
  *) echo "Unsupported smoke host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac
QUICK_ROOT="${1:-${AUDIT_QUICK_TOOL_PACK_ROOT:-$REPOSITORY_ROOT/tools/downloads/tool-pack/$PLATFORM/quick}}"
JAVA_EXECUTABLE="${JAVA_HOME:+$JAVA_HOME/bin/java}"
JAVA_EXECUTABLE="${JAVA_EXECUTABLE:-$(command -v java)}"

required=(
  "$QUICK_ROOT/gitleaks/bin/gitleaks"
  "$QUICK_ROOT/pmd/home/lib/pmd-cli-7.26.0.jar"
  "$QUICK_ROOT/checkstyle/checkstyle-12.3.1-all.jar"
  "$QUICK_ROOT/trivy/bin/trivy"
)
for file in "${required[@]}"; do [[ -e "$file" ]] || { echo "Missing Quick tool: $file" >&2; exit 2; }; done

"$REPOSITORY_ROOT/mvnw" -q -pl backend/scanner-adapters -am \
  -Dtest=GitleaksAdapterTest,PmdAdapterTest,PmdCpdAdapterTest,CheckstyleAdapterTest,TrivyRepositoryAdapterTest \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -Daudit.gitleaks.executable="$QUICK_ROOT/gitleaks/bin/gitleaks" \
  -Daudit.gitleaks.rules="$REPOSITORY_ROOT/config/rules/gitleaks/gitleaks.toml" \
  -Daudit.pmd.home="$QUICK_ROOT/pmd/home" \
  -Daudit.pmd.java="$JAVA_EXECUTABLE" \
  -Daudit.pmd.rules="$REPOSITORY_ROOT/config/rules/pmd/java-audit.xml" \
  -Daudit.checkstyle.jar="$QUICK_ROOT/checkstyle/checkstyle-12.3.1-all.jar" \
  -Daudit.checkstyle.java="$JAVA_EXECUTABLE" \
  -Daudit.checkstyle.rules="$REPOSITORY_ROOT/config/rules/checkstyle/java-audit.xml" \
  -Daudit.trivy.executable="$QUICK_ROOT/trivy/bin/trivy" \
  test
