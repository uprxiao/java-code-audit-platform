#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@17}"
MAVEN_EXECUTABLE="${AUDIT_MAVEN_EXECUTABLE:-$(command -v mvn)}"

export JAVA_HOME
"${REPOSITORY_ROOT}/scripts/build-standard-analysis-pack.sh"

PACK_ROOT="${REPOSITORY_ROOT}/tools/downloads/tool-pack/common/standard-analysis"
"${REPOSITORY_ROOT}/mvnw" -q -pl backend/scanner-adapters -am \
  -Dtest=SpotBugsAdapterTest,FindSecBugsAdapterTest,MavenAuditAdapterTest \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -Daudit.spotbugs.home="${PACK_ROOT}/spotbugs" \
  -Daudit.findsecbugs.plugin="${PACK_ROOT}/findsecbugs/lib/findsecbugs-plugin-1.14.0.jar" \
  -Daudit.spotbugs.exclude="${REPOSITORY_ROOT}/config/rules/spotbugs-exclude.xml" \
  -Daudit.standard.maven="${MAVEN_EXECUTABLE}" \
  test

echo "SpotBugs, FindSecBugs, Maven Dependency Analysis and Maven Enforcer real smoke passed."
