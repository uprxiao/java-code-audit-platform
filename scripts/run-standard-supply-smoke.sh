#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLATFORM="darwin-arm64" ;;
  Linux-x86_64) PLATFORM="linux-x86_64" ;;
  *) echo "Unsupported smoke host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

MAVEN_EXECUTABLE="${AUDIT_MAVEN_EXECUTABLE:-$(command -v mvn || true)}"
OSV_EXECUTABLE="${AUDIT_OSV_EXECUTABLE:-$REPOSITORY_ROOT/tools/downloads/tool-pack/$PLATFORM/standard/osv-scanner/bin/osv-scanner}"
DEPENDENCY_CHECK_EXECUTABLE="${AUDIT_DEPENDENCY_CHECK_EXECUTABLE:-$REPOSITORY_ROOT/tools/downloads/tool-pack/$PLATFORM/standard/dependency-check/dependency-check/bin/dependency-check.sh}"
TRIVY_EXECUTABLE="${AUDIT_TRIVY_EXECUTABLE:-$REPOSITORY_ROOT/tools/downloads/tool-pack/$PLATFORM/quick/trivy/bin/trivy}"
TRIVY_CACHE="${AUDIT_TRIVY_CACHE:-$REPOSITORY_ROOT/tools/downloads/databases/trivy}"
DEPENDENCY_CHECK_DATA="${AUDIT_DEPENDENCY_CHECK_DATA:-}"

[[ "$(java -XshowSettings:properties -version 2>&1 | awk '/java.specification.version =/ {print $3}')" == "17" ]] || {
  echo "JDK 17 is required" >&2; exit 2;
}
for executable in "$MAVEN_EXECUTABLE" "$OSV_EXECUTABLE" "$DEPENDENCY_CHECK_EXECUTABLE" "$TRIVY_EXECUTABLE"; do
  [[ -x "$executable" ]] || { echo "Executable unavailable: $executable" >&2; exit 2; }
done
[[ -s "$TRIVY_CACHE/db/metadata.json" && -s "$TRIVY_CACHE/db/trivy.db" \
  && -s "$TRIVY_CACHE/java-db/metadata.json" && -s "$TRIVY_CACHE/java-db/trivy-java.db" ]] || {
  echo "Trivy vulnerability or Java DB unavailable: $TRIVY_CACHE" >&2; exit 2;
}

"$DEPENDENCY_CHECK_EXECUTABLE" --version | grep -q '12.2.2'
"$OSV_EXECUTABLE" --version | grep -q '2.3.8'
"$TRIVY_EXECUTABLE" --version | grep -q '0.73.0'

cd "$REPOSITORY_ROOT"
./mvnw -q -pl backend/scanner-adapters -am \
  -Dtest='CycloneDxAdapterTest#realMacJdk17MavenSmokeWhenExecutableIsProvided,OsvScannerAdapterTest#realMacSmokeWhenExecutableIsProvided,TrivyArtifactAdapterTest#realMacSmokeWhenExecutableAndDatabaseAreProvided' \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -Daudit.maven.executable="$MAVEN_EXECUTABLE" \
  -Daudit.osv.executable="$OSV_EXECUTABLE" \
  -Daudit.trivy.executable="$TRIVY_EXECUTABLE" \
  -Daudit.trivy.cache="$TRIVY_CACHE" test

if [[ -n "$DEPENDENCY_CHECK_DATA" ]]; then
  find "$DEPENDENCY_CHECK_DATA" -maxdepth 1 -type f -name 'odc*.mv.db' -size +0c | grep -q . || {
    echo "Dependency-Check DB unavailable: $DEPENDENCY_CHECK_DATA" >&2; exit 2;
  }
  ./mvnw -q -pl backend/scanner-adapters -am \
    -Dtest='DependencyCheckAdapterTest#realMacJdk17FindingSmokeWhenExecutableAndDatabaseAreProvided' \
    -Dsurefire.failIfNoSpecifiedTests=false \
    -Daudit.dependency-check.executable="$DEPENDENCY_CHECK_EXECUTABLE" \
    -Daudit.dependency-check.data="$DEPENDENCY_CHECK_DATA" test
fi

echo "Standard supply real smoke passed on $PLATFORM with JDK 17."
if [[ -z "$DEPENDENCY_CHECK_DATA" ]]; then
  echo "Dependency-Check CLI was executed for version/runtime validation; a full finding smoke additionally requires an initialized AUDIT_DEPENDENCY_CHECK_DATA database."
fi
