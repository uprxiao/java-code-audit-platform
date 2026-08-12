#!/usr/bin/env bash
set -euo pipefail

DEPENDENCY_CHECK_VERSION="12.2.2"
OSV_VERSION="2.3.8"
CYCLONEDX_VERSION="2.9.3"
TARGET_PLATFORM="${1:-}"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) HOST_PLATFORM="darwin-arm64" ;;
  Linux-x86_64) HOST_PLATFORM="linux-x86_64" ;;
  *) echo "Unsupported build host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac
TARGET_PLATFORM="${TARGET_PLATFORM:-$HOST_PLATFORM}"
case "$TARGET_PLATFORM" in
  darwin-arm64)
    OSV_ASSET="osv-scanner_darwin_arm64"
    OSV_SHA="a8cd6507b06239f463a7642430cfd2d154882f150f6e30cdc0653e28dfc34216"
    ;;
  linux-x86_64)
    OSV_ASSET="osv-scanner_linux_amd64"
    OSV_SHA="bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc"
    ;;
  *) echo "Unsupported target platform: $TARGET_PLATFORM" >&2; exit 2 ;;
esac

DEPENDENCY_CHECK_ASSET="dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip"
DEPENDENCY_CHECK_ARCHIVE_SHA="bf07fefd81af3094c5f6850423b014df44db62ce2dbad0f79079a90df675e44a"
DEPENDENCY_CHECK_ENTRYPOINT_SHA="d683a49ec335eeca93d8707f3e8ce21d7ba63a1e619a325c6518f89c25efcdc4"
DEPENDENCY_CHECK_CORE_SHA="1ebe55e542b2f4d2727380395843922381447dc8b9a4f1633e77096f47ebfb48"

for command_name in curl unzip; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "$command_name is required" >&2; exit 2; }
done

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_ROOT="${AUDIT_TOOL_PACK_OUTPUT:-$REPOSITORY_ROOT/tools/downloads/tool-pack/$TARGET_PLATFORM/standard-supply}"
if [[ -e "$OUTPUT_ROOT" ]]; then
  echo "Refusing to overwrite existing tool pack: $OUTPUT_ROOT" >&2
  exit 2
fi
PARENT="$(dirname "$OUTPUT_ROOT")"
mkdir -p "$PARENT"
BUILD_ROOT="$(mktemp -d "$PARENT/.standard-supply-build.XXXXXX")"
PAYLOAD="$BUILD_ROOT/payload"
DOWNLOADS="$BUILD_ROOT/downloads"
cleanup() { rm -rf "$BUILD_ROOT"; }
trap cleanup EXIT
mkdir -p "$PAYLOAD/dependency-check" "$PAYLOAD/osv-scanner/bin" "$PAYLOAD/cyclonedx" "$DOWNLOADS"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
download() { curl -fL --retry 3 --retry-delay 2 -o "$2" "$1"; }
verify() {
  actual="$(sha256_file "$1")"
  [[ "$actual" == "$2" ]] || { echo "SHA256 mismatch for $1: $actual" >&2; exit 3; }
}

download "https://github.com/dependency-check/DependencyCheck/releases/download/v${DEPENDENCY_CHECK_VERSION}/${DEPENDENCY_CHECK_ASSET}" "$DOWNLOADS/$DEPENDENCY_CHECK_ASSET"
download "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/${OSV_ASSET}" "$PAYLOAD/osv-scanner/bin/osv-scanner.real"
download "https://raw.githubusercontent.com/google/osv-scanner/v${OSV_VERSION}/LICENSE" "$PAYLOAD/osv-scanner/LICENSE"
verify "$DOWNLOADS/$DEPENDENCY_CHECK_ASSET" "$DEPENDENCY_CHECK_ARCHIVE_SHA"
verify "$PAYLOAD/osv-scanner/bin/osv-scanner.real" "$OSV_SHA"
cp "$REPOSITORY_ROOT/scripts/tool-wrappers/osv-scanner-audit" "$PAYLOAD/osv-scanner/bin/osv-scanner"

unzip -q "$DOWNLOADS/$DEPENDENCY_CHECK_ASSET" -d "$PAYLOAD/dependency-check"
verify "$PAYLOAD/dependency-check/dependency-check/bin/dependency-check.sh" "$DEPENDENCY_CHECK_ENTRYPOINT_SHA"
verify "$PAYLOAD/dependency-check/dependency-check/lib/dependency-check-core-${DEPENDENCY_CHECK_VERSION}.jar" "$DEPENDENCY_CHECK_CORE_SHA"
chmod +x "$PAYLOAD/dependency-check/dependency-check/bin/dependency-check.sh" \
  "$PAYLOAD/osv-scanner/bin/osv-scanner" "$PAYLOAD/osv-scanner/bin/osv-scanner.real"
OSV_WRAPPER_SHA="$(sha256_file "$PAYLOAD/osv-scanner/bin/osv-scanner")"

NATIVE_VALIDATED=false
if [[ "$TARGET_PLATFORM" == "$HOST_PLATFORM" ]]; then
  [[ "$($PAYLOAD/osv-scanner/bin/osv-scanner --version | awk '/osv-scanner version:/ {print $3}')" == "$OSV_VERSION" ]]
  NATIVE_VALIDATED=true
fi
if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then
  [[ "$($PAYLOAD/dependency-check/dependency-check/bin/dependency-check.sh --version | awk '{print $NF}')" == "$DEPENDENCY_CHECK_VERSION" ]]
fi

cat > "$PAYLOAD/dependency-check/pack-metadata.json" <<EOF
{"schemaVersion":1,"id":"dependency-check","version":"$DEPENDENCY_CHECK_VERSION","platform":"common-java","launchMode":"script-with-jdk17","entrypoint":"dependency-check/bin/dependency-check.sh","entrypointSha256":"$DEPENDENCY_CHECK_ENTRYPOINT_SHA","coreJarSha256":"$DEPENDENCY_CHECK_CORE_SHA","source":"https://github.com/dependency-check/DependencyCheck/releases/tag/v$DEPENDENCY_CHECK_VERSION","sourceArchive":"$DEPENDENCY_CHECK_ASSET","sourceArchiveSha256":"$DEPENDENCY_CHECK_ARCHIVE_SHA","license":"Apache-2.0","dynamicDatabaseBundled":false}
EOF
cat > "$PAYLOAD/osv-scanner/pack-metadata.json" <<EOF
{"schemaVersion":1,"id":"osv-scanner","version":"$OSV_VERSION","platform":"$TARGET_PLATFORM","launchMode":"controlled-exit-code-wrapper","entrypoint":"bin/osv-scanner","entrypointSha256":"$OSV_WRAPPER_SHA","upstreamBinary":"bin/osv-scanner.real","upstreamBinarySha256":"$OSV_SHA","acceptedUpstreamExitCodes":[0,1],"source":"https://github.com/google/osv-scanner/releases/tag/v$OSV_VERSION","sourceAsset":"$OSV_ASSET","license":"Apache-2.0","nativeValidated":$NATIVE_VALIDATED,"onlineDataSource":"https://api.osv.dev"}
EOF
cat > "$PAYLOAD/cyclonedx/pack-metadata.json" <<EOF
{"schemaVersion":1,"id":"cyclonedx","version":"$CYCLONEDX_VERSION","distribution":"maven-plugin","coordinate":"org.cyclonedx:cyclonedx-maven-plugin:$CYCLONEDX_VERSION","artifactSha256":"c452d5eebe28bc86bef2e7c72d129f04f60877bef843eac8120f01fb655be293","source":"https://github.com/CycloneDX/cyclonedx-maven-plugin/releases/tag/cyclonedx-maven-plugin-$CYCLONEDX_VERSION","license":"Apache-2.0","bundled":false}
EOF
cat > "$PAYLOAD/standard-supply-pack-metadata.json" <<EOF
{"schemaVersion":1,"platform":"$TARGET_PLATFORM","layoutVersion":1,"tools":["dependency-check","osv-scanner","cyclonedx"],"reusedTools":["quick/trivy"],"nativeValidated":$NATIVE_VALIDATED,"vulnerabilityDatabasesBundled":false}
EOF

mv "$PAYLOAD" "$OUTPUT_ROOT"
echo "Standard supply tool pack ready: $OUTPUT_ROOT"
du -sh "$OUTPUT_ROOT"
