#!/usr/bin/env bash
set -euo pipefail

GITLEAKS_VERSION="8.30.1"
PMD_VERSION="7.26.0"
CHECKSTYLE_VERSION="12.3.1"
TRIVY_VERSION="0.73.0"
TARGET_PLATFORM="${1:-}"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) HOST_PLATFORM="darwin-arm64" ;;
  Linux-x86_64) HOST_PLATFORM="linux-x86_64" ;;
  *) echo "Unsupported build host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac
TARGET_PLATFORM="${TARGET_PLATFORM:-$HOST_PLATFORM}"
case "$TARGET_PLATFORM" in
  darwin-arm64)
    GITLEAKS_ASSET="gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz"
    GITLEAKS_ARCHIVE_SHA="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
    TRIVY_ASSET="trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz"
    TRIVY_ARCHIVE_SHA="80cc25faaf6378e37701202d0b4f9f43d9e413d198d594ba60fdf559fe44a683"
    ;;
  linux-x86_64)
    GITLEAKS_ASSET="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    GITLEAKS_ARCHIVE_SHA="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    TRIVY_ASSET="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
    TRIVY_ARCHIVE_SHA="2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b"
    ;;
  *) echo "Unsupported target platform: $TARGET_PLATFORM" >&2; exit 2 ;;
esac

PMD_ASSET="pmd-dist-${PMD_VERSION}-bin.zip"
PMD_ARCHIVE_SHA="9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9"
CHECKSTYLE_ASSET="checkstyle-${CHECKSTYLE_VERSION}-all.jar"
CHECKSTYLE_ARCHIVE_SHA="4ecdfa8504452e1557d2e2c364085f0ae5703b67ec9c759976ca378d41cb8f7a"

for command_name in curl tar unzip; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "$command_name is required" >&2; exit 2; }
done

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_ROOT="${AUDIT_TOOL_PACK_OUTPUT:-$REPOSITORY_ROOT/tools/downloads/tool-pack/$TARGET_PLATFORM/quick}"
if [[ -e "$OUTPUT_ROOT" ]]; then
  echo "Refusing to overwrite existing tool pack: $OUTPUT_ROOT" >&2
  exit 2
fi
PARENT="$(dirname "$OUTPUT_ROOT")"
mkdir -p "$PARENT"
BUILD_ROOT="$(mktemp -d "$PARENT/.quick-tools-build.XXXXXX")"
PAYLOAD="$BUILD_ROOT/payload"
DOWNLOADS="$BUILD_ROOT/downloads"
cleanup() { rm -rf "$BUILD_ROOT"; }
trap cleanup EXIT
mkdir -p "$PAYLOAD" "$DOWNLOADS"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
download() { curl -fL --retry 3 --retry-delay 2 -o "$2" "$1"; }
verify() {
  actual="$(sha256_file "$1")"
  [[ "$actual" == "$2" ]] || { echo "SHA256 mismatch for $1: $actual" >&2; exit 3; }
}

download "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${GITLEAKS_ASSET}" "$DOWNLOADS/$GITLEAKS_ASSET"
download "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${PMD_VERSION}/${PMD_ASSET}" "$DOWNLOADS/$PMD_ASSET"
download "https://github.com/checkstyle/checkstyle/releases/download/checkstyle-${CHECKSTYLE_VERSION}/${CHECKSTYLE_ASSET}" "$DOWNLOADS/$CHECKSTYLE_ASSET"
download "https://raw.githubusercontent.com/checkstyle/checkstyle/checkstyle-${CHECKSTYLE_VERSION}/LICENSE" "$DOWNLOADS/CHECKSTYLE-LICENSE"
download "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_ASSET}" "$DOWNLOADS/$TRIVY_ASSET"

verify "$DOWNLOADS/$GITLEAKS_ASSET" "$GITLEAKS_ARCHIVE_SHA"
verify "$DOWNLOADS/$PMD_ASSET" "$PMD_ARCHIVE_SHA"
verify "$DOWNLOADS/$CHECKSTYLE_ASSET" "$CHECKSTYLE_ARCHIVE_SHA"
verify "$DOWNLOADS/$TRIVY_ASSET" "$TRIVY_ARCHIVE_SHA"

mkdir -p "$PAYLOAD/gitleaks/bin" "$PAYLOAD/pmd" "$PAYLOAD/checkstyle" "$PAYLOAD/trivy/bin"
tar -xzf "$DOWNLOADS/$GITLEAKS_ASSET" -C "$PAYLOAD/gitleaks" LICENSE README.md gitleaks
mv "$PAYLOAD/gitleaks/gitleaks" "$PAYLOAD/gitleaks/bin/gitleaks"
unzip -q "$DOWNLOADS/$PMD_ASSET" -d "$PAYLOAD/pmd"
mv "$PAYLOAD/pmd/pmd-bin-${PMD_VERSION}" "$PAYLOAD/pmd/home"
cp "$DOWNLOADS/$CHECKSTYLE_ASSET" "$PAYLOAD/checkstyle/$CHECKSTYLE_ASSET"
cp "$DOWNLOADS/CHECKSTYLE-LICENSE" "$PAYLOAD/checkstyle/LICENSE"
tar -xzf "$DOWNLOADS/$TRIVY_ASSET" -C "$PAYLOAD/trivy" LICENSE README.md trivy
mv "$PAYLOAD/trivy/trivy" "$PAYLOAD/trivy/bin/trivy"
chmod +x "$PAYLOAD/gitleaks/bin/gitleaks" "$PAYLOAD/trivy/bin/trivy"

GITLEAKS_SHA="$(sha256_file "$PAYLOAD/gitleaks/bin/gitleaks")"
PMD_ENTRYPOINT="home/lib/pmd-cli-${PMD_VERSION}.jar"
PMD_SHA="$(sha256_file "$PAYLOAD/pmd/$PMD_ENTRYPOINT")"
CHECKSTYLE_SHA="$(sha256_file "$PAYLOAD/checkstyle/$CHECKSTYLE_ASSET")"
TRIVY_SHA="$(sha256_file "$PAYLOAD/trivy/bin/trivy")"
NATIVE_VALIDATED=false
if [[ "$TARGET_PLATFORM" == "$HOST_PLATFORM" ]]; then
  [[ "$($PAYLOAD/gitleaks/bin/gitleaks version)" == "$GITLEAKS_VERSION" ]]
  [[ "$($PAYLOAD/trivy/bin/trivy --version | awk '/^Version:/ {print $2}')" == "$TRIVY_VERSION" ]]
  NATIVE_VALIDATED=true
fi
if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then JAVA="$JAVA_HOME/bin/java"; else JAVA="$(command -v java || true)"; fi
if [[ -n "$JAVA" ]]; then
  "$JAVA" -cp "$PAYLOAD/pmd/home/lib/*" net.sourceforge.pmd.cli.PmdCli --version | grep -q "PMD $PMD_VERSION"
  "$JAVA" -jar "$PAYLOAD/checkstyle/$CHECKSTYLE_ASSET" --version | grep -q "$CHECKSTYLE_VERSION"
fi

cat > "$PAYLOAD/gitleaks/pack-metadata.json" <<EOF
{"schemaVersion":1,"id":"gitleaks","version":"$GITLEAKS_VERSION","platform":"$TARGET_PLATFORM","launchMode":"native","entrypoint":"bin/gitleaks","entrypointSha256":"$GITLEAKS_SHA","source":"https://github.com/gitleaks/gitleaks/releases/tag/v$GITLEAKS_VERSION","sourceArchive":"$GITLEAKS_ASSET","sourceArchiveSha256":"$GITLEAKS_ARCHIVE_SHA","license":"MIT","nativeValidated":$NATIVE_VALIDATED}
EOF
cat > "$PAYLOAD/pmd/pack-metadata.json" <<EOF
{"schemaVersion":1,"id":"pmd","version":"$PMD_VERSION","platform":"common-java","launchMode":"java-classpath","entrypoint":"$PMD_ENTRYPOINT","mainClass":"net.sourceforge.pmd.cli.PmdCli","entrypointSha256":"$PMD_SHA","source":"https://github.com/pmd/pmd/releases/tag/pmd_releases%2F$PMD_VERSION","sourceArchive":"$PMD_ASSET","sourceArchiveSha256":"$PMD_ARCHIVE_SHA","license":"LicenseRef-PMD-BSD-Style"}
EOF
cat > "$PAYLOAD/checkstyle/pack-metadata.json" <<EOF
{"schemaVersion":1,"id":"checkstyle","version":"$CHECKSTYLE_VERSION","platform":"common-java","launchMode":"java-jar","entrypoint":"$CHECKSTYLE_ASSET","entrypointSha256":"$CHECKSTYLE_SHA","source":"https://github.com/checkstyle/checkstyle/releases/tag/checkstyle-$CHECKSTYLE_VERSION","sourceArchive":"$CHECKSTYLE_ASSET","sourceArchiveSha256":"$CHECKSTYLE_ARCHIVE_SHA","license":"LGPL-2.1-or-later"}
EOF
cat > "$PAYLOAD/trivy/pack-metadata.json" <<EOF
{"schemaVersion":1,"id":"trivy","version":"$TRIVY_VERSION","platform":"$TARGET_PLATFORM","launchMode":"native","entrypoint":"bin/trivy","entrypointSha256":"$TRIVY_SHA","source":"https://github.com/aquasecurity/trivy/releases/tag/v$TRIVY_VERSION","sourceArchive":"$TRIVY_ASSET","sourceArchiveSha256":"$TRIVY_ARCHIVE_SHA","license":"Apache-2.0","nativeValidated":$NATIVE_VALIDATED,"dynamicDataBundled":false}
EOF
cat > "$PAYLOAD/quick-pack-metadata.json" <<EOF
{"schemaVersion":1,"platform":"$TARGET_PLATFORM","layoutVersion":1,"tools":["gitleaks","pmd","checkstyle","trivy"],"nativeValidated":$NATIVE_VALIDATED,"vulnerabilityDatabasesBundled":false}
EOF

mv "$PAYLOAD" "$OUTPUT_ROOT"
echo "Quick tool pack ready: $OUTPUT_ROOT"
du -sh "$OUTPUT_ROOT"
