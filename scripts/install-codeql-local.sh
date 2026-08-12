#!/usr/bin/env bash
set -euo pipefail

VERSION="2.26.2"
JAVA_PACK_VERSION="1.11.7"
REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    ASSET="codeql-osx64.zip"
    EXPECTED_SHA="c363637c914ef2dd6b0f5dddaffe7d70029787c0af52ea657a373788bb14c8a6"
    ;;
  Linux-x86_64)
    ASSET="codeql-linux64.zip"
    EXPECTED_SHA="f2a7f47f049b9de51977c02c7900b6e2af7587b50aef530a68975a97b136dfd4"
    ;;
  *) echo "Unsupported CodeQL host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

INSTALL_ROOT="${AUDIT_CODEQL_INSTALL_ROOT:-$REPOSITORY_ROOT/tools/local/codeql-v$VERSION}"
DOWNLOAD_ROOT="${AUDIT_CODEQL_DOWNLOAD_ROOT:-$REPOSITORY_ROOT/tools/local/downloads}"
PACK_ROOT="${AUDIT_CODEQL_PACK_ROOT:-$REPOSITORY_ROOT/tools/local/codeql-packs}"
ARCHIVE="$DOWNLOAD_ROOT/$ASSET"
if [[ -e "$INSTALL_ROOT" ]]; then
  echo "Refusing to overwrite CodeQL installation: $INSTALL_ROOT" >&2
  exit 2
fi
mkdir -p "$DOWNLOAD_ROOT" "$(dirname "$INSTALL_ROOT")" "$PACK_ROOT"
curl -fL --retry 3 --retry-delay 2 \
  -o "$ARCHIVE" "https://github.com/github/codeql-cli-binaries/releases/download/v$VERSION/$ASSET"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
else
  ACTUAL_SHA="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
fi
[[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] || { echo "CodeQL archive SHA256 mismatch" >&2; exit 3; }

TEMPORARY="$(mktemp -d "$(dirname "$INSTALL_ROOT")/.codeql-install.XXXXXX")"
cleanup() { rm -rf "$TEMPORARY"; }
trap cleanup EXIT
unzip -q "$ARCHIVE" -d "$TEMPORARY"
mkdir "$INSTALL_ROOT"
mv "$TEMPORARY/codeql" "$INSTALL_ROOT/codeql"
CODEQL_EXECUTABLE="$INSTALL_ROOT/codeql/codeql"
[[ -x "$CODEQL_EXECUTABLE" ]] || {
  echo "CodeQL archive did not contain the expected codeql/codeql entrypoint" >&2
  exit 3
}
"$CODEQL_EXECUTABLE" version --format=json | grep -q '"version" : "2.26.2"'
"$INSTALL_ROOT/codeql" pack download "codeql/java-queries@$JAVA_PACK_VERSION" --dir "$PACK_ROOT"

echo "CodeQL local installation ready: $INSTALL_ROOT"
echo "Query packs: $PACK_ROOT"
echo "Review tools/manifest/codeql-local.yaml and the current GitHub CodeQL Terms before enabling Deep."
