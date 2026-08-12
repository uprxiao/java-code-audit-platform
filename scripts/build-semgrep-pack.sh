#!/usr/bin/env bash
set -euo pipefail

SEMGREP_VERSION="1.170.0"
PYTHON_VERSION="3.14.2"
UV_MIN_VERSION="0.10.4"
REQUESTED_PLATFORM="${1:-}"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) HOST_PLATFORM="darwin-arm64" ;;
  Linux-x86_64) HOST_PLATFORM="linux-x86_64" ;;
  *) echo "Unsupported build host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

if [[ -n "$REQUESTED_PLATFORM" && "$REQUESTED_PLATFORM" != "$HOST_PLATFORM" ]]; then
  echo "Semgrep packs must be assembled natively: requested=$REQUESTED_PLATFORM host=$HOST_PLATFORM" >&2
  exit 2
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "uv >= $UV_MIN_VERSION is required only while assembling the tool pack." >&2
  exit 2
fi

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_ROOT="${AUDIT_TOOL_PACK_OUTPUT:-$REPOSITORY_ROOT/tools/downloads/tool-pack/$HOST_PLATFORM/semgrep}"
if [[ -e "$OUTPUT_ROOT" ]]; then
  echo "Refusing to overwrite existing tool pack: $OUTPUT_ROOT" >&2
  echo "Move it aside or set AUDIT_TOOL_PACK_OUTPUT to a new path." >&2
  exit 2
fi

PARENT="$(dirname "$OUTPUT_ROOT")"
mkdir -p "$PARENT"
BUILD_ROOT="$(mktemp -d "$PARENT/.semgrep-build.XXXXXX")"
PAYLOAD="$BUILD_ROOT/payload"
cleanup() { rm -rf "$BUILD_ROOT"; }
trap cleanup EXIT
mkdir -p "$PAYLOAD"

uv python install --install-dir "$PAYLOAD/python" --no-bin "$PYTHON_VERSION"
PYTHON_EXECUTABLE="$(find "$PAYLOAD/python" -type f -path '*/bin/python3.14' | head -n 1)"
if [[ -z "$PYTHON_EXECUTABLE" ]]; then
  echo "Managed Python $PYTHON_VERSION was not installed as expected." >&2
  exit 3
fi

uv venv "$PAYLOAD/semgrep" --python "$PYTHON_EXECUTABLE" --relocatable
uv pip install --python "$PAYLOAD/semgrep/bin/python" --no-cache "semgrep==$SEMGREP_VERSION"

# uv makes entrypoint scripts relocatable, but its venv interpreter link still
# targets the temporary absolute build path. Keep the managed runtime beside
# the venv and replace that one link with a stable relative target.
PYTHON_DISTRIBUTION="$(basename "$(dirname "$(dirname "$PYTHON_EXECUTABLE")")")"
unlink "$PAYLOAD/semgrep/bin/python"
ln -s "../../python/$PYTHON_DISTRIBUTION/bin/python3.14" "$PAYLOAD/semgrep/bin/python"

# `uv python install` also creates a convenience alias whose target is the
# absolute temporary build directory. Semgrep uses the exact versioned
# distribution above, so the alias is unnecessary and would make a release
# archive non-relocatable (or cause an archiver to follow the whole runtime
# twice). Remove only top-level Python aliases; links inside the runtime stay.
for python_alias in "$PAYLOAD/python"/*; do
  if [[ -L "$python_alias" ]]; then
    unlink "$python_alias"
  fi
done

VERSION_OUTPUT="$($PAYLOAD/semgrep/bin/semgrep --version | tail -n 1)"
if [[ "$VERSION_OUTPUT" != "$SEMGREP_VERSION" ]]; then
  echo "Unexpected Semgrep version: $VERSION_OUTPUT" >&2
  exit 3
fi

mv "$PAYLOAD" "$OUTPUT_ROOT"
POST_MOVE_VERSION="$($OUTPUT_ROOT/semgrep/bin/semgrep --version | tail -n 1)"
if [[ "$POST_MOVE_VERSION" != "$SEMGREP_VERSION" ]]; then
  echo "Relocated Semgrep pack failed validation." >&2
  exit 3
fi

if command -v sha256sum >/dev/null 2>&1; then
  SEMGREP_SHA256="$(sha256sum "$OUTPUT_ROOT/semgrep/bin/semgrep" | awk '{print $1}')"
  CORE_SHA256="$(find "$OUTPUT_ROOT/semgrep" -name semgrep-core -type f -exec sha256sum {} \; | head -n 1 | awk '{print $1}')"
else
  SEMGREP_SHA256="$(shasum -a 256 "$OUTPUT_ROOT/semgrep/bin/semgrep" | awk '{print $1}')"
  CORE_SHA256="$(find "$OUTPUT_ROOT/semgrep" -name semgrep-core -type f -exec shasum -a 256 {} \; | head -n 1 | awk '{print $1}')"
fi

cat > "$OUTPUT_ROOT/pack-metadata.json" <<EOF
{
  "schemaVersion": 1,
  "platform": "$HOST_PLATFORM",
  "semgrepVersion": "$SEMGREP_VERSION",
  "pythonVersion": "$PYTHON_VERSION",
  "entrypoint": "semgrep/bin/semgrep",
  "entrypointSha256": "$SEMGREP_SHA256",
  "semgrepCoreSha256": "$CORE_SHA256",
  "source": "https://pypi.org/project/semgrep/$SEMGREP_VERSION/",
  "license": "LGPL-2.1-or-later"
}
EOF

echo "Semgrep tool pack ready: $OUTPUT_ROOT"
du -sh "$OUTPUT_ROOT"
