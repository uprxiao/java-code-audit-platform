#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKSUMS="${BUNDLE_ROOT}/SHA256SUMS"
[[ -f "${CHECKSUMS}" ]] || { echo "Distribution SHA256SUMS is missing." >&2; exit 2; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

verified=0
while IFS= read -r line; do
  expected="${line%%  *}"
  relative="${line#*  }"
  case "${relative}" in
    app/*|bin/*|tools/manifest/*|tools/darwin-arm64/*|tools/linux-x86_64/*|tools/common/*|licenses/*)
      ;;
    *) continue ;;
  esac
  target="${BUNDLE_ROOT}/${relative}"
  [[ "${expected}" =~ ^[0-9a-f]{64}$ && -f "${target}" ]] \
    || { echo "Distribution integrity input is invalid or missing: ${relative}" >&2; exit 3; }
  actual="$(sha256_file "${target}")"
  [[ "${actual}" == "${expected}" ]] \
    || { echo "Distribution integrity mismatch: ${relative}" >&2; exit 3; }
  verified=$((verified + 1))
done < "${CHECKSUMS}"

(( verified > 0 )) || { echo "Distribution SHA256SUMS has no protected entries." >&2; exit 3; }
echo "Distribution integrity verified: ${verified} protected files."
