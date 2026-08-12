#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKSUMS="${BUNDLE_ROOT}/SHA256SUMS"
[[ -f "${CHECKSUMS}" ]] || { echo "Distribution SHA256SUMS is missing." >&2; exit 2; }

verified=0
FILTERED_CHECKSUMS="$(mktemp "${TMPDIR:-/tmp}/java-audit-checksums.XXXXXX")"
cleanup() { rm -f "${FILTERED_CHECKSUMS}"; }
trap cleanup EXIT
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
  printf '%s  %s\n' "${expected}" "${relative}" >> "${FILTERED_CHECKSUMS}"
  verified=$((verified + 1))
done < "${CHECKSUMS}"

(( verified > 0 )) || { echo "Distribution SHA256SUMS has no protected entries." >&2; exit 3; }
# Hash all protected files in one process. The previous per-file subprocess
# implementation took over a minute for the Semgrep runtime on macOS.
if command -v sha256sum >/dev/null 2>&1; then
  (cd "${BUNDLE_ROOT}" && sha256sum --quiet -c "${FILTERED_CHECKSUMS}") \
    || { echo "Distribution integrity verification failed." >&2; exit 3; }
else
  (cd "${BUNDLE_ROOT}" && shasum -a 256 -c "${FILTERED_CHECKSUMS}" >/dev/null) \
    || { echo "Distribution integrity verification failed." >&2; exit 3; }
fi
echo "Distribution integrity verified: ${verified} protected files."
