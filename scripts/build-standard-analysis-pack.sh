#!/usr/bin/env bash
set -euo pipefail

SPOTBUGS_VERSION="4.9.3"
FINDSECBUGS_VERSION="1.14.0"
SPOTBUGS_ARCHIVE_SHA256="d464d56050cf1dbda032e9482e1188f7cd7b7646eaff79c2e6cbe4d6822f4d9f"
FINDSECBUGS_ARCHIVE_SHA256="ff546e16e596ade5b6534a6da87881e569429bf46dfd8faed63ca63cdd69b4f8"
SPOTBUGS_JAR_SHA256="710e8b98f1ae23cdb71aaaf07e8d71fb63b44f2bbbaa1df3c3ba0de62aba6ec9"
FINDSECBUGS_PLUGIN_SHA256="6fa340344fa433ff46c2985dab1010e8bc739f9395c983594a5240095e92abc8"

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWNLOAD_ROOT="${REPOSITORY_ROOT}/tools/downloads/standard-analysis"
PACK_ROOT="${REPOSITORY_ROOT}/tools/downloads/tool-pack/common/standard-analysis"
SPOTBUGS_ARCHIVE="${DOWNLOAD_ROOT}/spotbugs-${SPOTBUGS_VERSION}.tgz"
FINDSECBUGS_ARCHIVE="${DOWNLOAD_ROOT}/findsecbugs-cli-${FINDSECBUGS_VERSION}.zip"

mkdir -p "${DOWNLOAD_ROOT}" "${PACK_ROOT}"

download() {
  local url="$1"
  local target="$2"
  if [[ ! -f "${target}" ]]; then
    curl --fail --location --retry 3 --output "${target}" "${url}"
  fi
}

verify_sha256() {
  local expected="$1"
  local target="$2"
  local actual
  actual="$(shasum -a 256 "${target}" | awk '{print $1}')"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "SHA-256 mismatch for ${target}: expected ${expected}, got ${actual}" >&2
    exit 1
  fi
}

download \
  "https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz" \
  "${SPOTBUGS_ARCHIVE}"
download \
  "https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-${FINDSECBUGS_VERSION}/findsecbugs-cli-${FINDSECBUGS_VERSION}.zip" \
  "${FINDSECBUGS_ARCHIVE}"
verify_sha256 "${SPOTBUGS_ARCHIVE_SHA256}" "${SPOTBUGS_ARCHIVE}"
verify_sha256 "${FINDSECBUGS_ARCHIVE_SHA256}" "${FINDSECBUGS_ARCHIVE}"

STAGING_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/java-audit-standard-analysis.XXXXXX")"
trap 'rm -rf "${STAGING_ROOT}"' EXIT

tar -xzf "${SPOTBUGS_ARCHIVE}" -C "${STAGING_ROOT}"
unzip -q "${FINDSECBUGS_ARCHIVE}" -d "${STAGING_ROOT}/findsecbugs"

rm -rf "${PACK_ROOT}/spotbugs" "${PACK_ROOT}/findsecbugs"
mkdir -p "${PACK_ROOT}/spotbugs" "${PACK_ROOT}/findsecbugs/lib"
cp -R "${STAGING_ROOT}/spotbugs-${SPOTBUGS_VERSION}/." "${PACK_ROOT}/spotbugs/"
cp "${STAGING_ROOT}/findsecbugs/lib/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar" \
  "${PACK_ROOT}/findsecbugs/lib/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar"
verify_sha256 "${SPOTBUGS_JAR_SHA256}" "${PACK_ROOT}/spotbugs/lib/spotbugs.jar"
verify_sha256 "${FINDSECBUGS_PLUGIN_SHA256}" \
  "${PACK_ROOT}/findsecbugs/lib/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar"

JAVA_EXECUTABLE="${JAVA_HOME:-}/bin/java"
if [[ ! -x "${JAVA_EXECUTABLE}" ]]; then
  JAVA_EXECUTABLE="$(command -v java)"
fi
"${JAVA_EXECUTABLE}" -cp "${PACK_ROOT}/spotbugs/lib/*" \
  edu.umd.cs.findbugs.LaunchAppropriateUI -textui -version

echo "Standard analysis pack assembled at ${PACK_ROOT}"
echo "SpotBugs archive SHA-256: ${SPOTBUGS_ARCHIVE_SHA256}"
echo "FindSecBugs archive SHA-256: ${FINDSECBUGS_ARCHIVE_SHA256}"
