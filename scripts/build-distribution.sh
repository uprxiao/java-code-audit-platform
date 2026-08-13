#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM="${1:-}"
VERSION="${2:-0.1.0-SNAPSHOT}"
OUTPUT_ROOT="${AUDIT_DISTRIBUTION_OUTPUT_ROOT:-${REPOSITORY_ROOT}/dist}"

if [[ "${PLATFORM}" != "darwin-arm64" && "${PLATFORM}" != "linux-x86_64" ]]; then
  echo "Usage: $0 <darwin-arm64|linux-x86_64> [version]" >&2
  exit 2
fi
[[ "${VERSION}" =~ ^[A-Za-z0-9._-]+$ ]] \
  || { echo "Distribution version contains unsafe characters: ${VERSION}" >&2; exit 2; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

require_file() {
  [[ -f "$1" ]] || { echo "Required distribution input is missing: $1" >&2; exit 3; }
}

require_directory() {
  [[ -d "$1" ]] || { echo "Required distribution input is missing: $1" >&2; exit 3; }
}

SEMGREP_PACK="${REPOSITORY_ROOT}/tools/downloads/tool-pack/${PLATFORM}/semgrep"
QUICK_PACK="${REPOSITORY_ROOT}/tools/downloads/tool-pack/${PLATFORM}/quick"
STANDARD_COMMON="${REPOSITORY_ROOT}/tools/downloads/tool-pack/common"
STANDARD_SUPPLY="${REPOSITORY_ROOT}/tools/downloads/tool-pack/${PLATFORM}/standard-supply"
require_directory "${SEMGREP_PACK}"
require_file "${QUICK_PACK}/quick-pack-metadata.json"
require_file "${STANDARD_COMMON}/standard-analysis/spotbugs/LICENSE.txt"
require_file "${STANDARD_COMMON}/standard-analysis/findsecbugs/LICENSE"
require_file "${STANDARD_SUPPLY}/standard-supply-pack-metadata.json"
require_file "${REPOSITORY_ROOT}/tools/manifest/tools-manifest.yaml"
require_file "${REPOSITORY_ROOT}/LICENSE"
command -v zip >/dev/null 2>&1 \
  || { echo "The zip command is required to preserve executable modes in the release archive." >&2; exit 3; }

"${REPOSITORY_ROOT}/mvnw" -q -pl backend/audit-api -am package -DskipTests
APP_JAR="${REPOSITORY_ROOT}/backend/audit-api/target/audit-api-0.1.0-SNAPSHOT.jar"
require_file "${APP_JAR}"

STAGING_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/java-audit-distribution.XXXXXX")"
cleanup() {
  chmod -R u+w "${STAGING_PARENT}" 2>/dev/null || true
  rm -rf "${STAGING_PARENT}"
}
trap cleanup EXIT
BUNDLE_NAME="java-code-audit-platform-${VERSION}-${PLATFORM}"
BUNDLE_ROOT="${STAGING_PARENT}/${BUNDLE_NAME}"
mkdir -p "${BUNDLE_ROOT}/app" "${BUNDLE_ROOT}/acceptance" "${BUNDLE_ROOT}/config" \
  "${BUNDLE_ROOT}/data" "${BUNDLE_ROOT}/licenses" "${BUNDLE_ROOT}/tools/${PLATFORM}"

cp "${APP_JAR}" "${BUNDLE_ROOT}/app/audit-api.jar"
cp -R "${REPOSITORY_ROOT}/packaging/bin" "${BUNDLE_ROOT}/bin"
cp "${REPOSITORY_ROOT}/scripts/update-standard-vulnerability-data.sh" \
  "${BUNDLE_ROOT}/bin/update-vulnerability-data.sh"
cp "${REPOSITORY_ROOT}/scripts/install-codeql-local.sh" \
  "${BUNDLE_ROOT}/bin/install-codeql-local.sh"
cp -R "${REPOSITORY_ROOT}/packaging/systemd" "${BUNDLE_ROOT}/systemd"
cp -R "${REPOSITORY_ROOT}/config/." "${BUNDLE_ROOT}/config/"
cp "${REPOSITORY_ROOT}/backend/audit-api/src/main/resources/application.yaml" \
  "${BUNDLE_ROOT}/config/application.yaml"
cp -R "${REPOSITORY_ROOT}/tools/manifest" "${BUNDLE_ROOT}/tools/manifest"
cp -R "${SEMGREP_PACK}" "${BUNDLE_ROOT}/tools/${PLATFORM}/semgrep"
# Older locally assembled packs may contain uv's temporary absolute Python
# alias. It is not used by the pinned Semgrep launcher and must never enter a
# relocatable archive.
for python_alias in "${BUNDLE_ROOT}/tools/${PLATFORM}/semgrep/python"/*; do
  if [[ -L "${python_alias}" ]]; then
    unlink "${python_alias}"
  fi
done
cp -R "${QUICK_PACK}" "${BUNDLE_ROOT}/tools/${PLATFORM}/quick"
cp -R "${STANDARD_COMMON}" "${BUNDLE_ROOT}/tools/common"
cp -R "${STANDARD_SUPPLY}" "${BUNDLE_ROOT}/tools/${PLATFORM}/standard-supply"
cp "${REPOSITORY_ROOT}/LICENSE" "${BUNDLE_ROOT}/licenses/PROJECT-LICENSE"
if [[ -f "${REPOSITORY_ROOT}/THIRD-PARTY-NOTICES.md" ]]; then
  cp "${REPOSITORY_ROOT}/THIRD-PARTY-NOTICES.md" "${BUNDLE_ROOT}/licenses/THIRD-PARTY-NOTICES.md"
fi
cp "${REPOSITORY_ROOT}/README.md" "${BUNDLE_ROOT}/README.md"

# Finder metadata is a local workstation artifact, not part of a reproducible
# release payload.
find "${BUNDLE_ROOT}" -type f -name '.DS_Store' -delete

# Bundled scanners are immutable release inputs. Runtime state belongs under
# data/, while tools/local remains writable for the separately licensed CodeQL
# installation workflow.
chmod -R a-w "${BUNDLE_ROOT}/tools/${PLATFORM}" "${BUNDLE_ROOT}/tools/common" \
  "${BUNDLE_ROOT}/tools/manifest"

chmod +x "${BUNDLE_ROOT}/bin/"*.sh
jar --create --file "${BUNDLE_ROOT}/acceptance/java17-acceptance-fixture.zip" \
  -C "${REPOSITORY_ROOT}/packaging/fixtures/maven17" .
jar --update --file "${BUNDLE_ROOT}/acceptance/java17-acceptance-fixture.zip" \
  -C "${REPOSITORY_ROOT}" LICENSE

CLASS_ROOT="${STAGING_PARENT}/class-check"
mkdir -p "${CLASS_ROOT}"
unzip -qq "${BUNDLE_ROOT}/app/audit-api.jar" \
  'BOOT-INF/classes/io/github/uprxiao/audit/api/AuditApplication.class' -d "${CLASS_ROOT}"
CLASS_MAJOR="$(javap -verbose \
  "${CLASS_ROOT}/BOOT-INF/classes/io/github/uprxiao/audit/api/AuditApplication.class" \
  | awk '/major version:/ {print $3; exit}')"
[[ "${CLASS_MAJOR}" == "61" ]] \
  || { echo "Expected JDK17 class major 61, found ${CLASS_MAJOR}." >&2; exit 4; }

(
  cd "${BUNDLE_ROOT}"
  find . -type f ! -name SHA256SUMS ! -name release-manifest.json | LC_ALL=C sort \
    | while IFS= read -r relative; do
        clean="${relative#./}"
        printf '%s  %s\n' "$(sha256_file "${relative}")" "${clean}"
      done > SHA256SUMS
)
FILE_COUNT="$(wc -l < "${BUNDLE_ROOT}/SHA256SUMS" | tr -d ' ')"
JAR_SHA="$(sha256_file "${BUNDLE_ROOT}/app/audit-api.jar")"
TOOLS_MANIFEST_SHA="$(sha256_file "${BUNDLE_ROOT}/tools/manifest/tools-manifest.yaml")"
printf '%s\n' \
  '{' \
  '  "schemaVersion": 1,' \
  "  \"version\": \"${VERSION}\"," \
  "  \"platform\": \"${PLATFORM}\"," \
  '  "javaClassMajor": 61,' \
  "  \"fileCount\": ${FILE_COUNT}," \
  "  \"applicationJarSha256\": \"sha256:${JAR_SHA}\"," \
  "  \"toolsManifestSha256\": \"sha256:${TOOLS_MANIFEST_SHA}\"," \
  '  "profiles": {"quickBundled": true, "standardBundled": true, "deepRequiresLocalCodeql": true},' \
  '  "dynamicVulnerabilityDatabasesBundled": false,' \
  '  "codeqlRedistributed": false,' \
  '  "checksums": "SHA256SUMS"' \
  '}' > "${BUNDLE_ROOT}/release-manifest.json"

mkdir -p "${OUTPUT_ROOT}"
ARCHIVE="${OUTPUT_ROOT}/${BUNDLE_NAME}.zip"
rm -f "${ARCHIVE}" "${ARCHIVE}.sha256"
(
  cd "${STAGING_PARENT}"
  zip -q -r -y "${ARCHIVE}" "${BUNDLE_NAME}"
)
ARCHIVE_SHA="$(sha256_file "${ARCHIVE}")"
printf '%s  %s\n' "${ARCHIVE_SHA}" "$(basename "${ARCHIVE}")" > "${ARCHIVE}.sha256"

echo "Distribution assembled: ${ARCHIVE}"
echo "Platform: ${PLATFORM}; class major: ${CLASS_MAJOR}; files: ${FILE_COUNT}"
echo "Archive SHA-256: ${ARCHIVE_SHA}"
