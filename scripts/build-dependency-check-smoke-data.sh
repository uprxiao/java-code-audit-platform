#!/usr/bin/env bash
set -euo pipefail

# ACCEPTANCE ONLY. This deliberately creates an incomplete Dependency-Check database
# containing the NVD 2021 feed and empty placeholders for every other year. It proves
# the parser/adapter can find Log4Shell; it MUST NOT be used for a real audit.

DEPENDENCY_CHECK_VERSION="12.2.2"
SMOKE_YEAR="2021"
LOG4SHELL_ID="CVE-2021-44228"
NVD_FEED_BASE_URL="${AUDIT_NVD_FEED_BASE_URL:-https://nvd.nist.gov/feeds/json/cve/2.0}"
REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLATFORM="darwin-arm64" ;;
  Linux-x86_64) PLATFORM="linux-x86_64" ;;
  *) echo "Unsupported acceptance host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

DEPENDENCY_CHECK="${AUDIT_DEPENDENCY_CHECK_EXECUTABLE:-$REPOSITORY_ROOT/tools/downloads/tool-pack/$PLATFORM/standard-supply/dependency-check/dependency-check/bin/dependency-check.sh}"
OUTPUT_DIRECTORY="${AUDIT_DEPENDENCY_CHECK_SMOKE_DATA:-$REPOSITORY_ROOT/tools/downloads/databases/dependency-check-smoke}"
PYTHON_EXECUTABLE="${AUDIT_PYTHON_EXECUTABLE:-$(command -v python3 || true)}"

[[ "${AUDIT_ACCEPT_INCOMPLETE_SMOKE_DATA:-}" == "YES" ]] || {
  echo "Refusing to build an incomplete database without AUDIT_ACCEPT_INCOMPLETE_SMOKE_DATA=YES" >&2
  echo "This script is for acceptance testing only and must never supply a production scan." >&2
  exit 2
}
for command_name in curl gzip awk date wc grep cp tr mktemp java jar; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "$command_name is required" >&2; exit 2; }
done
[[ -n "$PYTHON_EXECUTABLE" && -x "$PYTHON_EXECUTABLE" ]] || { echo "python3 is required" >&2; exit 2; }
[[ -x "$DEPENDENCY_CHECK" ]] || { echo "Dependency-Check executable unavailable: $DEPENDENCY_CHECK" >&2; exit 2; }
[[ "$(java -XshowSettings:properties -version 2>&1 | awk '/java.specification.version =/ {print $3}')" == "17" ]] || {
  echo "JDK 17 is required" >&2; exit 2;
}
jar --version | grep -Eq '^jar 17([.]|$)' || { echo "The JDK 17 jar tool is required" >&2; exit 2; }
DEPENDENCY_CHECK_VERSION_OUTPUT="$("$DEPENDENCY_CHECK" --version)"
grep -Fq "$DEPENDENCY_CHECK_VERSION" <<<"$DEPENDENCY_CHECK_VERSION_OUTPUT" || {
  echo "Dependency-Check $DEPENDENCY_CHECK_VERSION is required" >&2; exit 2;
}

OUTPUT_PARENT="$(dirname "$OUTPUT_DIRECTORY")"
OUTPUT_NAME="$(basename "$OUTPUT_DIRECTORY")"
case "$OUTPUT_NAME" in
  *smoke*|*acceptance*) ;;
  *) echo "Acceptance output name must contain 'smoke' or 'acceptance': $OUTPUT_NAME" >&2; exit 2 ;;
esac
mkdir -p "$OUTPUT_PARENT"
OUTPUT_PARENT="$(cd "$OUTPUT_PARENT" && pwd -P)"
OUTPUT_DIRECTORY="$OUTPUT_PARENT/$OUTPUT_NAME"
[[ ! -e "$OUTPUT_DIRECTORY" ]] || { echo "Refusing to overwrite acceptance data: $OUTPUT_DIRECTORY" >&2; exit 2; }

STAGING_ROOT="$(mktemp -d "$OUTPUT_PARENT/.dependency-check-smoke.XXXXXX")"
FEED_DIRECTORY="$STAGING_ROOT/feed"
DATABASE_DIRECTORY="$STAGING_ROOT/database"
VALIDATION_DIRECTORY="$STAGING_ROOT/validation"
PORT_FILE="$STAGING_ROOT/http-port"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  case "$STAGING_ROOT" in
    "$OUTPUT_PARENT"/.dependency-check-smoke.*) rm -rf -- "$STAGING_ROOT" ;;
    *) echo "Refusing unsafe staging cleanup: $STAGING_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM
mkdir -p "$FEED_DIRECTORY" "$DATABASE_DIRECTORY" "$VALIDATION_DIRECTORY"

sha256_stream() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'; else shasum -a 256 | awk '{print $1}'; fi
}
metadata_value() {
  awk -v requested="$1" '
    index($0, requested ":") == 1 {
      sub("^[^:]*:", ""); sub("\\r$", ""); print; exit
    }
  ' "$2"
}
download() {
  curl -fL --retry 3 --retry-delay 2 --connect-timeout 30 -o "$2" "$1"
}

OFFICIAL_META="$FEED_DIRECTORY/nvdcve-2.0-$SMOKE_YEAR.meta"
OFFICIAL_GZIP="$FEED_DIRECTORY/nvdcve-2.0-$SMOKE_YEAR.json.gz"
download "$NVD_FEED_BASE_URL/nvdcve-2.0-$SMOKE_YEAR.meta" "$OFFICIAL_META"
download "$NVD_FEED_BASE_URL/nvdcve-2.0-$SMOKE_YEAR.json.gz" "$OFFICIAL_GZIP"
gzip -t "$OFFICIAL_GZIP"

# NVD's meta sha256 is the digest of the uncompressed JSON, not the .gz file.
EXPECTED_SHA="$(metadata_value sha256 "$OFFICIAL_META" | tr '[:upper:]' '[:lower:]')"
EXPECTED_SIZE="$(metadata_value size "$OFFICIAL_META")"
EXPECTED_GZIP_SIZE="$(metadata_value gzSize "$OFFICIAL_META")"
ACTUAL_SHA="$(gzip -dc "$OFFICIAL_GZIP" | sha256_stream)"
ACTUAL_SIZE="$(gzip -dc "$OFFICIAL_GZIP" | wc -c | tr -d '[:space:]')"
ACTUAL_GZIP_SIZE="$(wc -c < "$OFFICIAL_GZIP" | tr -d '[:space:]')"
[[ -n "$EXPECTED_SHA" && "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] || {
  echo "NVD $SMOKE_YEAR uncompressed SHA256 mismatch: expected=$EXPECTED_SHA actual=$ACTUAL_SHA" >&2; exit 3;
}
[[ "$ACTUAL_SIZE" == "$EXPECTED_SIZE" && "$ACTUAL_GZIP_SIZE" == "$EXPECTED_GZIP_SIZE" ]] || {
  echo "NVD $SMOKE_YEAR feed size mismatch" >&2; exit 3;
}
gzip -dc "$OFFICIAL_GZIP" | grep -F "$LOG4SHELL_ID" >/dev/null || {
  echo "NVD $SMOKE_YEAR feed does not contain $LOG4SHELL_ID" >&2; exit 3;
}

EMPTY_JSON="$FEED_DIRECTORY/empty.json"
EMPTY_GZIP="$FEED_DIRECTORY/empty.json.gz"
cat > "$EMPTY_JSON" <<'EOF'
{
  "resultsPerPage": 0,
  "startIndex": 0,
  "totalResults": 0,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2000-01-01T00:00:00.000",
  "vulnerabilities": []
}
EOF
gzip -n -c "$EMPTY_JSON" > "$EMPTY_GZIP"
EMPTY_SIZE="$(wc -c < "$EMPTY_JSON" | tr -d '[:space:]')"
EMPTY_GZIP_SIZE="$(wc -c < "$EMPTY_GZIP" | tr -d '[:space:]')"
EMPTY_SHA="$(sha256_stream < "$EMPTY_JSON" | tr '[:lower:]' '[:upper:]')"
EMPTY_META="$FEED_DIRECTORY/empty.meta"
cat > "$EMPTY_META" <<EOF
lastModifiedDate:2000-01-01T00:00:00+00:00
size:$EMPTY_SIZE
zipSize:$EMPTY_GZIP_SIZE
gzSize:$EMPTY_GZIP_SIZE
sha256:$EMPTY_SHA
EOF

CURRENT_YEAR="$(date -u +%Y)"
for ((year = 2002; year <= CURRENT_YEAR; year++)); do
  if [[ "$year" != "$SMOKE_YEAR" ]]; then
    cp "$EMPTY_GZIP" "$FEED_DIRECTORY/nvdcve-2.0-$year.json.gz"
    cp "$EMPTY_META" "$FEED_DIRECTORY/nvdcve-2.0-$year.meta"
  fi
done
# Dependency-Check always probes the modified feed after the yearly feeds.
cp "$EMPTY_GZIP" "$FEED_DIRECTORY/nvdcve-2.0-modified.json.gz"
cp "$EMPTY_META" "$FEED_DIRECTORY/nvdcve-2.0-modified.meta"

"$PYTHON_EXECUTABLE" - "$FEED_DIRECTORY" "$PORT_FILE" <<'PY' &
import functools
import http.server
import pathlib
import sys

feed_directory, port_file = sys.argv[1:]

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass

handler = functools.partial(QuietHandler, directory=feed_directory)
with http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
    pathlib.Path(port_file).write_text(str(server.server_address[1]), encoding="ascii")
    server.serve_forever()
PY
SERVER_PID="$!"
for _attempt in {1..100}; do
  [[ -s "$PORT_FILE" ]] && break
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "Local feed server failed" >&2; exit 4; }
  sleep 0.05
done
[[ -s "$PORT_FILE" ]] || { echo "Local feed server did not become ready" >&2; exit 4; }
LOCAL_FEED_URL="http://127.0.0.1:$(cat "$PORT_FILE")/nvdcve-2.0-{0}.json.gz"

"$DEPENDENCY_CHECK" --updateonly --data "$DATABASE_DIRECTORY" \
  --nvdDatafeed "$LOCAL_FEED_URL" \
  --disableKnownExploited --disableHostedSuppressions --disableRetireJs \
  --disableOssIndex --disableVersionCheck
find "$DATABASE_DIRECTORY" -maxdepth 1 -type f -name 'odc*.mv.db' -size +0c | grep -q . || {
  echo "Acceptance update produced no usable Dependency-Check database" >&2; exit 4;
}

FIXTURE_ROOT="$VALIDATION_DIRECTORY/log4j-fixture"
mkdir -p "$FIXTURE_ROOT/META-INF/maven/org.apache.logging.log4j/log4j-core" \
  "$VALIDATION_DIRECTORY/report"
cat > "$FIXTURE_ROOT/META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties" <<'EOF'
groupId=org.apache.logging.log4j
artifactId=log4j-core
version=2.14.1
EOF
cat > "$FIXTURE_ROOT/META-INF/maven/org.apache.logging.log4j/log4j-core/pom.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.14.1</version>
  <name>Apache Log4j Core</name>
</project>
EOF
cat > "$VALIDATION_DIRECTORY/MANIFEST.MF" <<'EOF'
Manifest-Version: 1.0
Implementation-Title: Apache Log4j Core
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 2.14.1

EOF
jar --create --file "$VALIDATION_DIRECTORY/log4j-core-2.14.1.jar" \
  --manifest "$VALIDATION_DIRECTORY/MANIFEST.MF" -C "$FIXTURE_ROOT" .
"$DEPENDENCY_CHECK" --project dependency-check-acceptance-only \
  --scan "$VALIDATION_DIRECTORY/log4j-core-2.14.1.jar" \
  --format JSON --prettyPrint --out "$VALIDATION_DIRECTORY/report" \
  --data "$DATABASE_DIRECTORY" --noupdate --disableCentral --disableOssIndex \
  --disableNodeAudit --disableYarnAudit --disablePnpmAudit --disableKnownExploited \
  --failOnCVSS 11

"$PYTHON_EXECUTABLE" - "$VALIDATION_DIRECTORY/report/dependency-check-report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
expected_purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
sources = report.get("scanInfo", {}).get("dataSource", [])
for dependency in report.get("dependencies", []):
    purls = {item.get("id") for item in dependency.get("packages", [])}
    cves = {item.get("name") for item in dependency.get("vulnerabilities", [])}
    if expected_purl in purls and "CVE-2021-44228" in cves and sources:
        break
else:
    raise SystemExit("Smoke database did not produce the expected Log4Shell PURL/CVE finding")
PY

cp "$OFFICIAL_META" "$DATABASE_DIRECTORY/acceptance-nvdcve-2.0-$SMOKE_YEAR.meta"
cat > "$DATABASE_DIRECTORY/ACCEPTANCE-ONLY.txt" <<EOF
ACCEPTANCE TEST DATA ONLY - NEVER USE THIS DATABASE FOR A REAL AUDIT.

This intentionally incomplete database contains the NVD $SMOKE_YEAR feed only.
Every other yearly and modified feed was replaced by a valid empty feed.
It exists solely to verify Dependency-Check $DEPENDENCY_CHECK_VERSION and the Log4Shell parser contract.
Source metadata: $NVD_FEED_BASE_URL/nvdcve-2.0-$SMOKE_YEAR.meta
Verified uncompressed SHA256: $ACTUAL_SHA
EOF
"$PYTHON_EXECUTABLE" - "$DATABASE_DIRECTORY/smoke-data-metadata.json" \
  "$NVD_FEED_BASE_URL" "$EXPECTED_SHA" "$ACTUAL_SIZE" "$ACTUAL_GZIP_SIZE" <<'PY'
import json
import sys

target, base_url, sha256, size, gzip_size = sys.argv[1:]
payload = {
    "schemaVersion": 1,
    "acceptanceOnly": True,
    "productionUseProhibited": True,
    "dependencyCheckVersion": "12.2.2",
    "includedNvdYears": [2021],
    "emptyNvdYears": "all other years plus modified",
    "expectedFinding": "CVE-2021-44228",
    "feedBaseUrl": base_url,
    "feedUncompressedSha256": sha256,
    "feedUncompressedBytes": int(size),
    "feedGzipBytes": int(gzip_size),
}
with open(target, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

mv "$DATABASE_DIRECTORY" "$OUTPUT_DIRECTORY"
echo "Dependency-Check acceptance-only smoke database ready: $OUTPUT_DIRECTORY"
echo "WARNING: incomplete NVD 2021-only data; production use is prohibited."
