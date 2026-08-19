#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
CREDENTIALS_FILE="$PROJECT_ROOT/deploy/sonarqube/.state/credentials.env"
EVIDENCE_DIR="$PROJECT_ROOT/deploy/sonarqube/evidence/latest"
PROJECT_KEY="${SONAR_PROJECT_KEY:-java-code-audit-platform}"
SCANNER_VERSION="5.5.0.6356"

if [[ ! -f "$CREDENTIALS_FILE" ]]; then
  echo "Run scripts/sonarqube-local-up.sh first." >&2
  exit 1
fi

for command_name in curl mvn python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Required command is missing: $command_name" >&2
    exit 1
  }
done

if [[ -z "${JAVA_HOME:-}" ]]; then
  if [[ -x /usr/libexec/java_home ]]; then
    JAVA_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"
  fi
  if [[ -z "${JAVA_HOME:-}" && -x /opt/homebrew/opt/openjdk@17/bin/java ]]; then
    JAVA_HOME=/opt/homebrew/opt/openjdk@17
  fi
fi
if [[ -z "${JAVA_HOME:-}" || ! -x "$JAVA_HOME/bin/java" ]]; then
  echo "A JDK 17 JAVA_HOME is required to build this project." >&2
  exit 1
fi
java_feature="$($JAVA_HOME/bin/java -version 2>&1 | sed -n '1s/.*version "\([0-9][0-9]*\).*/\1/p')"
if [[ "$java_feature" != "17" ]]; then
  echo "JAVA_HOME must point to JDK 17; found Java $java_feature at $JAVA_HOME." >&2
  exit 1
fi
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

# shellcheck disable=SC1090
source "$CREDENTIALS_FILE"
export SONAR_TOKEN
mkdir -p "$EVIDENCE_DIR"

sonar_get() {
  local url="$1"
  printf 'user = "%s:"\n' "$SONAR_TOKEN" | curl --silent --show-error --fail --config - "$url"
}

echo "Building and analyzing the full Maven reactor with JDK $JAVA_HOME ..."
# Keep verify and the aggregate sonar goal in one Maven reactor. This preserves
# reactor dependency metadata and compiled bytecode for the Java analyzer.
(
  cd "$PROJECT_ROOT"
  mvn --batch-mode --no-transfer-progress clean verify \
    "org.sonarsource.scanner.maven:sonar-maven-plugin:${SCANNER_VERSION}:sonar" \
    -Dsonar.host.url="$SONAR_HOST_URL" \
    -Dsonar.projectKey="$PROJECT_KEY" \
    -Dsonar.projectName='Java Code Audit Platform' \
    -Dsonar.projectVersion='0.1.0-SNAPSHOT'
)

task_file="$PROJECT_ROOT/target/sonar/report-task.txt"
if [[ ! -f "$task_file" ]]; then
  echo "SonarScanner did not create $task_file" >&2
  exit 1
fi

ce_task_url="$(awk -F= '$1 == "ceTaskUrl" {print substr($0, index($0, "=") + 1)}' "$task_file")"
dashboard_url="$(awk -F= '$1 == "dashboardUrl" {print substr($0, index($0, "=") + 1)}' "$task_file")"
if [[ -z "$ce_task_url" ]]; then
  echo "SonarScanner did not provide a Compute Engine task URL." >&2
  exit 1
fi

deadline=$((SECONDS + 900))
ce_status="PENDING"
while (( SECONDS < deadline )); do
  ce_response="$(sonar_get "$ce_task_url")"
  printf '%s\n' "$ce_response" > "$EVIDENCE_DIR/compute-engine-task.json"
  ce_status="$(printf '%s' "$ce_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["task"]["status"])')"
  case "$ce_status" in
    SUCCESS) break ;;
    FAILED|CANCELED)
      echo "SonarQube Compute Engine task ended with status $ce_status." >&2
      exit 1
      ;;
  esac
  sleep 3
done

if [[ "$ce_status" != "SUCCESS" ]]; then
  echo "SonarQube Compute Engine task did not finish in 15 minutes." >&2
  exit 1
fi

sonar_get "$SONAR_HOST_URL/api/qualitygates/project_status?projectKey=$PROJECT_KEY" \
  > "$EVIDENCE_DIR/quality-gate.json"
sonar_get "$SONAR_HOST_URL/api/measures/component?component=$PROJECT_KEY&metricKeys=bugs,vulnerabilities,code_smells,security_hotspots,duplicated_lines_density,coverage,ncloc" \
  > "$EVIDENCE_DIR/measures.json"
sonar_get "$SONAR_HOST_URL/api/issues/search?componentKeys=$PROJECT_KEY&resolved=false&ps=500" \
  > "$EVIDENCE_DIR/issues-first-500.json"
sonar_get "$SONAR_HOST_URL/api/project_analyses/search?project=$PROJECT_KEY&ps=10" \
  > "$EVIDENCE_DIR/analyses.json"
sonar_get "$SONAR_HOST_URL/api/qualityprofiles/search?project=$PROJECT_KEY" \
  > "$EVIDENCE_DIR/quality-profiles.json"
sonar_get "$SONAR_HOST_URL/api/plugins/installed" \
  > "$EVIDENCE_DIR/plugins-installed.json"
sonar_get "$SONAR_HOST_URL/api/system/health" \
  > "$EVIDENCE_DIR/system-health.json"

python3 - "$EVIDENCE_DIR" <<'PY'
import collections
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
quality_gate_doc = json.loads((root / "quality-gate.json").read_text())["projectStatus"]
quality_gate = quality_gate_doc["status"]
measures = json.loads((root / "measures.json").read_text())["component"].get("measures", [])
issues_doc = json.loads((root / "issues-first-500.json").read_text())
issues = issues_doc.get("issues", [])
ce_task = json.loads((root / "compute-engine-task.json").read_text())["task"]
profiles = json.loads((root / "quality-profiles.json").read_text()).get("profiles", [])
java_profile = next((p for p in profiles if p.get("language") == "java"), {})
health = json.loads((root / "system-health.json").read_text()).get("health")
summary = {
    "serverHealth": health,
    "computeEngineStatus": ce_task.get("status"),
    "computeEngineWarningCount": ce_task.get("warningCount", 0),
    "analysisId": ce_task.get("analysisId"),
    "qualityGate": quality_gate,
    "qualityGateConditions": quality_gate_doc.get("conditions", []),
    "javaQualityProfile": java_profile.get("name"),
    "activeJavaRules": java_profile.get("activeRuleCount"),
    "totalIssues": issues_doc.get("total", len(issues)),
    "returnedIssues": len(issues),
    "bySeverity": dict(sorted(collections.Counter(i.get("severity", "UNKNOWN") for i in issues).items())),
    "byType": dict(sorted(collections.Counter(i.get("type", "UNKNOWN") for i in issues).items())),
    "topRules": collections.Counter(i.get("rule", "UNKNOWN") for i in issues).most_common(20),
    "topFiles": collections.Counter(i.get("component", "UNKNOWN") for i in issues).most_common(20),
    "measures": {m["metric"]: m.get("value") for m in measures},
}
(root / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
print(json.dumps(summary, indent=2, ensure_ascii=False))
PY

echo "Compute Engine status: $ce_status"
echo "Dashboard: $dashboard_url"
echo "Sanitized API evidence: $EVIDENCE_DIR"
