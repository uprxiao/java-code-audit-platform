#!/usr/bin/env python3
"""Compare a platform AuditReport with a SonarQube issues export.

The comparison is deliberately conservative: an overlap requires the same
project-relative file, the same line, and an explicitly reviewed semantic rule
mapping. Raw finding counts are never treated as equivalent coverage.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
from pathlib import Path
from typing import Any


SONAR_TO_PLATFORM_FAMILIES: dict[str, set[str]] = {
    "java:S1128": {"UNUSED_IMPORTS"},
    "java:S1144": {"UNUSED_PRIVATE_METHOD", "UPM_UNCALLED_PRIVATE_METHOD"},
    "java:S1068": {"UNUSED_PRIVATE_FIELD", "URF_UNREAD_FIELD"},
    "java:S1172": {"UNUSED_PARAMETER"},
    "java:S1481": {"UNUSED_LOCAL_VARIABLE", "LOCAL_VARIABLE_IS_NEVER_READ"},
    "java:S1854": {
        "UNUSED_ASSIGNMENT",
        "UNUSED_LOCAL_VARIABLE",
        "LOCAL_VARIABLE_IS_NEVER_READ",
        "DLS_DEAD_LOCAL_STORE",
    },
    "java:S899": {"IGNORED_ERROR_STATUS_OF_CALL", "RV_RETURN_VALUE_IGNORED_BAD_PRACTICE"},
    "java:S1948": {"SE_BAD_FIELD"},
    "java:S2093": {"USE_TRY_WITH_RESOURCES"},
    "java:S2275": {"VA_FORMAT_STRING_USES_NEWLINE"},
}


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sonar_path(issue: dict[str, Any]) -> str:
    component = str(issue.get("component", ""))
    return component.split(":", 1)[1] if ":" in component else component


def engines(finding: dict[str, Any]) -> list[str]:
    return sorted({str(item.get("engine", "")) for item in finding.get("evidence", []) if item.get("engine")})


def counts(values: list[str]) -> dict[str, int]:
    return dict(sorted(collections.Counter(values).items(), key=lambda item: (-item[1], item[0])))


def metric_value(measures: dict[str, Any], name: str) -> str | None:
    for measure in measures.get("component", {}).get("measures", []):
        if measure.get("metric") == name:
            return str(measure.get("value"))
    return None


def compare(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    platform = load(args.platform_report)
    platform_engines = load(args.platform_engines)
    sonar_export = load(args.sonar_issues)
    sonar_measures = load(args.sonar_measures)
    findings = platform.get("findings", [])
    issues = sonar_export.get("issues", [])

    sonar_index: dict[tuple[str, int, str], list[dict[str, Any]]] = collections.defaultdict(list)
    for issue in issues:
        line = int(issue.get("line") or issue.get("textRange", {}).get("startLine") or 0)
        sonar_index[(sonar_path(issue), line, str(issue.get("rule", "")))].append(issue)

    overlap: list[dict[str, Any]] = []
    for finding in findings:
        location = finding.get("location") or {}
        path = str(location.get("path", ""))
        line = int(location.get("startLine") or 0)
        family = str(finding.get("ruleFamily", ""))
        if not path or line < 1:
            continue
        for sonar_rule, families in SONAR_TO_PLATFORM_FAMILIES.items():
            if family not in families:
                continue
            for issue in sonar_index.get((path, line, sonar_rule), []):
                overlap.append(
                    {
                        "path": path,
                        "line": line,
                        "platformFindingId": finding.get("id"),
                        "platformRuleFamily": family,
                        "platformSeverity": finding.get("severity"),
                        "platformEngines": engines(finding),
                        "sonarIssueKey": issue.get("key"),
                        "sonarRule": sonar_rule,
                        "sonarType": issue.get("type"),
                        "sonarSeverity": issue.get("severity"),
                        "sonarMessage": issue.get("message"),
                    }
                )

    platform_ids = {row["platformFindingId"] for row in overlap}
    sonar_ids = {row["sonarIssueKey"] for row in overlap}
    source_sites = {(row["path"], row["line"]) for row in overlap}
    platform_with_location = [finding for finding in findings if (finding.get("location") or {}).get("path")]
    non_comparable_categories = {"DEPENDENCY_VULNERABILITY", "BUILD_GOVERNANCE"}

    summary = {
        "schemaVersion": 1,
        "platform": {
            "scanId": platform.get("scan", {}).get("scanId"),
            "status": platform.get("scan", {}).get("status"),
            "uniqueFindings": len(findings),
            "rawHits": platform.get("summary", {}).get("rawHitCount"),
            "findingsWithSourceLocation": len(platform_with_location),
            "sourceFindingsByCategory": counts(
                [str(finding.get("category")) for finding in platform_with_location]
            ),
            "ruleFamilies": counts([str(finding.get("ruleFamily")) for finding in findings]),
            "engineStates": {
                str(engine.get("engineId")): {
                    "status": engine.get("status"),
                    "rawHitCount": (engine.get("coverage") or {}).get("rawHitCount"),
                    "version": engine.get("toolVersion"),
                }
                for engine in platform_engines
            },
            "nonComparableFindings": sum(
                1 for finding in findings if finding.get("category") in non_comparable_categories
            ),
        },
        "sonarQube": {
            "projectKey": sonar_export.get("projectKey"),
            "issues": len(issues),
            "types": counts([str(issue.get("type")) for issue in issues]),
            "scopes": counts([str(issue.get("scope")) for issue in issues]),
            "rules": counts([str(issue.get("rule")) for issue in issues]),
            "measures": {
                name: metric_value(sonar_measures, name)
                for name in (
                    "bugs",
                    "vulnerabilities",
                    "code_smells",
                    "security_hotspots",
                    "ncloc",
                    "duplicated_blocks",
                    "duplicated_lines",
                    "duplicated_lines_density",
                    "coverage",
                )
            },
        },
        "semanticOverlap": {
            "pairCount": len(overlap),
            "platformFindingCount": len(platform_ids),
            "sonarIssueCount": len(sonar_ids),
            "sourceSiteCount": len(source_sites),
            "rulePairs": counts(
                [f"{row['platformRuleFamily']} <-> {row['sonarRule']}" for row in overlap]
            ),
        },
        "comparisonPolicy": {
            "path": "exact project-relative path",
            "line": "exact start line",
            "rule": "explicit SONAR_TO_PLATFORM_FAMILIES mapping",
            "warning": "Overlap is corroboration, not a precision or recall measurement.",
        },
    }
    return summary, sorted(overlap, key=lambda row: (row["path"], row["line"], row["sonarRule"]))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform-report", type=Path, required=True)
    parser.add_argument("--platform-engines", type=Path, required=True)
    parser.add_argument("--sonar-issues", type=Path, required=True)
    parser.add_argument("--sonar-measures", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    summary, overlap = compare(args)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "comparison-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    columns = list(overlap[0]) if overlap else ["path", "line"]
    with (args.output_dir / "semantic-overlap.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in overlap:
            writer.writerow({**row, "platformEngines": ",".join(row["platformEngines"])})
    print(json.dumps(summary["semanticOverlap"], ensure_ascii=False))


if __name__ == "__main__":
    main()
