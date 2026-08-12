#!/usr/bin/env python3
"""Black-box REST acceptance against an actually running release JAR.

The script intentionally uses only Python's standard library.  It stores every
request/response artifact under the evidence directory so a failed assertion is
reproducible instead of being reduced to a console message.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path


TERMINAL = {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED", "INTERRUPTED"}
PROFILE_ENGINES = {"QUICK": 6, "STANDARD": 14, "DEEP": 15}
FORBIDDEN_ARCHIVE_SEGMENT = re.compile(
    r"(^|/)(source|workspace|repository|target|codeql-db|\.m2|home|cache)(/|$)"
)
CANARY = b"AUDIT_CANARY_SECRET_V1_RELEASE_FIXTURE"


class ApiFailure(AssertionError):
    pass


class EvidenceClient:
    def __init__(self, base_url: str, evidence: Path, timeout: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.evidence = evidence
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.sequence = 0

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        expected: set[int] | None = None,
        label: str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        self.sequence += 1
        request = urllib.request.Request(
            self.base_url + path, data=body, headers=headers or {}, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = response.status
                response_headers = dict(response.headers.items())
                content = response.read()
        except urllib.error.HTTPError as error:
            status = error.code
            response_headers = dict(error.headers.items())
            content = error.read()
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "-", label or path.strip("/") or "root")
        prefix = self.evidence / f"{self.sequence:03d}-{method.lower()}-{safe_label}"
        prefix.with_suffix(".headers.json").write_text(
            json.dumps({"status": status, "headers": response_headers}, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        prefix.with_suffix(".body").write_bytes(content)
        if expected is not None and status not in expected:
            raise ApiFailure(
                f"{method} {path}: expected {sorted(expected)}, got {status}; "
                f"evidence={prefix.with_suffix('.body')}"
            )
        return status, response_headers, content

    def json(self, method: str, path: str, **kwargs) -> tuple[int, dict[str, str], object]:
        status, headers, body = self.request(method, path, **kwargs)
        try:
            return status, headers, json.loads(body)
        except json.JSONDecodeError as error:
            raise ApiFailure(f"{method} {path} did not return JSON: {error}") from error

    def multipart(
        self,
        path: str,
        source: bytes,
        request_json: bytes,
        *,
        filename: str = "source.zip",
        expected: set[int],
        label: str,
    ) -> tuple[int, dict[str, str], object]:
        boundary = "----java-audit-" + uuid.uuid4().hex
        output = io.BytesIO()

        def part(name: str, value: bytes, content_type: str, part_filename: str | None = None) -> None:
            output.write(f"--{boundary}\r\n".encode())
            disposition = f'Content-Disposition: form-data; name="{name}"'
            if part_filename is not None:
                disposition += f'; filename="{part_filename}"'
            output.write((disposition + "\r\n").encode())
            output.write(f"Content-Type: {content_type}\r\n\r\n".encode())
            output.write(value)
            output.write(b"\r\n")

        part("source", source, "application/zip", filename)
        part("request", request_json, "application/json")
        output.write(f"--{boundary}--\r\n".encode())
        return self.json(
            "POST",
            path,
            body=output.getvalue(),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            expected=expected,
            label=label,
        )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ApiFailure(message)


def error_code(payload: object) -> str:
    return payload.get("code", "") if isinstance(payload, dict) else ""


def create_scan(client: EvidenceClient, archive: bytes, profile: str, label: str) -> str:
    status, headers, payload = client.multipart(
        "/api/v1/scans/zip",
        archive,
        json.dumps({"displayName": label, "profile": profile}).encode(),
        expected={202},
        label=f"create-{profile.lower()}-{label}",
    )
    require(status == 202 and isinstance(payload, dict), f"{profile} create response is invalid")
    scan_id = payload.get("scanId", "")
    require(re.fullmatch(r"[0-9a-fA-F-]{36}", scan_id) is not None, f"invalid scan id: {scan_id}")
    require(payload.get("status") == "QUEUED", f"{profile} was not initially QUEUED")
    require(len(payload.get("plannedEngines", [])) == PROFILE_ENGINES[profile],
            f"{profile} planned engine count is wrong")
    require(headers.get("Location", "").endswith(scan_id), f"{profile} Location header is wrong")
    return scan_id


def wait_terminal(client: EvidenceClient, scan_id: str, label: str, timeout: int) -> dict:
    deadline = time.monotonic() + timeout
    last: dict = {}
    while time.monotonic() < deadline:
        _, _, payload = client.json(
            "GET", f"/api/v1/scans/{scan_id}", expected={200}, label=f"poll-{label}"
        )
        require(isinstance(payload, dict), f"scan {scan_id} state is not an object")
        last = payload
        if payload.get("status") in TERMINAL:
            return payload
        time.sleep(1)
    raise ApiFailure(f"scan {scan_id} did not finish within {timeout}s; last={last}")


def all_findings(client: EvidenceClient, scan_id: str, label: str) -> list[dict]:
    findings: list[dict] = []
    for page in range(10000):
        _, _, payload = client.json(
            "GET",
            f"/api/v1/scans/{scan_id}/findings?page={page}&size=200",
            expected={200},
            label=f"findings-{label}-page-{page}",
        )
        require(isinstance(payload, list), "findings response is not an array")
        findings.extend(payload)
        if len(payload) < 200:
            return findings
    raise ApiFailure("finding pagination did not terminate")


def verify_archive(content: bytes, profile: str) -> None:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        names = archive.namelist()
        required = {"report.html", "report.json", "report.sarif", "coverage.json", "manifest.json"}
        require(required.issubset(names), f"archive is missing {sorted(required - set(names))}")
        if profile in {"STANDARD", "DEEP"}:
            require("sbom/bom.json" in names, f"{profile} archive has no SBOM")
        forbidden = [name for name in names if FORBIDDEN_ARCHIVE_SEGMENT.search(name)]
        require(not forbidden, f"archive contains forbidden paths: {forbidden[:10]}")
        for name in names:
            if not name.endswith("/"):
                require(CANARY not in archive.read(name), f"canary leaked into archive member {name}")


def verify_completed_scan(client: EvidenceClient, scan_id: str, profile: str) -> dict:
    terminal = wait_terminal(client, scan_id, profile.lower(), client.timeout)
    require(terminal.get("status") == "COMPLETED", f"{profile} failed: {terminal}")
    require(terminal.get("progress", {}).get("enginesTotal") == PROFILE_ENGINES[profile],
            f"{profile} terminal engine count is wrong")

    _, _, engines = client.json(
        "GET", f"/api/v1/scans/{scan_id}/engines", expected={200}, label=f"engines-{profile.lower()}"
    )
    require(isinstance(engines, list) and len(engines) == PROFILE_ENGINES[profile],
            f"{profile} engines response is incomplete")
    for engine in engines:
        engine_id = engine.get("engineId", "")
        require(engine.get("status") == "SUCCEEDED", f"{profile}/{engine_id} did not succeed: {engine}")
        _, _, detail = client.json(
            "GET", f"/api/v1/scans/{scan_id}/engines/{urllib.parse.quote(engine_id)}",
            expected={200}, label=f"engine-{profile.lower()}-{engine_id}",
        )
        require(detail.get("engineId") == engine_id, f"engine detail mismatch for {engine_id}")

    findings = all_findings(client, scan_id, profile.lower())
    require(terminal.get("summary", {}).get("uniqueFindingCount") == len(findings),
            f"{profile} state/finding count mismatch")
    if findings:
        first = findings[0]
        finding_id = urllib.parse.quote(first["id"])
        _, _, detail = client.json(
            "GET", f"/api/v1/scans/{scan_id}/findings/{finding_id}",
            expected={200}, label=f"finding-{profile.lower()}-detail",
        )
        require(detail.get("id") == first["id"], "finding detail mismatch")
        for key in ("severity", "category"):
            value = urllib.parse.quote(str(first[key]))
            _, _, filtered = client.json(
                "GET", f"/api/v1/scans/{scan_id}/findings?{key}={value}&size=200",
                expected={200}, label=f"findings-{profile.lower()}-{key}",
            )
            require(filtered and all(item[key] == first[key] for item in filtered),
                    f"finding {key} filter is inconsistent")
        engine = first.get("evidence", [{}])[0].get("engine", "")
        if engine:
            _, _, filtered = client.json(
                "GET", f"/api/v1/scans/{scan_id}/findings?engine={urllib.parse.quote(engine)}&size=200",
                expected={200}, label=f"findings-{profile.lower()}-engine",
            )
            require(filtered, "finding engine filter unexpectedly returned no rows")
        module = first.get("module", "")
        if module:
            _, _, filtered = client.json(
                "GET", f"/api/v1/scans/{scan_id}/findings?module={urllib.parse.quote(module)}&size=200",
                expected={200}, label=f"findings-{profile.lower()}-module",
            )
            require(filtered and all(item.get("module") == module for item in filtered),
                    "finding module filter is inconsistent")
        needle = str(first.get("titleZh") or first.get("titleEn") or "")[:12]
        if needle:
            _, _, filtered = client.json(
                "GET", f"/api/v1/scans/{scan_id}/findings?text={urllib.parse.quote(needle)}&size=200",
                expected={200}, label=f"findings-{profile.lower()}-text",
            )
            require(any(item.get("id") == first["id"] for item in filtered),
                    "finding text filter did not return the matching row")
    _, _, suppressed = client.json(
        "GET", f"/api/v1/scans/{scan_id}/findings?suppressed=true&size=200",
        expected={200}, label=f"findings-{profile.lower()}-suppressed",
    )
    require(isinstance(suppressed, list), "suppressed finding filter is not an array")
    status, _, invalid_page = client.json(
        "GET", f"/api/v1/scans/{scan_id}/findings?size=201", expected={400},
        label=f"findings-{profile.lower()}-invalid-page",
    )
    require(status == 400 and error_code(invalid_page) == "INVALID_REQUEST", "invalid page contract changed")
    _, _, invalid_filter = client.json(
        "GET", f"/api/v1/scans/{scan_id}/findings?severity=NOT_A_SEVERITY", expected={400},
        label=f"findings-{profile.lower()}-invalid-severity",
    )
    require(error_code(invalid_filter) == "INVALID_REQUEST", "invalid severity contract changed")
    for endpoint, label in (("engines/not-an-engine", "unknown-engine"),
                            ("findings/not-a-finding", "unknown-finding")):
        _, _, missing = client.json(
            "GET", f"/api/v1/scans/{scan_id}/{endpoint}", expected={404},
            label=f"{label}-{profile.lower()}",
        )
        require(error_code(missing) == "SCAN_NOT_FOUND", f"{label} contract changed")

    report_bodies: dict[str, bytes] = {}
    for report_type, media in (
        ("html", "text/html"),
        ("json", "application/json"),
        ("sarif", "application/sarif+json"),
        ("archive", "application/zip"),
    ):
        _, headers, body = client.request(
            "GET", f"/api/v1/scans/{scan_id}/reports/{report_type}", expected={200},
            label=f"report-{profile.lower()}-{report_type}",
        )
        require(media in headers.get("Content-Type", ""), f"wrong {report_type} content type")
        require(scan_id in headers.get("Content-Disposition", ""), f"unsafe/missing {report_type} filename")
        report_bodies[report_type] = body
    require(b"<html" in report_bodies["html"].lower(), f"{profile} HTML report is invalid")
    report = json.loads(report_bodies["json"])
    sarif = json.loads(report_bodies["sarif"])
    require(report.get("summary", {}).get("uniqueFindingCount") == len(findings),
            f"{profile} report/finding count mismatch")
    require(len(report.get("engines", [])) == PROFILE_ENGINES[profile],
            f"{profile} report engine count mismatch")
    require(sarif.get("version") == "2.1.0", f"{profile} SARIF version is invalid")
    verify_archive(report_bodies["archive"], profile)

    status, _, cancelled = client.json(
        "POST", f"/api/v1/scans/{scan_id}/cancel", body=b"", expected={200},
        label=f"cancel-terminal-{profile.lower()}",
    )
    require(status == 200 and cancelled.get("status") == "COMPLETED",
            f"terminal cancel is not idempotent for {profile}")
    return {"scanId": scan_id, "findings": len(findings), "engines": len(engines)}


def malicious_archive() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("../escape.txt", "escape")
        archive.writestr("pom.xml", "<project/>")
    return output.getvalue()


def memory_archive(files: dict[str, str]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return output.getvalue()


def maven_pom(artifact: str, java_version: int) -> str:
    return f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion><groupId>example</groupId>
  <artifactId>{artifact}</artifactId><version>1.0</version>
  <properties><maven.compiler.release>{java_version}</maven.compiler.release></properties>
</project>"""


def verify_async_intake_failure(
    client: EvidenceClient, archive: bytes, expected_code: str, label: str
) -> None:
    _, _, payload = client.multipart(
        "/api/v1/scans/zip", archive, b'{"profile":"QUICK"}', expected={202}, label=label
    )
    scan_id = payload.get("scanId", "")
    terminal = wait_terminal(client, scan_id, label, client.timeout)
    require(terminal.get("status") == "FAILED", f"{label} did not fail: {terminal}")
    require(terminal.get("failure", {}).get("code") == expected_code,
            f"{label} returned the wrong failure: {terminal}")
    _, _, not_ready = client.json(
        "GET", f"/api/v1/scans/{scan_id}/reports/archive", expected={409},
        label=f"{label}-report-not-ready",
    )
    require(error_code(not_ready) == "REPORT_NOT_READY", f"{label} exposed a report")


def verify_error_contracts(client: EvidenceClient, project: bytes) -> None:
    _, _, payload = client.multipart(
        "/api/v1/scans/zip", b"", b'{"profile":"QUICK"}', expected={400}, label="empty-upload"
    )
    require(error_code(payload) == "INVALID_REQUEST", "empty upload error contract changed")
    _, _, payload = client.multipart(
        "/api/v1/scans/zip", project, b"{", expected={400}, label="malformed-request-json"
    )
    require(error_code(payload) == "INVALID_REQUEST", "malformed JSON error contract changed")
    _, _, payload = client.multipart(
        "/api/v1/scans/zip", project, b'{"profile":"NOPE"}', expected={400}, label="invalid-profile"
    )
    require(error_code(payload) == "INVALID_REQUEST", "invalid profile error contract changed")
    _, _, payload = client.multipart(
        "/api/v1/scans/zip", project,
        b'{"profile":"QUICK","mavenProfiles":["bad;profile"]}',
        expected={400}, label="invalid-maven-argument",
    )
    require(error_code(payload) == "INVALID_MAVEN_ARGUMENT", "Maven argument error contract changed")
    verify_async_intake_failure(
        client, malicious_archive(), "UNSAFE_ARCHIVE_ENTRY", "zip-path-traversal"
    )
    verify_async_intake_failure(
        client, memory_archive({"README.txt": "no Maven project"}),
        "NO_MAVEN_ROOT", "no-maven-root",
    )
    verify_async_intake_failure(
        client,
        memory_archive({"a/pom.xml": maven_pom("a", 17), "b/pom.xml": maven_pom("b", 17)}),
        "MULTIPLE_MAVEN_ROOTS", "multiple-maven-roots",
    )
    verify_async_intake_failure(
        client, memory_archive({"pom.xml": maven_pom("java21", 21)}),
        "UNSUPPORTED_JAVA_VERSION", "unsupported-java",
    )
    unknown = str(uuid.uuid4())
    _, _, payload = client.json(
        "GET", f"/api/v1/scans/{unknown}", expected={404}, label="unknown-scan"
    )
    require(error_code(payload) == "SCAN_NOT_FOUND", "unknown scan error contract changed")
    _, _, payload = client.json("GET", "/api/v1/scans/not-a-uuid", expected={400}, label="invalid-scan-id")
    require(error_code(payload) == "INVALID_REQUEST", "invalid UUID error contract changed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--project-zip", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    parser.add_argument("--profiles", nargs="+", choices=PROFILE_ENGINES, default=list(PROFILE_ENGINES))
    args = parser.parse_args()

    project = args.project_zip.read_bytes()
    client = EvidenceClient(args.base_url, args.evidence_dir, args.timeout_seconds)
    _, _, health = client.json("GET", "/api/v1/health", expected={200}, label="health")
    _, _, tools = client.json("GET", "/api/v1/tools", expected={200}, label="tools")
    _, _, profiles = client.json("GET", "/api/v1/profiles", expected={200}, label="profiles")
    require(isinstance(health, dict) and health.get("status") == "UP", f"platform health is not UP: {health}")
    profile_health = health.get("profiles", {})
    for profile in args.profiles:
        require(profile_health.get(profile) == "AVAILABLE", f"{profile} is unavailable: {health}")
    require(tools == health and profiles == health, "health/tools/profiles aliases diverged")

    verify_error_contracts(client, project)
    results = []
    for profile in args.profiles:
        scan_id = create_scan(client, project, profile, "self-audit")
        if not results:
            _, _, not_ready = client.json(
                "GET", f"/api/v1/scans/{scan_id}/reports/archive", expected={409},
                label="report-not-ready",
            )
            require(error_code(not_ready) == "REPORT_NOT_READY", "early report contract changed")
        results.append(verify_completed_scan(client, scan_id, profile))

    if "QUICK" in args.profiles:
        quick_id = results[args.profiles.index("QUICK")]["scanId"]
        client.request("DELETE", f"/api/v1/scans/{quick_id}", expected={204}, label="delete-terminal-quick")
        _, _, missing = client.json(
            "GET", f"/api/v1/scans/{quick_id}", expected={404}, label="deleted-scan"
        )
        require(error_code(missing) == "SCAN_NOT_FOUND", "deleted scan remains queryable")

    summary = {"baseUrl": args.base_url, "projectZip": str(args.project_zip), "results": results}
    (args.evidence_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ApiFailure, OSError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        print(f"PRODUCTION READINESS API FAILURE: {error}", file=sys.stderr)
        raise SystemExit(1)
