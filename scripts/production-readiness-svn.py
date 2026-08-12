#!/usr/bin/env python3
"""Black-box anonymous SVN HEAD and pinned-revision acceptance."""

from __future__ import annotations

import argparse
import importlib.util
import json
import io
import os
import urllib.parse
import zipfile
from pathlib import Path


def load_api_module():
    target = Path(__file__).with_name("production-readiness-api.py")
    spec = importlib.util.spec_from_file_location("production_readiness_api", target)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {target}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = load_api_module()


def submit(
    client, repository_url: str, revision: str, label: str, username: str = "", password: str = ""
) -> str:
    request = {
        "repositoryUrl": repository_url,
        "revision": revision,
        "displayName": label,
        "profile": "QUICK",
    }
    if username:
        request["username"] = username
        request["password"] = password
    body = json.dumps(request).encode()
    _, headers, payload = client.json(
        "POST", "/api/v1/scans/svn", body=body,
        headers={"Content-Type": "application/json"}, expected={202}, label=f"create-{label}",
    )
    scan_id = payload.get("scanId", "")
    api.require(headers.get("Location", "").endswith(scan_id), "SVN Location header is invalid")
    api.require(len(payload.get("plannedEngines", [])) == 6, "SVN Quick engine count is invalid")
    return scan_id


def source_report(client, scan_id: str, label: str) -> dict:
    state = api.wait_terminal(client, scan_id, label, client.timeout)
    api.require(state.get("status") == "COMPLETED", f"SVN {label} failed: {state}")
    archive = client.request(
        "GET", f"/api/v1/scans/{scan_id}/reports/archive", expected={200}, label=f"archive-{label}"
    )[2]
    api.verify_archive(archive, "QUICK")
    with zipfile.ZipFile(io.BytesIO(archive)) as report_archive:
        manifest = json.loads(report_archive.read("manifest.json"))
    source = manifest.get("source", {})
    api.require(source.get("type") == "SVN", f"SVN source metadata is missing: {source}")
    api.require(source.get("revision", "").startswith("svn:"), "SVN revision is not resolved")
    api.require(source.get("sha256", "").startswith("sha256:"), "SVN snapshot SHA is missing")
    return source


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--repository-url", required=True)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--username", default="")
    parser.add_argument("--password-env", default="AUDIT_TEST_SVN_PASSWORD")
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    args = parser.parse_args()

    client = api.EvidenceClient(args.base_url, args.evidence_dir, args.timeout_seconds)
    password = os.environ.get(args.password_env, "") if args.username else ""
    api.require(not args.username or password, f"{args.password_env} is required for authenticated SVN")
    head_id = submit(client, args.repository_url, "HEAD", "svn-head", args.username, password)
    head = source_report(client, head_id, "svn-head")
    revision = head["revision"].removeprefix("svn:")
    api.require(revision.isdigit(), f"resolved revision is invalid: {revision}")

    pinned_id = submit(client, args.repository_url, revision, "svn-pinned", args.username, password)
    pinned = source_report(client, pinned_id, "svn-pinned")
    api.require(pinned["revision"] == head["revision"], "pinned revision changed")
    api.require(pinned["sha256"] == head["sha256"], "pinned snapshot content changed")

    parsed = urllib.parse.urlsplit(args.repository_url)
    expected_origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port is not None:
        expected_origin += f":{parsed.port}"
    for source in (head, pinned):
        api.require(source.get("repositoryUrl") == expected_origin + "/***",
                    f"repository URL was not redacted: {source.get('repositoryUrl')}")
        api.require(source.get("repositoryUrlSha256", "").startswith("sha256:"),
                    "repository URL hash is missing")

    summary = {"headScanId": head_id, "pinnedScanId": pinned_id, "source": head}
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    (args.evidence_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (api.ApiFailure, OSError, json.JSONDecodeError) as error:
        print(f"PRODUCTION READINESS SVN FAILURE: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
