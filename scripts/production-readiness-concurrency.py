#!/usr/bin/env python3
"""Real HTTP concurrency, queue and cancellation acceptance for the release JAR."""

from __future__ import annotations

import argparse
import importlib.util
import json
import time
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--project-zip", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=20)
    parser.add_argument("--profile", choices=api.PROFILE_ENGINES, default="QUICK")
    parser.add_argument("--max-running", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    parser.add_argument("--expect-queue-full", action="store_true")
    parser.add_argument("--skip-cancel", action="store_true")
    args = parser.parse_args()

    project = args.project_zip.read_bytes()
    client = api.EvidenceClient(args.base_url, args.evidence_dir, args.timeout_seconds)
    accepted: list[str] = []
    rejected = 0
    retry_headers: list[str] = []
    for index in range(args.jobs):
        status, headers, payload = client.multipart(
            "/api/v1/scans/zip",
            project,
            json.dumps({"displayName": f"concurrent-{index:02d}", "profile": args.profile}).encode(),
            expected={202, 429} if args.expect_queue_full else {202},
            label=f"create-concurrent-{index:02d}",
        )
        if status == 202:
            accepted.append(payload["scanId"])
        else:
            rejected += 1
            api.require(api.error_code(payload) == "QUEUE_FULL", f"unexpected 429 body: {payload}")
            retry = headers.get("Retry-After", "")
            api.require(retry.isdigit() and int(retry) >= 1, "QUEUE_FULL has no valid Retry-After")
            retry_headers.append(retry)
    api.require(accepted, "no concurrent job was accepted")
    if args.expect_queue_full:
        api.require(rejected > 0, "queue-full run did not produce a 429")
    else:
        api.require(rejected == 0 and len(accepted) == args.jobs, "20-job run rejected work")

    terminal: dict[str, str] = {}
    max_observed_running = 0
    deadline = time.monotonic() + args.timeout_seconds
    while len(terminal) < len(accepted) and time.monotonic() < deadline:
        running = 0
        for scan_id in accepted:
            if scan_id in terminal:
                continue
            _, _, state = client.json(
                "GET", f"/api/v1/scans/{scan_id}", expected={200}, label=f"poll-{scan_id}"
            )
            status = state.get("status")
            if status == "RUNNING":
                running += 1
            if status in api.TERMINAL:
                terminal[scan_id] = status
        max_observed_running = max(max_observed_running, running)
        api.require(running <= args.max_running,
                    f"observed {running} running jobs, configured maximum is {args.max_running}")
        if len(terminal) < len(accepted):
            time.sleep(0.25)
    api.require(len(terminal) == len(accepted), "concurrent jobs did not all reach a terminal state")
    unexpected = {scan_id: status for scan_id, status in terminal.items() if status != "COMPLETED"}
    api.require(not unexpected, f"concurrent jobs failed: {unexpected}")

    cancel_result = None
    if not args.skip_cancel:
        scan_id = api.create_scan(client, project, "DEEP", "cancel-running")
        deadline = time.monotonic() + args.timeout_seconds
        running = False
        while time.monotonic() < deadline:
            _, _, state = client.json(
                "GET", f"/api/v1/scans/{scan_id}", expected={200}, label="cancel-poll-running"
            )
            if state.get("status") == "RUNNING":
                running = True
                break
            if state.get("status") in api.TERMINAL:
                break
            time.sleep(0.05)
        api.require(running, f"cancel fixture completed before reaching RUNNING: {state}")
        _, _, delete_error = client.json(
            "DELETE", f"/api/v1/scans/{scan_id}", expected={409}, label="delete-running"
        )
        api.require(api.error_code(delete_error) == "INVALID_SCAN_STATE", "running delete did not return 409")
        first_status, _, first = client.json(
            "POST", f"/api/v1/scans/{scan_id}/cancel", body=b"", expected={200, 202}, label="cancel-running"
        )
        second_status, _, second = client.json(
            "POST", f"/api/v1/scans/{scan_id}/cancel", body=b"", expected={200, 202}, label="cancel-idempotent"
        )
        state = api.wait_terminal(client, scan_id, "cancelled", args.timeout_seconds)
        api.require(state.get("status") == "CANCELLED", f"cancelled scan ended as {state.get('status')}")
        cancel_result = {
            "scanId": scan_id,
            "firstHttpStatus": first_status,
            "secondHttpStatus": second_status,
            "firstState": first.get("status"),
            "secondState": second.get("status"),
            "terminalState": state.get("status"),
        }

    summary = {
        "jobsRequested": args.jobs,
        "profile": args.profile,
        "jobsAccepted": len(accepted),
        "jobsRejected": rejected,
        "maxConfiguredRunning": args.max_running,
        "maxObservedRunning": max_observed_running,
        "retryAfterHeaders": retry_headers,
        "terminalStates": terminal,
        "cancel": cancel_result,
    }
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
        print(f"PRODUCTION READINESS CONCURRENCY FAILURE: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
