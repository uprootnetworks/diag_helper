#!/usr/bin/env python3
"""Troubleshoot HTTPS connectivity and collect a local support report."""
import argparse
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from common import CONTROL, INTAKE, tls_context
from diagnostics import normalize_target
from support_upload import validate_summary

ROOT = Path(__file__).resolve().parent


def save_json(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(data, output, indent=2)
        output.write("\n")


def child_args(name, ca_file):
    command = [sys.executable, "-B", str(ROOT / name)]
    if ca_file:
        command.extend(["--ca-file", str(ca_file)])
    return command


def run_probe(target, ca_file, samples, timeout):
    command = child_args("diagnostics.py", ca_file) + ["--samples", str(samples), "--timeout", str(timeout), target]
    try:
        child = subprocess.run(command, capture_output=True, text=True, check=True,
                               timeout=10 + timeout * (samples * 2 + 2))
        result = json.loads(child.stdout)
        if not isinstance(result, dict) or result.get("target") != target or not isinstance(result.get("findings"), list):
            raise ValueError("Invalid diagnostic worker result.")
        return result
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = error.stderr if isinstance(error, subprocess.CalledProcessError) else str(error)
        return {"target": target, "worker_error": str(detail)[:600],
                "findings": ["Diagnostic worker failed or exceeded its time limit; see the local report."]}


def effective_https(check):
    return check.get("https_with_approved_ca") or check.get("https_current_trust", [])


def make_summary(report):
    checks = report["checks"]
    control = next(check for check in checks if check["target"] == CONTROL)
    def failed(check, phase):
        if phase == "dns":
            return check.get("dns", {}).get("status") != "resolved"
        results = effective_https(check)
        return not results or any(row["status"] != "verified" for row in results)
    summary = {
        "schema": "network-triage-v1", "collected_at": report["started_utc"], "target": CONTROL,
        "workstation": {"hostname": "not-collected", "os": "not-collected", "release": "not-collected"},
        "resolver_settings": "not-collected",
        "dns": {"status": "error" if failed(control, "dns") else "resolved",
                "targets_checked": len(checks), "targets_with_errors": sum(failed(c, "dns") for c in checks)},
        "https": {"status": "error" if failed(control, "https") else "verified",
                  "targets_checked": len(checks), "targets_with_errors": sum(failed(c, "https") for c in checks)},
    }
    return validate_summary(summary)


def submit_summary(summary, ca_file):
    try:
        child = subprocess.run(child_args("support_upload.py", ca_file),
                               input=json.dumps(summary), capture_output=True, text=True,
                               check=True, timeout=20)
        receipt = json.loads(child.stdout)
        if (not isinstance(receipt, dict) or receipt.get("accepted") is not True
                or not isinstance(receipt.get("receipt"), str)
                or uuid.UUID(receipt["receipt"]).version != 4):
            raise ValueError("Invalid support receipt.")
        return {"status": "accepted", **receipt}
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = error.stderr if isinstance(error, subprocess.CalledProcessError) else str(error)
        return {"status": "error", "detail": str(detail)[:600]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*", help="HTTPS URLs or hostnames (up to five)")
    parser.add_argument("--ca-file", type=Path, help="Approved additional root certificate, PEM or DER")
    parser.add_argument("--samples", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--timeout", type=int, choices=range(1, 16), default=5)
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()
    if len(args.targets) > 5:
        parser.error("Specify at most five targets.")
    try:
        targets = list(dict.fromkeys([normalize_target(value) for value in args.targets] + [CONTROL]))
        ca_file = args.ca_file.resolve() if args.ca_file else None
        tls_context(ca_file)
        started = datetime.now(timezone.utc)
        run_id = started.strftime("%Y%m%dT%H%M%SZ") + "-" + str(uuid.uuid4())
        args.output_dir.mkdir(parents=True, exist_ok=True)
        folder = args.output_dir / run_id
        folder.mkdir(mode=0o700)
        report = {"schema": "connectivity-support-v2", "run_id": run_id,
                  "started_utc": started.isoformat(), "checks": []}
        print(f"Report ID: {run_id}", flush=True)
        for target in targets:
            print(f"Checking {target}", flush=True)
            check = run_probe(target, ca_file, args.samples, args.timeout)
            report["checks"].append(check)
            for finding in check["findings"]:
                print(f"  {finding}", flush=True)
        summary = make_summary(report)
        save_json(folder / "support-summary.json", summary)
        print(f"Submitting minimized support summary to {INTAKE}", flush=True)
        report["support"] = submit_summary(summary, ca_file)
        if report["support"]["status"] == "accepted":
            print(f"Support receipt: {report['support']['receipt']}", flush=True)
        else:
            print("Support submission failed; diagnostic findings remain available locally.", flush=True)
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save_json(folder / "diagnostic-report.json", report)
        print(f"Local report: {(folder / 'diagnostic-report.json').resolve()}")
        if report["support"]["status"] == "error":
            return 2
        return 1 if any("worker_error" in check for check in report["checks"]) else 0
    except (OSError, ValueError) as error:
        print(f"Diag Helper: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
