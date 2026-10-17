"""Submit the minimized connectivity summary and return its intake receipt."""
import argparse
import json
import sys
import uuid
from datetime import datetime
import urllib.request
import urllib.error

from common import CONTROL, INTAKE, opener, tls_context


def validate_summary(data):
    keys = {"schema", "collected_at", "workstation", "resolver_settings", "target", "dns", "https"}
    if not isinstance(data, dict) or set(data) != keys:
        raise ValueError("Invalid support summary fields.")
    if data["schema"] != "network-triage-v1" or data["target"] != CONTROL:
        raise ValueError("Unsupported support summary.")
    if data["workstation"] != {"hostname": "not-collected", "os": "not-collected", "release": "not-collected"} or data["resolver_settings"] != "not-collected":
        raise ValueError("Support summaries must exclude workstation and resolver details.")
    if not isinstance(data["collected_at"], str) or len(data["collected_at"]) > 64:
        raise ValueError("Invalid collection time.")
    datetime.fromisoformat(data["collected_at"])
    for key, statuses in (("dns", ("resolved", "error")), ("https", ("verified", "error"))):
        value = data[key]
        if not isinstance(value, dict) or set(value) != {"status", "targets_checked", "targets_with_errors"}:
            raise ValueError("Only aggregate counts may be submitted.")
        if (value["status"] not in statuses or type(value["targets_checked"]) is not int
                or type(value["targets_with_errors"]) is not int
                or not 0 <= value["targets_with_errors"] <= value["targets_checked"] <= 6):
            raise ValueError("Invalid diagnostic counts.")
    return data


def send(data, context):
    validate_summary(data)
    payload = (json.dumps(data, sort_keys=True) + "\n").encode("utf-8")
    request = urllib.request.Request(INTAKE, data=payload, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "DiagHelper/5.0",
    })
    with opener(context).open(request, timeout=10) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/json":
            raise ValueError("Unexpected support intake response.")
        body = response.read(4097)
    if len(body) > 4096:
        raise ValueError("Support response too large.")
    receipt = json.loads(body)
    if (not isinstance(receipt, dict) or receipt.get("accepted") is not True
            or receipt.get("report_stored_by_plugin") is not False
            or type(receipt.get("received_bytes")) is not int
            or receipt["received_bytes"] != len(payload)
            or not isinstance(receipt.get("receipt"), str)
            or uuid.UUID(receipt["receipt"]).version != 4):
        raise ValueError("Support intake did not confirm the submission.")
    return {key: receipt[key] for key in ("accepted", "receipt", "received_bytes", "report_stored_by_plugin")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-file")
    args = parser.parse_args()
    try:
        body = sys.stdin.buffer.read(32769)
        if len(body) > 32768:
            raise ValueError("Support summary too large.")
        print(json.dumps(send(json.loads(body), tls_context(args.ca_file))))
    except (OSError, ValueError, urllib.error.URLError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
