#!/usr/bin/env python3
"""Collect real network diagnostics, or read external troubleshooting guidance."""

import argparse
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TARGET = "https://uprootnetworks.com/"
HOST = "uprootnetworks.com"
GUIDANCE = "https://uprootnetworks.com/wp-content/uploads/2026/10/setup-profile-2.txt"
MAX_BYTES = 32768
REPORT = Path("diagnostic-report.json")


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def tls_context(ca_file):
    context = ssl.create_default_context()
    if ca_file:
        with Path(ca_file).open("rb") as certificate:
            data = certificate.read(262145)
        if len(data) > 262144:
            raise ValueError("Certificate file is too large.")
        if b"-----BEGIN CERTIFICATE-----" in data:
            pem = data.decode("ascii")
        else:
            pem = ssl.DER_cert_to_PEM_cert(data)
        context.load_verify_locations(cadata=pem)
    return context


def opener_for(context):
    return urllib.request.build_opener(
        NoRedirects(), urllib.request.HTTPSHandler(context=context)
    )


def plain_text(text):
    return "".join(c if c.isprintable() or c in "\n\t" else "?" for c in text)


def resolver_settings():
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/usr/sbin/scutil", "--dns"],
                capture_output=True, text=True, check=True, timeout=5,
            )
            # Keep only fields useful to diagnosis; do not collect arbitrary files.
            lines = [line.strip() for line in result.stdout.splitlines()
                     if any(key in line for key in ("nameserver[", "search domain[", "domain :"))]
            return plain_text("\n".join(dict.fromkeys(lines)))[:8192]
        except (OSError, subprocess.SubprocessError):
            return "Resolver settings unavailable."
    if sys.platform.startswith("linux"):
        try:
            with Path("/etc/resolv.conf").open() as resolvers:
                lines = resolvers.read(8192).splitlines()
            return plain_text("\n".join(line for line in lines
                              if line.startswith(("nameserver ", "search ", "domain "))))
        except OSError:
            return "Resolver settings unavailable."
    return "Resolver collection is supported on macOS and Linux."


def diagnose(context):
    report = {
        "schema": "network-triage-v1",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "workstation": {"hostname": socket.gethostname(),
                        "os": platform.system(), "release": platform.release()},
        "resolver_settings": resolver_settings(),
        "target": TARGET,
    }
    try:
        addresses = sorted({row[4][0] for row in socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)})
        report["dns"] = {"status": "resolved", "addresses": addresses}
    except OSError as error:
        report["dns"] = {"status": "error", "detail": plain_text(str(error))[:1000]}
    request = urllib.request.Request(TARGET, method="HEAD", headers={"User-Agent": "NetworkTriage/2.0"})
    try:
        with opener_for(context).open(request, timeout=10) as response:
            report["https"] = {"status": "verified", "http_status": response.status}
    except urllib.error.HTTPError as error:
        # A valid HTTPS response with a non-2xx status still establishes TLS success.
        report["https"] = {"status": "verified", "http_status": error.code}
        error.close()
    except (OSError, urllib.error.URLError) as error:
        report["https"] = {"status": "error", "detail": plain_text(str(error))[:1000]}
    return report


def save_report(report):
    data = (json.dumps(report, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_BYTES:
        raise ValueError("Report exceeds the size limit.")
    # A new, private file; do not overwrite an existing report or follow a symlink.
    fd = os.open(REPORT, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def guidance(context):
    request = urllib.request.Request(GUIDANCE, headers={"Accept": "text/plain", "User-Agent": "NetworkTriage/2.0"})
    with opener_for(context).open(request, timeout=10) as response:
        if response.headers.get_content_type() != "text/plain":
            raise ValueError("Expected plain-text troubleshooting instructions.")
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES or not body.strip():
        raise ValueError("Troubleshooting instructions are empty or too large.")
    return plain_text(body.decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-file", help="Approved additional root certificate (PEM or DER)")
    parser.add_argument("command", choices=("diagnose", "guidance"))
    args = parser.parse_args()
    try:
        context = tls_context(args.ca_file)
        if args.command == "guidance":
            print(f"Troubleshooting instructions from {GUIDANCE}\n")
            print(guidance(context))
        else:
            report = diagnose(context)
            save_report(report)
            print(f"Saved real diagnostic results to {REPORT}.")
            print(f"DNS: {report['dns']['status']}")
            print(f"HTTPS: {report['https']['status']}")
            if report["https"]["status"] == "error":
                print(report["https"]["detail"])
            print("The report includes workstation and resolver information. It has not been uploaded.")
    except (OSError, ValueError, urllib.error.URLError) as error:
        print(f"Network Triage: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
