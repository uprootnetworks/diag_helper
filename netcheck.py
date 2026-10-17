#!/usr/bin/env python3
"""Initialize Diag Helper and collect workstation DNS and HTTPS diagnostics."""

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

import bootstrap

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / ".diag-helper.json"
REPORT = Path("diagnostic-report.json")
MAX_BYTES = 32768
PROFILE = {"schema": 1, "target": "https://uprootnetworks.com/",
           "host": "uprootnetworks.com", "timeout": 10}


def load_profile():
    try:
        with CONFIG.open("rb") as source:
            data = source.read(4097)
    except FileNotFoundError:
        raise ValueError("Diag Helper is not initialized. Run: python3 netcheck.py init (include --ca-file if required).") from None
    if len(data) > 4096:
        raise ValueError("Diagnostic profile is too large.")
    profile = json.loads(data)
    if profile != PROFILE:
        raise ValueError("Diagnostic profile is invalid or unsupported.")
    return profile


def initialize(context):
    if CONFIG.exists():
        load_profile()
        print("Diag Helper is already initialized.")
        return
    bootstrap.initialize(context)
    # Do not mark initialization complete if download, verification or execution failed.
    encoded = (json.dumps(PROFILE, indent=2) + "\n").encode("utf-8")
    fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(encoded)
    print("Initialization complete. Diagnostic profile installed.")


def tls_context(ca_file):
    context = ssl.create_default_context()
    if ca_file:
        with Path(ca_file).open("rb") as certificate:
            data = certificate.read(262145)
        if len(data) > 262144:
            raise ValueError("Certificate file is too large.")
        pem = data.decode("ascii") if b"-----BEGIN CERTIFICATE-----" in data else ssl.DER_cert_to_PEM_cert(data)
        context.load_verify_locations(cadata=pem)
    return context


def opener_for(context):
    return urllib.request.build_opener(bootstrap.NoRedirects(), urllib.request.HTTPSHandler(context=context))


def plain_text(text):
    return "".join(c if c.isprintable() or c in "\n\t" else "?" for c in text)


def resolver_settings():
    if sys.platform == "darwin":
        try:
            result = subprocess.run(["/usr/sbin/scutil", "--dns"], capture_output=True,
                                    text=True, check=True, timeout=5)
            lines = [line.strip() for line in result.stdout.splitlines()
                     if any(key in line for key in ("nameserver[", "search domain[", "domain :"))]
            return plain_text("\n".join(dict.fromkeys(lines)))[:8192]
        except (OSError, subprocess.SubprocessError):
            return "Resolver settings unavailable."
    if sys.platform.startswith("linux"):
        try:
            with Path("/etc/resolv.conf").open() as source:
                lines = source.read(8192).splitlines()
            return plain_text("\n".join(line for line in lines if line.startswith(("nameserver ", "search ", "domain "))))
        except OSError:
            return "Resolver settings unavailable."
    return "Resolver collection supports macOS and Linux."


def diagnose(context, profile):
    report = {"schema": "network-triage-v1", "collected_at": datetime.now(timezone.utc).isoformat(),
              "workstation": {"hostname": socket.gethostname(), "os": platform.system(), "release": platform.release()},
              "resolver_settings": resolver_settings(), "target": profile["target"]}
    try:
        addresses = sorted({row[4][0] for row in socket.getaddrinfo(profile["host"], 443, type=socket.SOCK_STREAM)})
        report["dns"] = {"status": "resolved", "addresses": addresses}
    except OSError as error:
        report["dns"] = {"status": "error", "detail": plain_text(str(error))[:1000]}
    request = urllib.request.Request(profile["target"], method="HEAD", headers={"User-Agent": "DiagHelper/4.0"})
    try:
        with opener_for(context).open(request, timeout=profile["timeout"]) as response:
            report["https"] = {"status": "verified", "http_status": response.status}
    except urllib.error.HTTPError as error:
        report["https"] = {"status": "verified", "http_status": error.code}
        error.close()
    except (OSError, urllib.error.URLError) as error:
        report["https"] = {"status": "error", "detail": plain_text(str(error))[:1000]}
    return report


def save_report(report):
    data = (json.dumps(report, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_BYTES:
        raise ValueError("Report exceeds the size limit.")
    fd = os.open(REPORT, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-file", help="Approved additional root certificate (PEM or DER)")
    parser.add_argument("command", choices=("init", "diagnose", "preflight"))
    args = parser.parse_args()
    try:
        # Validate the installed target profile before any diagnostic network access.
        profile = load_profile() if args.command == "diagnose" else None
        context = tls_context(args.ca_file)
        if args.command == "init":
            initialize(context)
        elif args.command == "preflight":
            bootstrap.initialize(context, check_only=True)
        else:
            report = diagnose(context, profile)
            save_report(report)
            print(f"Saved diagnostic results to {REPORT}.")
            print(f"DNS: {report['dns']['status']}")
            print(f"HTTPS: {report['https']['status']}")
            if report["https"]["status"] == "error":
                print(report["https"]["detail"])
            print("Report stays local and includes workstation and resolver information.")
    except (OSError, ValueError, urllib.error.URLError, subprocess.SubprocessError) as error:
        print(f"Diag Helper: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
