"""Collect bounded DNS, direct TCP and HTTPS samples for a requested target."""
import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from common import opener, tls_context


def normalize_target(value):
    if len(value) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("Target contains whitespace/control characters or is too long.")
    parsed = urllib.parse.urlsplit(value if "://" in value else "https://" + value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError("Use an HTTPS URL or hostname without credentials, queries or fragments.")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid target port.")
    parsed.hostname.encode("idna")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def error_kind(error):
    reason = getattr(error, "reason", error)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "certificate_trust"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(reason, socket.gaierror):
        return "dns"
    return "connection"


def https_sample(url, context, timeout):
    started = time.monotonic()
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "DiagHelper/5.0"})
    try:
        with opener(context).open(request, timeout=timeout) as response:
            result = {"status": "verified", "http_status": response.status}
    except urllib.error.HTTPError as error:
        # An HTTP error still proves that the HTTPS handshake verified.
        result = {"status": "verified", "http_status": error.code}
        error.close()
    except (OSError, urllib.error.URLError) as error:
        result = {"status": "error", "error_kind": error_kind(error),
                  "detail": "".join(c if c.isprintable() else "?" for c in str(error))[:600]}
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def findings(report):
    items = []
    if report["dns"]["status"] != "resolved":
        items.append("DNS resolution failed. Check the hostname, resolver and VPN connection.")
    current = report["https_current_trust"]
    approved = report.get("https_with_approved_ca", [])
    if (any(row.get("error_kind") == "certificate_trust" for row in current)
            and approved and all(row["status"] == "verified" for row in approved)):
        items.append("Current Python trust fails while the approved CA verifies. Use that CA with this application; keep TLS verification enabled.")
    effective = approved or current
    failures = sum(row["status"] == "error" for row in effective)
    if 0 < failures < len(effective):
        items.append("Samples show inconsistent HTTPS connectivity. Repeat during the incident and compare VPN/proxy paths.")
    elif failures == len(effective):
        items.append("HTTPS failed for every sample. Use the recorded error types to check TLS trust, proxy, VPN or firewall policy.")
    codes = {row.get("http_status") for row in effective}
    if any(code in (401, 403, 407) for code in codes):
        items.append("HTTPS connected but an authentication/access-policy response was returned. Check application, proxy or access-policy authorization.")
    if any(isinstance(code, int) and code >= 500 for code in codes):
        items.append("The HTTPS endpoint returned a server-side error. Check service health and reverse-proxy logs.")
    if any(isinstance(code, int) and 300 <= code < 400 for code in codes):
        items.append("The requested URL redirects. Test the intended final URL explicitly; redirects were not followed.")
    if any(code == 405 for code in codes):
        items.append("The server rejects HEAD requests. TLS is verified, but this check cannot establish application availability.")
    if report["tcp"]["status"] == "error" and any(row["status"] == "verified" for row in effective):
        items.append("Direct TCP failed while HTTPS succeeded. Check whether HTTPS uses an allowed proxy path.")
    if (not failures and report["dns"]["status"] == "resolved"
            and all(isinstance(row.get("http_status"), int) and 200 <= row["http_status"] < 300 for row in effective)):
        trust_label = " with the approved CA" if approved else " with current Python trust"
        items.append(f"DNS and sampled HTTPS requests succeeded{trust_label}. Investigate application-specific behavior or repeat while the failure is occurring.")
    if effective and max(row["elapsed_ms"] for row in effective) > 3000:
        items.append("At least one HTTPS request exceeded three seconds. Compare timing during and outside the incident.")
    return items


def probe(url, ca_file=None, samples=3, timeout=5):
    url = normalize_target(url)
    parsed = urllib.parse.urlsplit(url)
    current = tls_context()
    approved = tls_context(ca_file) if ca_file else None
    report = {"target": url, "https_proxy_configured": bool(urllib.request.getproxies().get("https")),
              "python_trust_override_present": bool(os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR")),
              "requests_ca_override_present": bool(os.environ.get("REQUESTS_CA_BUNDLE"))}
    try:
        addresses = sorted({row[4][0] for row in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)})
        report["dns"] = {"status": "resolved", "addresses": addresses}
    except OSError as error:
        report["dns"] = {"status": "error", "error_kind": error_kind(error)}
    try:
        started = time.monotonic()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=timeout):
            report["tcp"] = {"status": "connected", "elapsed_ms": round((time.monotonic() - started) * 1000)}
    except OSError as error:
        report["tcp"] = {"status": "error", "error_kind": error_kind(error)}
    report["https_current_trust"] = [https_sample(url, current, timeout) for _ in range(samples)]
    if approved:
        report["https_with_approved_ca"] = [https_sample(url, approved, timeout) for _ in range(samples)]
    report["findings"] = findings(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--ca-file")
    parser.add_argument("--samples", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--timeout", type=int, choices=range(1, 16), default=5)
    args = parser.parse_args()
    try:
        print(json.dumps(probe(args.target, args.ca_file, args.samples, args.timeout)))
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
