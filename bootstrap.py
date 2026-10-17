"""Resolve and verify the release bootstrap."""

import base64
import binascii
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

RECORD = "_diag-bootstrap.uprootnetworks.com"
EXPECTED_SHA256 = "742a8dd269215c8de79b37c64e1be7e2f1d24d58983b9afeac6484a075d5791b"
MAX_SCRIPT_BYTES = 4096


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "uprootnetworks.com"
            or parsed.query or parsed.fragment
            or not re.fullmatch(r"/wp-content/uploads/[0-9]{4}/[0-9]{2}/[A-Za-z0-9._-]+\.txt", parsed.path)):
        raise ValueError("Bootstrap URL must be an HTTPS text-file upload on uprootnetworks.com.")
    return url


def parse_txt(output):
    if len(output) > 8192:
        raise ValueError("DNS response is too large.")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError(f"Expected exactly one TXT record at {RECORD}.")
    text = "".join(shlex.split(lines[0]))
    if not text.startswith("v=1 "):
        # A TXT record may encode the manifest, never a shell command.
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
            raise ValueError("TXT must contain a plain-text or Base64 v=1 URL manifest.")
        try:
            text = base64.b64decode(text + "=" * (-len(text) % 4), validate=True).decode("ascii")
        except (binascii.Error, UnicodeDecodeError) as error:
            raise ValueError("Invalid Base64 bootstrap manifest.") from error
        # Accept records encoded with their surrounding DNS presentation quotes.
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
    parts = text.split()
    if len(parts) != 2 or parts[0] != "v=1" or not parts[1].startswith("url="):
        raise ValueError("Decoded TXT format must be: v=1 url=https://uprootnetworks.com/...")
    return validate_url(parts[1][4:])


def resolve_url():
    dig = shutil.which("dig")
    if not dig:
        raise ValueError("dig is required; it is included with macOS.")
    result = subprocess.run(
        [dig, "+time=3", "+tries=1", "+short", "TXT", RECORD],
        capture_output=True, text=True, check=True, timeout=8,
    )
    return parse_txt(result.stdout)


def download_script(url, context):
    validate_url(url)
    opener = urllib.request.build_opener(NoRedirects(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, headers={"Accept": "text/plain", "User-Agent": "DiagHelper/4.1"})
    with opener.open(request, timeout=10) as response:
        if response.headers.get_content_type() != "text/plain":
            raise ValueError("Bootstrap file must be served as text/plain.")
        body = response.read(MAX_SCRIPT_BYTES + 1)
    if len(body) > MAX_SCRIPT_BYTES:
        raise ValueError("Bootstrap file is too large.")
    return body


def verify_script(body):
    if hashlib.sha256(body).hexdigest() != EXPECTED_SHA256:
        raise ValueError("Bootstrap checksum mismatch. Nothing will execute.")


def execute_bootstrap(body):
    verify_script(body)
    with tempfile.TemporaryDirectory(prefix="diag-helper-") as folder:
        script = Path(folder) / "bootstrap.sh"
        script.write_bytes(body)
        script.chmod(0o600)
        # Only the previously reviewed, pinned script can reach execution.
        # Exclude shell startup hooks such as BASH_ENV from the child environment.
        subprocess.run(["/bin/bash", "--noprofile", "--norc", str(script)],
                       env={"PATH": os.defpath, "LANG": "C"}, check=True, timeout=5)


def initialize(context, check_only=False):
    print(f"Reading bootstrap manifest: TXT {RECORD}", flush=True)
    url = resolve_url()
    print(f"Downloading bootstrap: {url}", flush=True)
    body = download_script(url, context)
    verify_script(body)
    print(f"Bootstrap SHA-256 verified: {EXPECTED_SHA256}", flush=True)
    if check_only:
        print("Preflight complete. Script was not executed.", flush=True)
        return
    print("Running verified bootstrap.", flush=True)
    execute_bootstrap(body)
