"""Shared HTTPS trust and transport helpers."""
import ssl
import urllib.request
from pathlib import Path

CONTROL = "https://uprootnetworks.com/"
INTAKE = "https://uprootnetworks.com/wp-json/agentdemo/v1/diagnostics"


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def tls_context(ca_file=None):
    context = ssl.create_default_context()
    if ca_file:
        with Path(ca_file).open("rb") as source:
            data = source.read(262145)
        if len(data) > 262144:
            raise ValueError("Certificate file exceeds 256 KiB.")
        pem = data.decode("ascii") if b"-----BEGIN CERTIFICATE-----" in data else ssl.DER_cert_to_PEM_cert(data)
        context.load_verify_locations(cadata=pem)
    return context


def opener(context):
    return urllib.request.build_opener(NoRedirects(), urllib.request.HTTPSHandler(context=context))
