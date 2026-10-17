import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import diagnostics
import netcheck
import support_upload
from common import CONTROL


def healthy(target=CONTROL):
    return {"target": target, "dns": {"status": "resolved", "addresses": ["192.0.2.1"]},
            "tcp": {"status": "connected"},
            "https_current_trust": [{"status": "verified", "http_status": 200, "elapsed_ms": 100}],
            "findings": ["Connected."]}


class SupportTests(unittest.TestCase):
    def test_target_validation_before_network(self):
        self.assertEqual(diagnostics.normalize_target("example.com"), "https://example.com/")
        for target in ("http://example.com/", "https://user:secret@example.com/", "https://example.com/?key=secret",
                       "https://example.com/#secret", "https://example.com:99999", "example.com\n"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                diagnostics.normalize_target(target)

    def test_certificate_comparison_produces_specific_finding(self):
        report = healthy()
        report["https_with_approved_ca"] = report["https_current_trust"]
        report["https_current_trust"] = [{"status": "error", "error_kind": "certificate_trust", "elapsed_ms": 10}]
        self.assertTrue(any("approved CA verifies" in row for row in diagnostics.findings(report)))

    def test_http_denial_is_not_reported_as_healthy(self):
        report = healthy()
        report["https_current_trust"][0]["http_status"] = 403
        result = diagnostics.findings(report)
        self.assertTrue(any("access-policy" in row for row in result))
        self.assertFalse(any("requests succeeded" in row for row in result))

    def test_summary_does_not_contain_private_target_or_raw_errors(self):
        private = healthy("https://private.internal/secret-path")
        private["dns"] = {"status": "error", "detail": "internal DNS detail"}
        summary = netcheck.make_summary({"started_utc": "2026-10-17T00:00:00+00:00",
                                        "checks": [private, healthy()]})
        encoded = json.dumps(summary)
        for value in ("private.internal", "secret-path", "internal DNS detail", "192.0.2.1"):
            self.assertNotIn(value, encoded)
        self.assertEqual(summary["dns"]["targets_with_errors"], 1)

    def test_extra_upload_fields_never_open_connection(self):
        summary = netcheck.make_summary({"started_utc": "2026-10-17T00:00:00+00:00", "checks": [healthy()]})
        summary["dns"]["detail"] = "private information"
        with patch("support_upload.opener") as network:
            with self.assertRaises(ValueError):
                support_upload.send(summary, None)
            network.assert_not_called()

    def test_failed_probe_is_reported_and_summary_records_failure(self):
        with patch("netcheck.subprocess.run", side_effect=subprocess.TimeoutExpired("worker", 30)):
            result = netcheck.run_probe(CONTROL, None, 3, 5)
        self.assertIn("worker_error", result)
        summary = netcheck.make_summary({"started_utc": "2026-10-17T00:00:00+00:00", "checks": [result]})
        self.assertEqual(summary["https"]["status"], "error")

    def test_submission_is_attempted_and_failed_submission_keeps_diagnostics(self):
        for status in ("accepted", "error"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as folder, \
                 patch("netcheck.tls_context"), patch("netcheck.run_probe", return_value=healthy()), \
                 patch("netcheck.submit_summary", return_value={"status": status, "receipt": "test-receipt"}) as submit:
                command = ["netcheck.py", "--output-dir", folder]
                with patch("sys.argv", command):
                    self.assertEqual(netcheck.main(), 0 if status == "accepted" else 2)
                submit.assert_called_once()
                reports = list(Path(folder).glob("*/diagnostic-report.json"))
                self.assertEqual(len(reports), 1)
                self.assertEqual(reports[0].stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(reports[0].read_text())["checks"][0]["target"], CONTROL)


if __name__ == "__main__":
    unittest.main()
