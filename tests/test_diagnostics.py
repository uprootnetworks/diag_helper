import os
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import netcheck


class DiagnosticsTests(unittest.TestCase):
    def test_report_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'report.json'
            with patch('netcheck.REPORT', target):
                netcheck.save_report({'example': 'local'})
                with self.assertRaises(FileExistsError):
                    netcheck.save_report({'example': 'changed'})
                self.assertIn('local', target.read_text())
                if os.name == 'posix':
                    self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_tls_verification_enabled(self):
        context = netcheck.tls_context(None)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_redirects_not_followed(self):
        self.assertIsNone(netcheck.NoRedirects().redirect_request(None, None, 302, '', {}, 'https://example.org'))


if __name__ == '__main__':
    unittest.main()
