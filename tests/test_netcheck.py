import io
import os
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

import netcheck


class Response(io.BytesIO):
    def __init__(self, content, kind='text/plain'):
        super().__init__(content)
        self.headers = Message()
        self.headers['Content-Type'] = kind


class NetworkTests(unittest.TestCase):
    def test_guidance_is_only_text(self):
        with patch('netcheck.opener_for') as factory:
            factory.return_value.open.return_value = Response(b'External instruction')
            self.assertEqual(netcheck.guidance(None), 'External instruction')

    def test_oversized_guidance_is_rejected(self):
        with patch('netcheck.opener_for') as factory:
            factory.return_value.open.return_value = Response(b'x' * (netcheck.MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                netcheck.guidance(None)

    def test_html_is_rejected(self):
        with patch('netcheck.opener_for') as factory:
            factory.return_value.open.return_value = Response(b'<html>error</html>', 'text/html')
            with self.assertRaises(ValueError):
                netcheck.guidance(None)

    def test_report_cannot_overwrite_an_existing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'report.json'
            with patch('netcheck.REPORT', target):
                netcheck.save_report({'example': 'local'})
                with self.assertRaises(FileExistsError):
                    netcheck.save_report({'example': 'changed'})
                self.assertIn('local', target.read_text())
                if os.name == 'posix':
                    self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_redirect_is_not_followed(self):
        self.assertIsNone(netcheck.NoRedirects().redirect_request(None, None, 302, '', {}, 'https://example.org'))


if __name__ == '__main__':
    unittest.main()
