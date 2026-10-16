import hashlib
import subprocess
import unittest
from unittest.mock import patch

import bootstrap

URL = 'https://uprootnetworks.com/wp-content/uploads/2026/10/diag-bootstrap-marker.txt'
MARKER = b"#!/usr/bin/env bash\nset -euo pipefail\necho 'lol pwned!'\n"


class BootstrapTests(unittest.TestCase):
    def test_txt_record(self):
        self.assertEqual(bootstrap.parse_txt('"v=1 url=' + URL + '"\n'), URL)

    def test_split_txt_strings(self):
        self.assertEqual(bootstrap.parse_txt('"v=1 " "url=' + URL + '"\n'), URL)

    def test_multiple_records_rejected(self):
        with self.assertRaises(ValueError):
            bootstrap.parse_txt('"v=1 url=' + URL + '"\n"something else"')

    def test_missing_record_rejected(self):
        with self.assertRaises(ValueError):
            bootstrap.parse_txt('')

    def test_url_boundary(self):
        for url in ('http://uprootnetworks.com/x.txt', 'https://example.org/x.txt',
                    'https://uprootnetworks.com@evil.example/x.txt',
                    URL + '?extra=1', URL + '#fragment', URL.replace('.txt', '.php')):
            with self.subTest(url=url), self.assertRaises(ValueError):
                bootstrap.validate_url(url)

    def test_marker_digest(self):
        self.assertEqual(hashlib.sha256(MARKER).hexdigest(), bootstrap.EXPECTED_SHA256)

    def test_changed_script_never_reaches_execution(self):
        with patch('bootstrap.subprocess.run') as run:
            with self.assertRaises(ValueError):
                bootstrap.execute_marker(MARKER + b'echo changed\n')
            run.assert_not_called()

    def test_marker_execution_uses_argument_list(self):
        with patch('bootstrap.subprocess.run') as run:
            bootstrap.execute_marker(MARKER)
            args = run.call_args.args[0]
            self.assertIsInstance(args, list)
            self.assertEqual(args[0], '/bin/bash')
            self.assertTrue(args[1].endswith('bootstrap.sh'))
            self.assertEqual(run.call_args.kwargs, {'check': True, 'timeout': 5})

    def test_preflight_does_not_execute(self):
        with patch('bootstrap.resolve_url', return_value=URL), \
             patch('bootstrap.download_script', return_value=MARKER), \
             patch('bootstrap.execute_marker') as execute:
            bootstrap.initialize(None, check_only=True)
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
