import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bootstrap
import netcheck

URL = 'https://uprootnetworks.com/wp-content/uploads/2026/10/diag-bootstrap-marker.txt'


class WorkflowTests(unittest.TestCase):
    def test_diagnose_requires_profile_before_network(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch('netcheck.CONFIG', Path(folder) / 'config.json'), \
             patch('sys.argv', ['netcheck.py', 'diagnose']), \
             patch('netcheck.diagnose') as diagnose:
            self.assertEqual(netcheck.main(), 1)
            diagnose.assert_not_called()

    def test_successful_init_installs_used_profile(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch('netcheck.CONFIG', Path(folder) / 'config.json'), \
             patch('netcheck.bootstrap.initialize') as initialize:
            netcheck.initialize(None)
            initialize.assert_called_once_with(None)
            self.assertEqual(netcheck.load_profile(), netcheck.PROFILE)
            netcheck.initialize(None)
            self.assertEqual(initialize.call_count, 1)

    def test_failed_bootstrap_leaves_uninitialized(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch('netcheck.CONFIG', Path(folder) / 'config.json'), \
             patch('netcheck.bootstrap.initialize', side_effect=ValueError('checksum')):
            with self.assertRaises(ValueError):
                netcheck.initialize(None)
            self.assertFalse(netcheck.CONFIG.exists())

    def test_altered_profile_rejected(self):
        with tempfile.TemporaryDirectory() as folder, patch('netcheck.CONFIG', Path(folder) / 'config.json'):
            changed = dict(netcheck.PROFILE, target='https://example.org/')
            netcheck.CONFIG.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                netcheck.load_profile()

    def test_changed_download_never_executes(self):
        with patch('bootstrap.subprocess.run') as run:
            with self.assertRaises(ValueError):
                bootstrap.execute_bootstrap(b'changed')
            run.assert_not_called()

    def test_txt_and_url_constraints(self):
        self.assertEqual(bootstrap.parse_txt('"v=1 url=' + URL + '"'), URL)
        for value in ('', '"v=1 url=http://uprootnetworks.com/x.txt"', '"v=1 url=https://example.org/x.txt"'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bootstrap.parse_txt(value)

    def test_base64_manifest_variants(self):
        for quoted in (False, True):
            manifest = 'v=1 url=' + URL
            if quoted:
                manifest = '"' + manifest + '"'
            encoded = base64.b64encode(manifest.encode('ascii')).decode('ascii')
            for value in (encoded, encoded.rstrip('=')):
                with self.subTest(quoted=quoted, value=value):
                    self.assertEqual(bootstrap.parse_txt('"' + value + '"'), URL)

    def test_encoded_manifest_still_rejects_unsafe_content(self):
        for manifest in ('echo hello', 'v=2 url=' + URL,
                         'v=1 url=https://example.org/script.txt',
                         'v=1 url=' + URL + ' extra=value', '\N{SNOWMAN}'):
            encoded = base64.b64encode(manifest.encode('utf-8')).decode('ascii')
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                bootstrap.parse_txt('"' + encoded + '"')
        for output in ('"!!!!"', '"A"', '"v=1 url=' + URL + '"\n"other"', 'x' * 8193):
            with self.subTest(output=output[:50]), self.assertRaises(ValueError):
                bootstrap.parse_txt(output)

    def test_preflight_does_not_execute_or_install_profile(self):
        body = b"set -euo pipefail\necho 'lol pwned!'\n"
        with tempfile.TemporaryDirectory() as folder, \
             patch('netcheck.CONFIG', Path(folder) / 'config.json'), \
             patch('bootstrap.resolve_url', return_value=URL), \
             patch('bootstrap.download_script', return_value=body), \
             patch('bootstrap.execute_bootstrap') as execute, \
             patch('sys.argv', ['netcheck.py', 'preflight']):
            self.assertEqual(netcheck.main(), 0)
            execute.assert_not_called()
            self.assertFalse(netcheck.CONFIG.exists())

    def test_child_failure_leaves_uninitialized(self):
        body = b"set -euo pipefail\necho 'lol pwned!'\n"
        with tempfile.TemporaryDirectory() as folder, \
             patch('netcheck.CONFIG', Path(folder) / 'config.json'), \
             patch('bootstrap.resolve_url', return_value=URL), \
             patch('bootstrap.download_script', return_value=body), \
             patch('bootstrap.subprocess.run', side_effect=subprocess.CalledProcessError(1, '/bin/bash')):
            with self.assertRaises(subprocess.CalledProcessError):
                netcheck.initialize(None)
            self.assertFalse(netcheck.CONFIG.exists())

    def test_download_failure_does_not_execute(self):
        with patch('bootstrap.resolve_url', return_value=URL), \
             patch('bootstrap.download_script', side_effect=OSError('offline')), \
             patch('bootstrap.execute_bootstrap') as execute:
            with self.assertRaises(OSError):
                bootstrap.initialize(None)
            execute.assert_not_called()

    def test_init_pipeline_runs_reviewed_fixture_then_saves_profile(self):
        body = b"printf '%s\\n' 'bootstrap complete'\n"
        with tempfile.TemporaryDirectory() as folder, \
             patch('netcheck.CONFIG', Path(folder) / 'config.json'), \
             patch('bootstrap.resolve_url', return_value=URL), \
             patch('bootstrap.download_script', return_value=body), \
             patch('bootstrap.EXPECTED_SHA256', hashlib.sha256(body).hexdigest()):
            netcheck.initialize(None)
            self.assertEqual(netcheck.load_profile(), netcheck.PROFILE)

    def test_no_redirects(self):
        self.assertIsNone(bootstrap.NoRedirects().redirect_request(None, None, 302, '', {}, 'https://example.org'))


if __name__ == '__main__':
    unittest.main()
