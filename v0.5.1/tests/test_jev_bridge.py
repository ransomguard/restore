import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ransomguard.jev import JevClient, JevConfig, JevConfigurationError, JevResponseError, JevTransportError


@unittest.skipUnless(os.name == 'nt', 'Windows bridge invocation')
class JevBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.exe = Path(self.temp.name)/'JevBridge.exe'
        self.exe.write_bytes(b'test placeholder; subprocess is mocked')
        self.env = patch.dict(os.environ, {'RANSOMGUARD_JEV_BRIDGE': str(self.exe), 'TYPESAFE_API_KEY': ''})
        self.env.start()
        self.addCleanup(self.env.stop)

    def reply(self, **values):
        data = {'score': 0.7, 'model': 'jev-test', 'request_id': 'test-request'}
        data.update(values)
        return subprocess.CompletedProcess([], 0, json.dumps(data).encode(), b'')

    def test_bridge_uses_stdin_without_api_key_or_state_arguments(self):
        with patch('ransomguard.jev_bridge.subprocess.run', return_value=self.reply()) as run:
            result = JevClient().evaluate({'path': 'lab.txt'})
        args, options = run.call_args
        self.assertEqual(args[0], [str(self.exe), '--evaluate'])
        self.assertEqual(json.loads(options['input'])['state'], {'path': 'lab.txt'})
        self.assertNotIn('key', json.loads(options['input']))
        self.assertEqual(result['request_id'], 'test-request')

    def test_other_endpoint_is_rejected_before_execution(self):
        with patch('ransomguard.jev_bridge.subprocess.run') as run:
            with self.assertRaises(JevConfigurationError):
                JevClient(JevConfig(base_url='https://example.invalid')).evaluate({'pid': 1})
            run.assert_not_called()

    def test_transport_errors_never_return_a_verdict_or_leak_detail(self):
        with patch('ransomguard.jev_bridge.subprocess.run', side_effect=subprocess.TimeoutExpired('secret-canary', 10)):
            with self.assertRaises(JevTransportError) as raised:
                JevClient().evaluate({'pid': 1})
        self.assertNotIn('secret-canary', str(raised.exception))

    def test_failed_process_cannot_supply_a_successful_score(self):
        failed = self.reply(); failed.returncode = 3
        with patch('ransomguard.jev_bridge.subprocess.run', return_value=failed):
            with self.assertRaises(JevTransportError): JevClient().evaluate({'pid': 1})

    def test_bridge_verdict_keeps_existing_strict_probability_validation(self):
        for score in [True, -1, 2, '0.9', None]:
            with self.subTest(score=score), patch('ransomguard.jev_bridge.subprocess.run', return_value=self.reply(score=score)):
                with self.assertRaises(JevResponseError): JevClient().evaluate({'pid': 1})

    def test_missing_request_identity_is_not_accepted(self):
        with patch('ransomguard.jev_bridge.subprocess.run', return_value=self.reply(request_id='')):
            with self.assertRaises(JevResponseError): JevClient().evaluate({'pid': 1})

    def test_unbounded_response_is_rejected(self):
        oversized = subprocess.CompletedProcess([], 0, b'x'*65537, b'')
        with patch('ransomguard.jev_bridge.subprocess.run', return_value=oversized):
            with self.assertRaises(JevTransportError): JevClient().evaluate({'pid': 1})
