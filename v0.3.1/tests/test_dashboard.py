"""Offline dashboard contract tests; all HTTP transport is mocked."""

import json
import math
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import URLError
from urllib.request import Request

from ransomguard.dashboard import _NoRedirect, send_batch
from ransomguard.outbox import Outbox


ENDPOINT = "https://dashboard.example.invalid/events"
TOKEN_ENV = "RANSOMGUARD_DASHBOARD_TOKEN"


class FakeResponse:
    def __init__(self, body):
        self.body = body
        self.read_limits = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def read(self, limit):
        self.read_limits.append(limit)
        return self.body[:limit]


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.box = Outbox(Path(self.temp.name) / "outbox.sqlite3")
        self.first = self.box.append("detected", {"pid": 77, "path": "문서.txt"})
        self.second = self.box.append("restore_started", {"files": 2})
        self.environment = patch.dict(os.environ, {TOKEN_ENV: "offline-test-token"})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.box.close()
        self.temp.cleanup()

    def pending_ids(self):
        return [event["event_id"] for event in self.box.pending()]

    def transport(self, payload):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        response = FakeResponse(body)
        opener = Mock()
        opener.open.return_value = response
        return opener, response

    def test_success_acknowledges_only_explicit_ids(self):
        opener, response = self.transport({"acknowledged_event_ids": [self.second]})
        with patch("ransomguard.dashboard.build_opener", return_value=opener) as builder:
            self.assertEqual(send_batch(self.box, ENDPOINT, timeout=4), 1)
        self.assertEqual(self.pending_ids(), [self.first])
        builder.assert_called_once_with(_NoRedirect)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, ENDPOINT)
        self.assertEqual(request.get_header("Authorization"), "Bearer offline-test-token")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 4)
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["schema_version"], 1)
        self.assertEqual([item["event_id"] for item in body["events"]], [self.first, self.second])
        self.assertEqual(body["events"][0]["data"]["path"], "문서.txt")
        self.assertEqual(response.read_limits, [1_048_577])
        self.assertTrue(response.closed)

    def test_all_ids_can_be_acknowledged(self):
        opener, _ = self.transport({"acknowledged_event_ids": [self.first, self.second]})
        with patch("ransomguard.dashboard.build_opener", return_value=opener):
            self.assertEqual(send_batch(self.box, ENDPOINT), 2)
        self.assertEqual(self.pending_ids(), [])

    def test_http_success_without_valid_ack_preserves_events(self):
        malformed = ({}, [], None, {"acknowledged_event_ids": None},
                     {"acknowledged_event_ids": self.first}, {"acknowledged_event_ids": [123]}, b"not JSON")
        for payload in malformed:
            with self.subTest(payload=payload):
                opener, _ = self.transport(payload)
                with patch("ransomguard.dashboard.build_opener", return_value=opener):
                    with self.assertRaises(ValueError):
                        send_batch(self.box, ENDPOINT)
                self.assertEqual(self.pending_ids(), [self.first, self.second])

    def test_unknown_ack_does_not_partially_commit_known_ids(self):
        opener, _ = self.transport({"acknowledged_event_ids": [self.first, "unknown-event"]})
        with patch("ransomguard.dashboard.build_opener", return_value=opener):
            with self.assertRaises(ValueError):
                send_batch(self.box, ENDPOINT)
        self.assertEqual(self.pending_ids(), [self.first, self.second])

    def test_duplicate_ack_is_rejected_without_deleting_events(self):
        opener, _ = self.transport({"acknowledged_event_ids": [self.first, self.first]})
        with patch("ransomguard.dashboard.build_opener", return_value=opener):
            with self.assertRaises(ValueError):
                send_batch(self.box, ENDPOINT)
        self.assertEqual(self.pending_ids(), [self.first, self.second])

    def test_ack_for_pending_but_unsent_id_is_rejected(self):
        opener, _ = self.transport({"acknowledged_event_ids": [self.second]})
        with patch("ransomguard.dashboard.build_opener", return_value=opener):
            with self.assertRaises(ValueError):
                send_batch(self.box, ENDPOINT, limit=1)
        request = opener.open.call_args.args[0]
        self.assertEqual([item["event_id"] for item in json.loads(request.data)["events"]], [self.first])
        self.assertEqual(self.pending_ids(), [self.first, self.second])

    def test_empty_ack_preserves_batch(self):
        opener, _ = self.transport({"acknowledged_event_ids": []})
        with patch("ransomguard.dashboard.build_opener", return_value=opener):
            self.assertEqual(send_batch(self.box, ENDPOINT), 0)
        self.assertEqual(self.pending_ids(), [self.first, self.second])

    def test_send_error_preserves_pending(self):
        opener = Mock()
        opener.open.side_effect = URLError("offline test connection failure")
        with patch("ransomguard.dashboard.build_opener", return_value=opener):
            with self.assertRaises(URLError):
                send_batch(self.box, ENDPOINT)
        self.assertEqual(self.pending_ids(), [self.first, self.second])

    def test_redirect_is_refused_and_preserves_pending(self):
        opener = Mock()
        opener.open.side_effect = lambda request, **_: _NoRedirect().redirect_request(
            request, None, 302, "Found", {}, "https://different.example.invalid/events"
        )
        with patch("ransomguard.dashboard.build_opener", return_value=opener):
            with self.assertRaises(RuntimeError):
                send_batch(self.box, ENDPOINT)
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(self.pending_ids(), [self.first, self.second])

    def test_oversized_response_is_rejected(self):
        opener, response = self.transport(b"x" * 1_048_577)
        with patch("ransomguard.dashboard.build_opener", return_value=opener):
            with self.assertRaises(ValueError):
                send_batch(self.box, ENDPOINT)
        self.assertEqual(self.pending_ids(), [self.first, self.second])
        self.assertTrue(response.closed)

    def test_invalid_https_endpoint_never_creates_transport(self):
        endpoints = ("http://example.invalid/events", "https://user:pass@example.invalid/events",
                     "https://@example.invalid/events", "https://*.example.invalid/events",
                     "https://example.invalid:99999/events", "https://example.invalid/events#fragment",
                     "https://example.invalid/\npath", "https://example.invalid/a b", "")
        with patch("ransomguard.dashboard.build_opener") as builder:
            for endpoint in endpoints:
                with self.subTest(endpoint=endpoint):
                    with self.assertRaises(ValueError):
                        send_batch(self.box, endpoint)
            builder.assert_not_called()
        self.assertEqual(self.pending_ids(), [self.first, self.second])

    def test_invalid_timeout_never_creates_transport(self):
        with patch("ransomguard.dashboard.build_opener") as builder:
            for timeout in (0, -1, 61, True, math.nan, math.inf, "10", None):
                with self.subTest(timeout=timeout):
                    with self.assertRaises(ValueError):
                        send_batch(self.box, ENDPOINT, timeout=timeout)
            builder.assert_not_called()

    def test_invalid_token_is_rejected_without_exposing_it(self):
        bad = "secret-value\nInjected-Header: value"
        with patch.dict(os.environ, {TOKEN_ENV: bad}), patch("ransomguard.dashboard.build_opener") as builder:
            with self.assertRaises(ValueError) as raised:
                send_batch(self.box, ENDPOINT)
            self.assertNotIn("secret-value", str(raised.exception))
            builder.assert_not_called()
        self.assertEqual(self.pending_ids(), [self.first, self.second])

    def test_empty_outbox_does_not_contact_server(self):
        self.box.acknowledge([self.first, self.second], sent_ids=[self.first, self.second])
        with patch("ransomguard.dashboard.build_opener") as builder:
            self.assertEqual(send_batch(self.box, ENDPOINT), 0)
            builder.assert_not_called()


if __name__ == "__main__":
    unittest.main()
