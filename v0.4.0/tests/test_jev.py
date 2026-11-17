"""Offline verdict tests: no SDK import, credentials, or network is needed."""

import json
import math
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ransomguard.jev import (
    JevClient, JevConfig, JevConfigurationError, JevResponseError,
    JevTransportError, parse_verdict,
)


def response(score=0.7, answer_type="noul", **overrides):
    values = dict(answers={"is_ransomware": SimpleNamespace(type=answer_type, noul=score)},
                  model="jev-test-version", request_id="test-request-1")
    values.update(overrides)
    return SimpleNamespace(**values)


class FakeSession:
    def __init__(self, reply=None, error=None):
        self.reply = reply or response()
        self.error = error
        self.calls = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def system_one(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.reply


class JevTests(unittest.TestCase):
    def test_valid_boundary_scores_and_metadata(self):
        for score in (0, 0.25, 1):
            with self.subTest(score=score):
                self.assertEqual(parse_verdict(response(score)),
                                 {"score": float(score), "model": "jev-test-version", "request_id": "test-request-1"})

    def test_rejects_non_numeric_nonfinite_out_of_range_and_bool(self):
        for score in (None, True, False, "0.9", {}, [], math.nan, math.inf, -math.inf, -0.01, 1.01):
            with self.subTest(score=score):
                with self.assertRaises(JevResponseError):
                    parse_verdict(response(score))

    def test_missing_wrong_answer_never_returns_an_object(self):
        for reply in (object(), {}, response(answers={}), response(answer_type="score"),
                      response(answers={"is_ransomware": object()})):
            with self.subTest(reply=type(reply)):
                with self.assertRaises(JevResponseError):
                    parse_verdict(reply)

    def test_huge_numeric_values_produce_typed_errors(self):
        with self.assertRaises(JevResponseError):
            parse_verdict(response(10 ** 1000))
        with self.assertRaises(JevConfigurationError):
            JevConfig(timeout_seconds=10 ** 1000)

    def test_requires_response_correlation_metadata(self):
        for overrides in ({"model": ""}, {"model": None}, {"request_id": ""}, {"request_id": None}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(JevResponseError):
                    parse_verdict(response(**overrides))

    def test_explicit_client_config_state_object_and_key(self):
        session = FakeSession()
        factory = Mock(return_value=session)
        config = JevConfig(base_url="https://example.invalid/api/", model="fixed-version", timeout_seconds=3.5)
        state = {"process_instance_id": "instance-1", "window_seconds": 2, "rename_count": 50}
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": "offline-test-key"}):
            verdict = JevClient(config, client_factory=factory).evaluate(state)
        self.assertEqual(verdict["score"], 0.7)
        factory.assert_called_once_with(api_key="offline-test-key", base_url="https://example.invalid/api",
                                        model="fixed-version", timeout=3.5, max_retries=0)
        self.assertIsInstance(session.calls[0]["state"], str)
        self.assertEqual(json.loads(session.calls[0]["state"]), state)
        self.assertEqual(session.calls[0]["questions"]["is_ransomware"]["type"], "noul")
        self.assertTrue(session.closed)

    def test_missing_credentials_make_no_request(self):
        factory = Mock()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(JevConfigurationError):
                JevClient(client_factory=factory).evaluate({"pid": 1})
        factory.assert_not_called()

    def test_transport_failure_does_not_leak_sdk_error_or_secret(self):
        secret = "offline-secret-value"
        session = FakeSession(error=RuntimeError("Authorization: " + secret))
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": secret}):
            with self.assertRaises(JevTransportError) as raised:
                JevClient(client_factory=lambda **_: session).evaluate({"pid": 1})
        self.assertNotIn(secret, str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertTrue(session.closed)

    def test_invalid_state_never_reaches_sdk(self):
        factory = Mock()
        for state in ({}, [], {"score": math.nan}, {"opaque": object()}):
            with self.subTest(state=type(state)):
                with self.assertRaises(JevConfigurationError):
                    JevClient(client_factory=factory).evaluate(state)
        factory.assert_not_called()

    def test_state_size_is_bounded(self):
        with self.assertRaises(JevConfigurationError):
            JevClient(JevConfig(max_state_bytes=10)).evaluate({"long": "x" * 100})

    def test_configuration_rejects_unsafe_urls_and_invalid_timeouts(self):
        for url in ("http://example.invalid", "https://user:pass@example.invalid", "https://example.invalid?key=x",
                    "https://example.invalid#fragment", "", "https://example.invalid:99999"):
            with self.subTest(url=url):
                with self.assertRaises(JevConfigurationError):
                    JevConfig(base_url=url)
        for timeout in (0, -1, math.inf, math.nan, True, "10"):
            with self.subTest(timeout=timeout):
                with self.assertRaises(JevConfigurationError):
                    JevConfig(timeout_seconds=timeout)


if __name__ == "__main__":
    unittest.main()
