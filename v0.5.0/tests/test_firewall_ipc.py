from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest

from ransomguard.firewall_ipc import (
    MAX_REQUEST_BYTES, FirewallIpcClient, FirewallIpcError,
    FirewallProtocolError, decode_firewall_response, encode_firewall_request,
)
from ransomguard.firewall_control import FirewallHoldError, FirewallHoldManager, FirewallProfile


class FakeFirewallDaemon:
    def __init__(self):
        self.active = False
        self.allowlist = []
        self.calls = []
        self.fail_action = None

    def request(self, action, *, whitelist=None):
        self.calls.append((action, whitelist))
        if action == self.fail_action:
            raise TimeoutError("Test daemon lost the reply")
        if action == "on":
            self.active = True
            if whitelist is not None:
                self.allowlist = list(whitelist)
        elif action == "set":
            if whitelist is not None:
                self.allowlist = list(whitelist)
        elif action == "off":
            self.active = False
        return {"success": True, "action": action, "active": self.active,
                "whitelist": [{"type": "url", "value": item,
                               "data": {"domain": "example.com", "port": 443, "ipv4": ["192.0.2.1"], "ipv6": []}}
                              for item in self.allowlist]}


class FirewallIpcTests(unittest.TestCase):
    def test_wire_matches_daemon_single_read_contract(self):
        data = encode_firewall_request("on", whitelist=["https://api.typesafe.ai"])
        self.assertEqual(data, b'{"action":"on","whitelist":["https://api.typesafe.ai"]}')
        self.assertNotIn(b"\n", data)
        self.assertLessEqual(len(data), MAX_REQUEST_BYTES)

    def test_no_newline_request_and_validated_response(self):
        def transport(raw, timeout_ms):
            self.assertEqual(timeout_ms, 1500)
            self.assertEqual(json.loads(raw), {"action": "get"})
            return b'{"success":true,"action":"get","active":false,"whitelist":[]}\n'
        result = FirewallIpcClient(timeout_ms=1500, transport=transport).request("get")
        self.assertFalse(result["active"])

    def test_invalid_actions_and_whitelist_do_not_send(self):
        for action, targets in (("get", []), ("off", ["https://example.com"]),
                                ("on", ["*:443"]), ("on", ["https://example.com"] * 2)):
            if action == "on" and targets == ["*:443"]:
                # IPC encoding itself is contract-generic; strict URL validation
                # belongs to the higher-level profile.
                continue
            with self.subTest(action=action, targets=targets), self.assertRaises(ValueError):
                encode_firewall_request(action, whitelist=targets)
        self.assertRaises(ValueError, lambda: FirewallProfile("*:443"))
        self.assertRaises(ValueError, lambda: FirewallProfile("http://api.typesafe.ai"))
        self.assertRaises(ValueError, lambda: FirewallProfile("https://user:pass@api.typesafe.ai"))

    def test_rejects_malformed_and_forged_success(self):
        raw_cases = [b"{}\n", b"not-json\n", b'{"success":true,"action":"get","active":true}\n',
                     b'{"success":true,"action":"off","active":true}\n',
                     b'{"success":true,"success":false,"action":"get","active":false,"whitelist":[]}\n',
                     b'{"success":true,"action":"get","active":false,"whitelist":[],"weird":NaN}\n',
                     b'{"success":true,"action":"get","active":false,"whitelist":[]}\n\n',
                     b'{"success":true,"action":"set","active":false,"whitelist":[]}\n']
        for raw in raw_cases:
            with self.subTest(raw=raw), self.assertRaises(FirewallProtocolError):
                decode_firewall_response(raw, action="get")

    def test_daemon_rejection_and_missing_allowlist(self):
        raw = b'{"success":false,"action":"on","message":"error"}\n'
        with self.assertRaises(FirewallIpcError):
            decode_firewall_response(raw, action="on")
        raw = b'{"success":true,"action":"on","active":true,"whitelist":[]}\n'
        with self.assertRaises(FirewallProtocolError):
            decode_firewall_response(raw, action="on", requested_whitelist=["https://api.typesafe.ai"])


class FirewallManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "hold.sqlite3"
        self.profile = FirewallProfile("https://api.typesafe.ai")
        self.fake = FakeFirewallDaemon()

    def tearDown(self):
        self.tmp.cleanup()

    def test_track_a_and_b_share_host_scope_without_premature_off(self):
        with FirewallHoldManager(self.db, self.profile, client=self.fake) as owner:
            first = owner.acquire("incident-A", "A")
            self.assertTrue(first["active_reported"])
            self.assertFalse(first["wfp_enforcement_verified"])
            second = owner.acquire("incident-B", "B")
            self.assertEqual(second["active_holds"], 2)
            self.assertEqual(sum(a == "on" for a, _ in self.fake.calls), 1,
                             "The second incident must not reapply WFP allowlist filters")
            remaining = owner.release("incident-A")
            self.assertEqual(remaining["remaining_holds"], 1)
            self.assertFalse(remaining["firewall_off_requested"])
            self.assertTrue(self.fake.active)
            result = owner.release("incident-B")
            self.assertTrue(result["firewall_off_reported"])
            self.assertFalse(self.fake.active)
            self.assertEqual(sum(a == "off" for a, _ in self.fake.calls), 1)

    def test_idempotency_and_stale_profile_protection(self):
        with FirewallHoldManager(self.db, self.profile, client=self.fake) as owner:
            owner.acquire("A", "A")
            self.assertEqual(owner.acquire("A", "A")["active_holds"], 1)
            self.assertEqual(sum(a == "on" for a, _ in self.fake.calls), 1,
                             "Retrying the same acknowledged incident must be read-only")
            self.assertRaises(FirewallHoldError, owner.acquire, "A", "B")
            self.assertEqual(owner.status(with_daemon=False)["active_holds"], 1)
            owner.release("A")
        with FirewallHoldManager(self.db, FirewallProfile("https://different.example"), client=self.fake) as another:
            self.assertRaises(FirewallHoldError, another.acquire, "B", "B")

    def test_daemon_restart_reasserts_once_only_when_policy_is_inactive(self):
        with FirewallHoldManager(self.db, self.profile, client=self.fake) as owner:
            owner.acquire("A", "A")
            # A restarted daemon loses the old dynamic WFP engine session.
            self.fake.active = False
            self.fake.allowlist = []
            result = owner.acquire("B", "B")
            self.assertEqual(result["active_holds"], 2)
            self.assertEqual(sum(a == "on" for a, _ in self.fake.calls), 2)
            owner.acquire("B", "B")
            self.assertEqual(sum(a == "on" for a, _ in self.fake.calls), 2)
            self.assertFalse(owner.release("A")["firewall_off_requested"])
            self.assertTrue(owner.release("B")["firewall_off_reported"])
            self.assertEqual(sum(a == "off" for a, _ in self.fake.calls), 1)

    def test_changed_active_allowlist_does_not_trigger_unsafe_reapply(self):
        with FirewallHoldManager(self.db, self.profile, client=self.fake) as owner:
            owner.acquire("A", "A")
            self.fake.allowlist = ["https://unexpected.example"]
            with self.assertRaises(FirewallHoldError):
                owner.acquire("B", "B")
            self.assertEqual(sum(a == "on" for a, _ in self.fake.calls), 1)
            holds = {item["incident_id"]: item["state"] for item in owner.status(with_daemon=False)["holds"]}
            self.assertEqual(holds["A"], "acknowledged")
            self.assertEqual(holds["B"], "review_required")
            self.assertFalse(owner.release("A")["firewall_off_requested"])
            self.assertEqual(sum(a == "off" for a, _ in self.fake.calls), 0)

    def test_error_retains_durable_hold_across_restart(self):
        self.fake.fail_action = "on"
        with FirewallHoldManager(self.db, self.profile, client=self.fake) as owner:
            with self.assertRaises(TimeoutError):
                owner.acquire("A", "A")
            self.assertEqual(owner.status(with_daemon=False)["holds"][0]["state"], "review_required")
        self.fake.fail_action = None
        with FirewallHoldManager(self.db, self.profile, client=self.fake) as owner:
            self.assertRaises(FirewallHoldError, owner.release, "A")

    def test_does_not_seize_external_active_policy(self):
        self.fake.active = True
        with FirewallHoldManager(self.db, self.profile, client=self.fake) as owner:
            self.assertRaises(FirewallHoldError, owner.acquire, "A", "B")
            self.assertNotIn("on", [name for name, _ in self.fake.calls])
            self.assertRaises(FirewallHoldError, owner.release, "A")

    def test_release_failure_never_deletes_hold(self):
        with FirewallHoldManager(self.db, self.profile, client=self.fake) as owner:
            owner.acquire("A", "A")
            self.fake.fail_action = "off"
            self.assertRaises(TimeoutError, owner.release, "A")
            self.assertEqual(owner.status(with_daemon=False)["active_holds"], 1)

    def test_operator_can_release_review_hold_after_explicit_verification(self):
        with FirewallHoldManager(self.db, self.profile, client=self.fake) as owner:
            owner.acquire("A", "B")
            owner.db.execute("UPDATE firewall_holds SET state='review_required' WHERE incident_id='A'")
            owner.db.commit()
            self.assertRaises(FirewallHoldError, owner.release, "A")
            self.assertRaises(PermissionError, owner.operator_review_release, "A")
            released = owner.operator_review_release("A", operator_verified_safe=True)
            self.assertTrue(released["firewall_off_reported"])
            self.assertFalse(self.fake.active)

    def test_operator_unowned_inactive_hold_can_clear_without_remote_off(self):
        self.fake.fail_action = "on"
        with FirewallHoldManager(self.db, self.profile, client=self.fake) as owner:
            self.assertRaises(TimeoutError, owner.acquire, "A", "B")
            self.fake.fail_action = None
            result = owner.operator_review_release("A", operator_verified_safe=True)
            self.assertEqual(result["operator_reconciliation"], "cleared_unowned_inactive_hold")
            self.assertEqual(self.fake.calls.count(("off", None)), 0)


if __name__ == "__main__":
    unittest.main()
