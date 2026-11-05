from __future__ import annotations

from datetime import datetime, timezone
import tempfile
from pathlib import Path
import unittest

from ransomguard.firewall_control import FirewallHoldManager, FirewallProfile
from ransomguard.incidents import ProcessInstance
from ransomguard.live_response import LiveResponseCoordinator, ResponseThresholds
from ransomguard.outbox import Outbox
from ransomguard.recovery import Snapshot, build_plan

from tests.test_firewall_ipc import FakeFirewallDaemon


class FakeProcessSession:
    def __init__(self, process, state):
        self.process = process
        self.state = state
        if process.create_time != state["expected_generation"]:
            raise RuntimeError("PID reused")

    def is_exited(self):
        return self.state["exited"]

    def wait_exit(self, timeout_ms):
        return self.state["exited"]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class FakeDriver:
    def __init__(self, state):
        self.state = state
        self.calls = []
        self.should_fail = False

    def terminate_checked(self, **kwargs):
        self.calls.append(kwargs)
        if self.should_fail:
            return {"request_accepted": False, "kernel_ntstatus": "0xC0000022"}
        self.state["exited"] = True
        return {"request_accepted": True, "kernel_ntstatus": "0x00000000", "exit_confirmed": False}


class FakeJev:
    def __init__(self, score=None, *, fail=False):
        self.score = score
        self.fail = fail
        self.calls = []

    def evaluate(self, evidence):
        self.calls.append(evidence)
        if self.fail:
            raise RuntimeError("JEV unavailable")
        return {"score": self.score, "request_id": "request-1", "model": "demo-model"}


class FakeRecovery:
    def __init__(self):
        self.calls = []
        self.result = {"status": "verified", "verified": True, "files_verified": 1}

    def execute(self, plan, *, allow_live, containment_confirmed):
        self.calls.append((plan, allow_live, containment_confirmed))
        return dict(self.result)


def sample_recovery_plan():
    snapshot = Snapshot(
        snapshot_id="{00000000-0000-0000-0000-000000000111}",
        volume_id=r"\\?\Volume{00000000-0000-0000-0000-000000000222}" + "\\",
        device_path=r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9",
        created_at=datetime(2026, 11, 4, tzinfo=timezone.utc),
    )
    return build_plan(snapshot, volume_root="C:\\", protected_root=r"C:\RansomGuardLab\Protected",
                      manifest=["critical.txt"], incident_at=datetime(2026, 11, 5, tzinfo=timezone.utc))


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.box = Outbox(Path(self.temp.name) / "events.sqlite3")
        self.fake_fw = FakeFirewallDaemon()
        self.owner = FirewallHoldManager(Path(self.temp.name) / "firewall.sqlite3",
                                         FirewallProfile("https://api.typesafe.ai"), client=self.fake_fw)
        self.process = ProcessInstance(4004, 133000000000000005)
        self.state = {"expected_generation": self.process.create_time, "exited": False}
        self.driver = FakeDriver(self.state)
        self.recovery = FakeRecovery()
        self.jev = FakeJev(0.99)
        self.coordinator = self.new_coordinator()

    def tearDown(self):
        self.owner.close()
        self.box.close()
        self.temp.cleanup()

    def new_coordinator(self):
        return LiveResponseCoordinator(
            outbox=self.box, firewall=self.owner, driver=self.driver,
            jev=self.jev, recovery=self.recovery,
            process_factory=lambda process: FakeProcessSession(process, self.state))

    def respond_b(self, **kw):
        return self.coordinator.respond(track="B", process=self.process, jev_state={"counts": {"write": 2}},
                                        explicit_authorization=True, **kw)

    def test_benign_score_releases_after_ipc_without_kill(self):
        self.jev.score = 0.05
        item = self.respond_b()
        self.assertEqual(item.state, "RELEASED")
        self.assertFalse(item.firewall_hold_retained)
        self.assertFalse(self.driver.calls)
        self.assertFalse(self.recovery.calls)
        self.assertFalse(self.fake_fw.active)
        self.assertEqual(self.jev.calls, [{"counts": {"write": 2}}])

    def test_malicious_b_requires_exit_and_verified_restore_before_release(self):
        item = self.respond_b(recovery_plan=sample_recovery_plan())
        self.assertEqual(item.state, "RELEASED")
        self.assertTrue(item.exit_confirmed)
        self.assertTrue(item.recovery_verified)
        self.assertFalse(item.firewall_hold_retained)
        self.assertEqual(len(self.driver.calls), 1)
        self.assertEqual(self.driver.calls[0]["expected_create_time"], self.process.create_time)
        self.assertTrue(self.driver.calls[0]["explicit_authorization"])
        self.assertEqual(self.recovery.calls[0][1:], (True, True))
        kinds = [row["event_type"] for row in self.box.pending()]
        self.assertLess(kinds.index("host_outbound_policy_acknowledged"), kinds.index("jev_requested"))
        self.assertLess(kinds.index("process_exit_confirmed"), kinds.index("restore_started"))
        self.assertLess(kinds.index("restore_verified"), kinds.index("incident_firewall_hold_released"))

    def test_track_a_requires_explicit_strong_signal(self):
        with self.assertRaises(PermissionError):
            self.coordinator.respond(track="A", process=self.process, explicit_authorization=True)
        self.assertFalse(self.fake_fw.calls)
        item = self.coordinator.respond(track="A", process=self.process, track_a_confirmed=True,
                                        explicit_authorization=True, recovery_required=False)
        self.assertEqual(item.state, "RELEASED")
        self.assertEqual(len(self.driver.calls), 1)
        self.assertEqual(self.jev.calls, [])

    def test_authorization_gate_prevents_any_external_effect(self):
        with self.assertRaises(PermissionError):
            self.coordinator.respond(track="B", process=self.process,
                                     jev_state={"counts": {"write": 2}},
                                     explicit_authorization=False)
        self.assertEqual(self.fake_fw.calls, [])

    def test_missing_plan_does_not_unlock_after_malicious_kill(self):
        item = self.respond_b()
        self.assertEqual(item.state, "REVIEW_REQUIRED")
        self.assertEqual(item.reason, "verified_recovery_plan_missing")
        self.assertTrue(item.exit_confirmed)
        self.assertTrue(item.firewall_hold_retained)
        self.assertTrue(self.fake_fw.active)

    def test_ambiguous_jev_leaves_global_hold(self):
        self.jev.score = 0.50
        item = self.respond_b(incident_id="same-incident")
        self.assertEqual(item.reason, "jev_ambiguous_demo_threshold")
        self.assertTrue(item.firewall_hold_retained)
        self.assertFalse(self.driver.calls)
        self.assertTrue(self.fake_fw.active)
        self.assertEqual(self.owner.status(with_daemon=False)["holds"][0]["state"], "review_required")
        self.jev.score = 0.01
        replay = self.respond_b(incident_id="same-incident")
        self.assertEqual(replay.state, "REVIEW_REQUIRED")
        self.assertEqual(replay.reason, "host_outbound_containment_unconfirmed")
        self.assertTrue(self.fake_fw.active)

    def test_jev_failure_leaves_global_hold(self):
        self.jev.fail = True
        item = self.respond_b()
        self.assertEqual(item.reason, "jev_query_or_validation_failed")
        self.assertTrue(self.fake_fw.active)

    def test_pid_reuse_rejected_without_termination(self):
        self.state["expected_generation"] += 1
        item = self.respond_b(recovery_plan=sample_recovery_plan())
        self.assertEqual(item.state, "REVIEW_REQUIRED")
        self.assertFalse(self.driver.calls)
        self.assertFalse(self.recovery.calls)
        self.assertTrue(item.firewall_hold_retained)

    def test_restore_partial_keeps_hold(self):
        self.recovery.result = {"status": "partial", "verified": False, "files_failed": 1}
        item = self.respond_b(recovery_plan=sample_recovery_plan())
        self.assertEqual(item.reason, "restore_not_verified")
        self.assertTrue(self.fake_fw.active)

    def test_two_incidents_do_not_release_global_policy_early(self):
        self.jev.score = 0.5
        held = self.respond_b(incident_id="B")
        self.assertTrue(held.firewall_hold_retained)
        released = self.coordinator.respond(track="A", process=self.process,
                                            track_a_confirmed=True, explicit_authorization=True,
                                            recovery_required=False, incident_id="A")
        self.assertEqual(released.state, "RELEASED")
        self.assertTrue(self.fake_fw.active)
        self.assertEqual(self.owner.status(with_daemon=False)["active_holds"], 1)

    def test_network_unavailable_track_a_still_attempts_kill_b_does_not_query(self):
        self.fake_fw.fail_action = "on"
        item = self.coordinator.respond(track="A", process=self.process, track_a_confirmed=True,
                                        explicit_authorization=True, recovery_required=False)
        self.assertEqual(item.reason, "host_outbound_containment_unconfirmed")
        self.assertEqual(len(self.driver.calls), 1)
        self.assertTrue(item.firewall_hold_retained)
        self.jev.score = 0.99
        blocked = self.respond_b()
        self.assertEqual(blocked.reason, "host_outbound_containment_unconfirmed")
        self.assertEqual(self.jev.calls, [])


if __name__ == "__main__":
    unittest.main()
