import tempfile
import unittest
from pathlib import Path
from ransomguard.incidents import IncidentController, ProcessInstance, SimulationEffects
from ransomguard.outbox import Outbox


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.box = Outbox(Path(self.temp.name) / "events.sqlite3")
        self.effects = SimulationEffects()
        self.controller = IncidentController(self.box, self.effects)

    def tearDown(self):
        self.box.close()
        self.temp.cleanup()

    def test_benign_does_not_kill_or_restore(self):
        controller, effects = self.controller, self.effects
        item = controller.begin(ProcessInstance(500, 111), "B")
        controller.decision(controller.ticket(item.incident_id), 0.01)
        self.assertEqual(item.state, "RELEASED")
        self.assertFalse(any(call[0] in ("terminate_and_confirm", "restore") for call in effects.calls))
        self.assertFalse(controller.network_holders)

    def test_malicious_releases_only_after_verified_restore(self):
        controller, effects, box = self.controller, self.effects, self.box
        item = controller.begin(ProcessInstance(500, 111), "B")
        controller.decision(controller.ticket(item.incident_id), 0.99)
        names = [x[0] for x in effects.calls]
        self.assertLess(names.index("terminate_and_confirm"), names.index("restore"))
        self.assertLess(names.index("restore"), names.index("host_outbound_off"))
        self.assertEqual(item.state, "RELEASED")
        self.assertTrue(all(event["data"]["execution_mode"] == "simulation" for event in box.pending()))

    def test_invalid_scores_never_release_or_kill(self):
        for score in (None, True, float("nan"), float("inf"), -0.1, 1.1, "0.9"):
            with self.subTest(score=score), tempfile.TemporaryDirectory() as directory:
                with Outbox(Path(directory) / "events.sqlite3") as box:
                    effects = SimulationEffects()
                    controller = IncidentController(box, effects)
                    item = controller.begin(ProcessInstance(500, 111), "B")
                    controller.decision(controller.ticket(item.incident_id), score)
                    self.assertEqual(item.state, "REVIEW_REQUIRED")
                    self.assertIn(item.incident_id, controller.network_holders)
                    self.assertFalse(any(x[0] == "terminate_and_confirm" for x in effects.calls))

    def test_timeout_preserves_containment(self):
        controller = self.controller
        item = controller.begin(ProcessInstance(500, 111), "B")
        controller.decision(controller.ticket(item.incident_id), error="timeout")
        self.assertEqual(item.state, "REVIEW_REQUIRED")
        self.assertTrue(controller.network_holders)

    def test_partial_restore_does_not_automatically_release(self):
        self.effects.recovery_status = "partial"
        item = self.controller.begin(ProcessInstance(500, 111), "A")
        self.assertEqual(item.state, "REVIEW_REQUIRED")
        self.assertFalse(any(x[0] == "host_outbound_off" for x in self.effects.calls))

    def test_global_policy_is_shared_across_different_processes(self):
        controller, effects = self.controller, self.effects
        first = controller.begin(ProcessInstance(500, 111), "B")
        second = controller.begin(ProcessInstance(501, 112), "B")
        controller.decision(controller.ticket(first.incident_id), 0.01)
        self.assertEqual(controller.network_holders, {second.incident_id})
        self.assertEqual(effects.calls.count(("host_outbound_on", "whole_host")), 1)
        self.assertNotIn(("host_outbound_off", "whole_host"), effects.calls)
        controller.decision(controller.ticket(second.incident_id), 0.01)
        self.assertEqual(sum(x[0] == "host_outbound_off" for x in effects.calls), 1)
        self.assertEqual(effects.calls.count(("file_release", "500:111")), 1)
        self.assertEqual(effects.calls.count(("file_release", "501:112")), 1)

    def test_same_process_incidents_share_hold_until_last_owner_releases(self):
        controller, effects = self.controller, self.effects
        process = ProcessInstance(500, 111)
        first = controller.begin(process, "B")
        second = controller.begin(process, "B")
        self.assertEqual(effects.calls.count(("host_outbound_on", "whole_host")), 1)
        self.assertEqual(effects.calls.count(("file_hold", "500:111")), 1)
        controller.decision(controller.ticket(first.incident_id), 0.01)
        self.assertEqual(controller.network_holders, {second.incident_id})
        self.assertEqual(controller.file_holders[process], {second.incident_id})
        self.assertNotIn(("host_outbound_off", "whole_host"), effects.calls)
        self.assertNotIn(("file_release", "500:111"), effects.calls)
        controller.decision(controller.ticket(second.incident_id), 0.01)
        self.assertEqual(effects.calls.count(("host_outbound_off", "whole_host")), 1)
        self.assertEqual(effects.calls.count(("file_release", "500:111")), 1)
        self.assertFalse(controller.network_holders)
        self.assertFalse(controller.file_holders)

    def test_pid_reuse_does_not_merge_or_release_a_new_process_instance(self):
        controller, effects = self.controller, self.effects
        old = controller.begin(ProcessInstance(500, 111), "B")
        new = controller.begin(ProcessInstance(500, 222), "B")
        controller.decision(controller.ticket(old.incident_id), 0.01)
        self.assertEqual(controller.network_holders, {new.incident_id})
        self.assertEqual(controller.file_holders, {new.process: {new.incident_id}})
        self.assertNotIn(("host_outbound_off", "whole_host"), effects.calls)
        self.assertNotIn(("file_release", "500:222"), effects.calls)
        self.assertEqual(controller.summary()["host_firewall_holder_incident_ids"], [new.incident_id])

    def test_simulation_reports_current_host_outbound_scope(self):
        item = self.controller.begin(ProcessInstance(500, 111), "B")
        self.assertIn(("host_outbound_on", "whole_host"), self.effects.calls)
        summary = self.controller.summary()
        self.assertEqual(summary["network_scope"], "host_outbound")
        self.assertTrue(summary["host_outbound_blocked"])
        self.assertEqual(summary["network_hold_count"], 1)
        events = [event for event in self.box.pending()
                  if event["event_type"] in ("quarantine_requested", "quarantine_applied")]
        self.assertTrue(events)
        self.assertTrue(all(event["data"]["scope"] == "host_outbound" for event in events))

    def test_late_normal_answer_cannot_override_track_a(self):
        controller, effects, box = self.controller, self.effects, self.box
        item = controller.begin(ProcessInstance(500, 111), "B")
        ticket = controller.ticket(item.incident_id)
        controller.escalate_to_a(item.incident_id)
        before = list(effects.calls)
        controller.decision(ticket, 0.01)
        self.assertEqual(effects.calls, before)
        self.assertEqual(box.pending()[-1]["event_type"], "stale_decision_ignored")

    def test_track_a_still_requests_exit_if_network_application_fails(self):
        self.effects.fail.add("host_outbound_on")
        item = self.controller.begin(ProcessInstance(500, 111), "A")
        self.assertIn(("terminate_and_confirm", "500:111"), self.effects.calls)
        self.assertEqual(item.state, "REVIEW_REQUIRED")
        self.assertFalse(any(x[0] == "restore" for x in self.effects.calls))

    def test_track_a_escalation_still_requests_exit_after_containment_failure(self):
        self.effects.fail.add("host_outbound_on")
        item = self.controller.begin(ProcessInstance(500, 111), "B")
        self.controller.escalate_to_a(item.incident_id)
        self.assertIn(("terminate_and_confirm", "500:111"), self.effects.calls)
        self.assertEqual(item.state, "REVIEW_REQUIRED")
        self.assertFalse(any(x[0] == "restore" for x in self.effects.calls))

    def test_failed_exit_never_starts_restore(self):
        self.effects.fail.add("terminate_and_confirm")
        item = self.controller.begin(ProcessInstance(500, 111), "A")
        self.assertEqual(item.state, "REVIEW_REQUIRED")
        self.assertFalse(any(x[0] == "restore" for x in self.effects.calls))

    def test_failed_host_release_retains_ownership(self):
        controller, effects = self.controller, self.effects
        item = controller.begin(ProcessInstance(500, 111), "B")
        effects.fail.add("host_outbound_off")
        controller.decision(controller.ticket(item.incident_id), 0.01)
        self.assertIn(item.incident_id, controller.network_holders)
        self.assertEqual(item.state, "REVIEW_REQUIRED")

    def test_failed_file_release_does_not_remove_network_hold(self):
        item = self.controller.begin(ProcessInstance(500, 111), "B")
        self.effects.fail.add("file_release")
        self.controller.decision(self.controller.ticket(item.incident_id), 0.01)
        self.assertIn(item.incident_id, self.controller.network_holders)
        self.assertIn(item.incident_id, self.controller.file_holders[item.process])
        self.assertNotIn(("host_outbound_off", "whole_host"), self.effects.calls)

    def test_non_simulation_effects_are_rejected(self):
        class OtherEffects(SimulationEffects):
            pass
        with self.assertRaises(TypeError):
            IncidentController(self.box, OtherEffects())


if __name__ == "__main__":
    unittest.main()
