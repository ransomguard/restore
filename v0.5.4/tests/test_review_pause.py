import copy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from ransomguard.review_pause import PauseJournal, ReviewPause, operator_resume
from ransomguard.live_response import LiveResponseCoordinator
from tests.test_live_response import ResponseTests, FakeProcessSession, sample_recovery_plan


def evidence():
    return {'counts': {'high_entropy_writes': 2, 'extension_change_attempts': 2},
            'verified_write_effects': {'files_changed_sha256': 2, 'files_checked': 2,
                'files_unverified': 0, 'changed_relative_paths': ['a', 'b']}}


class ReviewPauseTests(ResponseTests):
    # Reuse integration fixtures, including the real firewall owner state DB.
    def setUp(self):
        super().setUp()
        self.pause_events = []
        self.fail_resume = False
        self.fail_suspend = False
        self.journal = PauseJournal(Path(self.temp.name) / 'pauses.sqlite3')
        outer = self
        class Session(FakeProcessSession):
            def suspend(self):
                outer.pause_events.append('suspend')
                if outer.fail_suspend: raise OSError('uncertain')
            def resume(self):
                outer.pause_events.append('resume')
                if outer.fail_resume: raise OSError('uncertain')
        self.factory = lambda p: Session(p, self.state)
        self.scores = [.79, .9]
        self.calls = []
        def evaluate(value):
            self.calls.append(copy.deepcopy(value))
            return {'score': self.scores[len(self.calls)-1], 'request_id': 'req-'+str(len(self.calls)),
                    'model': 'controlled-test', 'request_state': value}
        self.fake_jev = SimpleNamespace(evaluate=evaluate)

    def run_review(self, provider=None, guard=None):
        def fresh(value):
            value['verified_write_effects'].update(files_changed_sha256=3, files_checked=3,
                                                  changed_relative_paths=['a','b','c'])
            return value
        followup = ReviewPause(self.journal, provider or fresh, session_factory=self.factory)
        coordinator = LiveResponseCoordinator(outbox=self.box, firewall=self.owner, driver=self.driver,
            recovery=self.recovery, jev=self.fake_jev, process_factory=self.factory,
            decision_guard=guard, review_followup=followup)
        return coordinator.respond(track='B', process=self.process, jev_state=evidence(),
            explicit_authorization=True, recovery_plan=sample_recovery_plan())

    def test_followup_malicious_terminates_before_restore(self):
        result = self.run_review()
        self.assertTrue(result.exit_confirmed and result.recovery_verified)
        self.assertEqual(self.pause_events, ['suspend'])
        self.assertEqual(result.state, 'RELEASED')
        self.assertEqual(self.journal.get(result.incident_id)['state'], 'EXIT_CONFIRMED')
        self.assertEqual(len(self.calls), 2)

    def test_followup_benign_resumes_without_restore(self):
        self.scores = [.79, .2]
        result = self.run_review()
        self.assertEqual(result.state, 'RELEASED')
        self.assertEqual(self.pause_events, ['suspend','resume'])
        self.assertFalse(self.driver.calls or self.recovery.calls)

    def test_followup_ambiguous_retains_pause_and_network(self):
        self.scores = [.79, .79]
        result = self.run_review()
        self.assertEqual(result.state, 'REVIEW_REQUIRED')
        self.assertTrue(result.firewall_hold_retained)
        self.assertEqual(self.journal.get(result.incident_id)['state'], 'SUSPENDED')
        self.assertEqual(self.pause_events, ['suspend'])

    def test_no_new_facts_never_requeries(self):
        result = self.run_review(provider=lambda value: value)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(result.review_followup['reassessment'], 'NO_NEW_VERIFIED_FACTS')
        self.assertEqual(result.state, 'REVIEW_REQUIRED')

    def test_suspend_failure_is_not_resumed_or_retried(self):
        self.fail_suspend = True
        result = self.run_review()
        self.assertEqual(self.journal.get(result.incident_id)['state'], 'REQUESTING')
        self.assertEqual(self.pause_events, ['suspend'])
        with self.assertRaises(RuntimeError):
            operator_resume(self.journal, result.incident_id, confirmed_safe=True, session_factory=self.factory)

    def test_resume_failure_retains_network(self):
        self.scores = [.79, .1]
        self.fail_resume = True
        result = self.run_review()
        self.assertTrue(result.firewall_hold_retained)
        self.assertEqual(self.journal.get(result.incident_id)['state'], 'RESUME_REQUESTED')

    def test_operator_resume_once_preserves_network_hold(self):
        result = self.run_review(provider=lambda value:value)
        with self.assertRaises(PermissionError):
            operator_resume(self.journal, result.incident_id, session_factory=self.factory)
        operator_resume(self.journal, result.incident_id, confirmed_safe=True, session_factory=self.factory)
        self.assertTrue(self.fake_fw.active)
        with self.assertRaises(RuntimeError):
            operator_resume(self.journal, result.incident_id, confirmed_safe=True, session_factory=self.factory)

    def test_generation_mismatch_prevents_operator_resume(self):
        result = self.run_review(provider=lambda value:value)
        self.state['expected_generation'] += 1
        with self.assertRaises(RuntimeError):
            operator_resume(self.journal, result.incident_id, confirmed_safe=True, session_factory=self.factory)
        self.assertEqual(self.pause_events, ['suspend'])

    def test_late_result_does_not_resume(self):
        self.scores = [.79, .1]
        result = self.run_review(guard=lambda: len(self.calls)<2)
        self.assertEqual(result.state, 'REVIEW_REQUIRED')
        self.assertEqual(self.pause_events, ['suspend'])

    def test_threshold_not_lowered_at_point_799(self):
        self.scores = [.79, .799]
        result = self.run_review()
        self.assertFalse(result.exit_confirmed)
        self.assertEqual(result.state, 'REVIEW_REQUIRED')

    def test_duplicate_process_reservation_prevents_double_suspend(self):
        self.run_review(provider=lambda value:value)
        self.calls.clear()
        result = self.run_review(provider=lambda value:value)
        self.assertEqual(self.pause_events, ['suspend'])
        self.assertEqual(result.state, 'REVIEW_REQUIRED')


if __name__ == '__main__': unittest.main()
