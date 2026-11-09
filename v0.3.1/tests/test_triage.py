import math
import unittest

from ransomguard.protocol import Event, EVENT_NAMES, FILE_FLAG_HIGH_ENTROPY, FILE_FLAG_PREOP_OBSERVATION
from ransomguard.triage import TriageConfig, TriageIntake


class Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


def event(kind, sequence, *, pid=1234, created=999, entropy=False, path=r"C:\lab\one.txt"):
    fields = {"process_create_time": created} if kind in (1, 2, 3) else {
        "flags": FILE_FLAG_PREOP_OBSERVATION | (FILE_FLAG_HIGH_ENTROPY if entropy else 0),
        "path": path, "new_extension": "locked" if kind == 5 else ""}
    return Event(kind, EVENT_NAMES[kind], sequence, 133000000000000000 + sequence, pid, fields)


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.triage = TriageIntake(clock=self.clock)

    def create(self, sequence=1, *, pid=1234, created=999):
        return self.triage.ingest(event(1, sequence, pid=pid, created=created),
                                  correlated_create_time=created)

    def write(self, sequence, *, generation=999, entropy=True, pid=1234, path=r"C:\lab\one.txt"):
        return self.triage.ingest(event(4, sequence, pid=pid, entropy=entropy, path=path),
                                  correlated_create_time=generation)

    def test_one_high_entropy_write_routes_to_b_without_authorizing_response(self):
        self.create()
        records = self.write(2)
        self.assertEqual([item.kind for item in records], ["track_b_candidate"])
        result = records[0].payload
        self.assertEqual((result["track"], result["pid"], result["correlated_process_create_time"]),
                         ("B", 1234, 999))
        self.assertEqual(result["counts"]["high_entropy_writes"], 1)
        self.assertEqual(result["evidence"]["operation_result"], "unknown_pre_operation")
        for flag in ("identity_authorization", "complete_event_coverage", "containment_confirmed",
                     "jev_requested", "termination_requested", "restore_requested", "automatic_response"):
            self.assertFalse(result[flag], flag)

    def test_normal_write_and_rename_only_add_context(self):
        self.create()
        self.assertEqual(self.write(2, entropy=False), [])
        self.assertEqual(self.triage.ingest(event(5, 3, entropy=True), correlated_create_time=999), [])
        result = self.write(4)[0].payload
        self.assertEqual(result["counts"], {"write_attempts": 2, "rename_attempts": 1,
                                           "high_entropy_writes": 1, "retained_observations": 3})

    def test_cooldown_throttles_candidates_but_keeps_evidence(self):
        self.create()
        self.clock.value = 1
        first = self.write(2)[0]
        self.clock.value = 2
        self.assertEqual(self.write(3), [])
        self.assertEqual(self.triage.stats()["suppressed_candidates"], 1)
        self.clock.value = 31
        next_record = self.write(4)[0]
        self.assertNotEqual(first.payload["candidate_id"], next_record.payload["candidate_id"])
        self.assertEqual(next_record.payload["suppressed_since_last_emit"], 1)
        self.assertEqual(next_record.payload["counts"]["high_entropy_writes"], 1)

    def test_window_expiry_excludes_old_writes_but_keeps_recent_renames(self):
        self.triage = TriageIntake(TriageConfig(cooldown_seconds=0), clock=self.clock)
        self.create()
        self.write(2, path=r"C:\lab\expired.txt")
        self.clock.value = 9
        self.triage.ingest(event(5, 3, path=r"C:\lab\recent.txt"), correlated_create_time=999)
        self.clock.value = 10
        result = self.write(4, path=r"C:\lab\current.txt")[0].payload
        self.assertEqual(result["counts"]["write_attempts"], 1)
        self.assertEqual(result["counts"]["rename_attempts"], 1)
        self.assertNotIn(r"C:\lab\expired.txt", result["evidence"]["sample_source_paths"])

    def test_pid_reuse_resets_evidence_and_cooldown(self):
        self.create()
        self.write(2)
        resets = self.create(3, created=1000)
        self.assertEqual(resets[0].kind, "triage_identity_reset")
        result = self.write(4, generation=1000)[0].payload
        self.assertEqual(result["correlated_process_create_time"], 1000)
        self.assertEqual(result["counts"]["high_entropy_writes"], 1)
        self.assertEqual(result["suppressed_since_last_emit"], 0)

    def test_process_exit_clears_identity_even_if_external_cache_is_stale(self):
        self.create()
        self.write(2)
        records = self.triage.ingest(event(2, 3), correlated_create_time=None)
        self.assertEqual(records[0].payload["reason"], "process_exited")
        result = self.write(4)[0]
        self.assertEqual(result.kind, "track_b_deferred")
        self.assertIsNone(result.payload["correlated_process_create_time"])

    def test_old_generation_exit_does_not_remove_new_generation(self):
        self.create(created=1000)
        self.assertEqual(self.triage.ingest(event(2, 2, created=999), correlated_create_time=1000), [])
        self.assertEqual(self.write(3, generation=1000)[0].kind, "track_b_candidate")

    def test_missing_generation_is_deferred_and_not_merged_after_create(self):
        deferred = self.write(1, generation=None)[0]
        self.assertEqual(deferred.kind, "track_b_deferred")
        self.assertIn("missing_process_generation", deferred.payload["reason_codes"])
        self.create(2)
        result = self.write(3)[0].payload
        self.assertEqual(result["counts"]["high_entropy_writes"], 1)
        self.assertEqual(result["correlated_process_create_time"], 999)

    def test_sequence_gap_clears_lifetime_and_audits_deferred_signal(self):
        self.create()
        self.write(2)
        records = self.write(4)  # Deliberately pass a stale external generation.
        self.assertEqual([item.kind for item in records], ["triage_reset", "track_b_deferred"])
        self.assertEqual(records[0].payload["expected_sequence"], 3)
        self.assertIsNone(records[1].payload["correlated_process_create_time"])
        self.create(5)
        self.assertEqual(self.write(6)[0].kind, "track_b_candidate")

    def test_explicit_loss_reset_cannot_be_undone_by_stale_registry(self):
        self.create()
        self.write(2)
        reset = self.triage.reset(reason="driver_drop_counter_increased")
        self.assertEqual(reset.kind, "triage_reset")
        self.assertEqual(reset.payload["cleared_observations"], 1)
        self.assertEqual(self.write(3)[0].kind, "track_b_deferred")

    def test_correlation_disappearance_resets_counts_and_requires_fresh_lifecycle(self):
        self.create()
        self.write(2)
        records = self.write(3, generation=None)
        self.assertEqual([item.kind for item in records], ["triage_identity_reset", "track_b_deferred"])
        self.assertEqual(records[1].payload["counts"]["high_entropy_writes"], 1)
        self.clock.value = 30
        self.assertEqual(self.write(4)[0].kind, "track_b_deferred")

    def test_process_capacity_eviction_is_audited_and_identity_not_reused(self):
        self.triage = TriageIntake(TriageConfig(max_processes=2), clock=self.clock)
        self.create(pid=100, created=1)
        self.create(2, pid=200, created=2)
        self.write(3, pid=100, generation=1)
        records = self.create(4, pid=300, created=3)
        self.assertEqual(records[0].kind, "triage_state_evicted")
        self.assertEqual(records[0].payload["pid"], 200)
        self.assertEqual(self.triage.stats()["tracked_processes"], 2)
        records = self.write(5, pid=200, generation=2)
        self.assertEqual(records[-1].kind, "track_b_deferred")
        self.assertEqual(self.triage.stats()["tracked_processes"], 2)

    def test_event_and_path_bounds_disclose_truncated_window(self):
        self.triage = TriageIntake(TriageConfig(cooldown_seconds=0, max_events_per_process=3,
                                               max_paths_per_process=2), clock=self.clock)
        self.create()
        for sequence in range(2, 7):
            result = self.write(sequence, path=f"C:\\lab\\{sequence}.txt")[-1].payload
        self.assertEqual(self.triage.stats()["retained_observations"], 3)
        self.assertEqual(self.triage.stats()["retained_paths"], 2)
        self.assertEqual(result["counts"]["write_attempts"], 3)
        self.assertTrue(result["window_truncated_by_capacity"])
        self.assertEqual(result["observation_evictions_since_identity_reset"], 2)
        self.clock.value = 10
        self.assertFalse(self.write(7)[-1].payload["window_truncated_by_capacity"])

    def test_entropy_never_escalates_to_a_even_under_repeated_high_signals(self):
        self.triage = TriageIntake(TriageConfig(cooldown_seconds=0), clock=self.clock)
        self.create()
        for sequence in range(2, 102):
            result = self.write(sequence)[-1].payload
            self.assertEqual(result["track"], "B")
            self.assertFalse(result["termination_requested"])

    def test_clock_and_configuration_reject_invalid_timing_and_limits(self):
        for kwargs in ({"window_seconds": 0}, {"window_seconds": math.nan},
                       {"cooldown_seconds": -1}, {"max_processes": 0},
                       {"max_events_per_process": True}, {"max_paths_per_process": 1.5}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                TriageConfig(**kwargs)
        self.create()
        self.clock.value = -1
        with self.assertRaises(ValueError):
            self.write(2)


if __name__ == "__main__":
    unittest.main()
