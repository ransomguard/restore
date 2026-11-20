import sqlite3
import tempfile
import unittest
from pathlib import Path

from ransomguard.damage_candidates import approved_nt_directory, propose_recovery_candidates
from ransomguard.outbox import Outbox
from ransomguard.protocol import Event, FILE_FLAG_HIGH_ENTROPY


PID = 4100
CREATE_TIME = 133000000000000001
PREFIX = r"\Device\HarddiskVolume3\RG_Test"


def append_event(outbox, kind, seq, *, pid=PID, create_time=None,
                 path=None, flags=0, correlated=None):
    fields = {}
    if create_time is not None:
        fields["process_create_time"] = create_time
    if path is not None:
        fields["path"] = path
        fields["flags"] = flags
    event = Event(kind, "test", seq, 133000000000000000 + seq, pid, fields)
    payload = event.to_dict()
    payload["correlated_process_create_time"] = correlated
    payload["execution_mode"] = "observation"
    outbox.append("kernel_event", payload)


class RecoveryCandidatesTests(unittest.TestCase):
    def test_requires_real_correlated_lifecycle_and_exact_nt_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            with Outbox(Path(directory) / "events.db") as outbox:
                append_event(outbox, 4, 1, path=PREFIX + r"\untrusted.txt", correlated=CREATE_TIME)
                append_event(outbox, 1, 2, create_time=CREATE_TIME)
                append_event(outbox, 4, 3, path=PREFIX + r"\test.txt", flags=FILE_FLAG_HIGH_ENTROPY,
                             correlated=CREATE_TIME)
                append_event(outbox, 4, 4, path=PREFIX + r"\TEST.txt", correlated=CREATE_TIME)
                append_event(outbox, 5, 5, path=PREFIX + r"\old.txt", correlated=CREATE_TIME)
                append_event(outbox, 4, 6, path=PREFIX + r"\..\Windows\not_allowed.txt",
                             correlated=CREATE_TIME)
                append_event(outbox, 4, 7, path=r"\Device\HarddiskVolume3\Other\a.txt",
                             correlated=CREATE_TIME)
                append_event(outbox, 2, 8, create_time=CREATE_TIME)
                append_event(outbox, 4, 9, path=PREFIX + r"\after_exit.txt", correlated=CREATE_TIME)
                result = propose_recovery_candidates(
                    outbox.db, pid=PID, process_create_time=CREATE_TIME,
                    approved_path_prefix=PREFIX)
                self.assertEqual(result["manifest"], ["test.txt"])
                self.assertEqual(result["evidence"][0]["write_attempts"], 2)
                self.assertEqual(result["evidence"][0]["high_entropy_observations"], 1)
                self.assertEqual(result["rename_attempts_without_target_path"], 1)
                self.assertEqual(result["uncorrelated_attempts_excluded"], 2)
                self.assertFalse(result["file_damage_confirmed"])
                self.assertFalse(result["auto_restore_authorized"])
                self.assertTrue(result["operator_review_required"])

    def test_pid_reuse_cannot_mix_files(self):
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, kind TEXT, payload TEXT)")
            # An empty table must not invent a lifecycle or a manifest.
            result = propose_recovery_candidates(db, pid=PID, process_create_time=CREATE_TIME,
                                                 approved_path_prefix=PREFIX)
            self.assertEqual(result["manifest"], [])

    def test_unsafe_prefix_is_rejected(self):
        for raw in (r"\Device\HarddiskVolume3\RG_Test\..",
                    r"\Device\HarddiskVolume3\RG_Test\CON", r"C:\RG_Test",
                    r"\Device\HarddiskVolume3\RG_Test\bad:name"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                approved_nt_directory(raw)

    def test_capacity_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with Outbox(Path(directory) / "events.db") as outbox:
                append_event(outbox, 1, 1, create_time=CREATE_TIME)
                append_event(outbox, 4, 2, path=PREFIX + r"\first.txt", correlated=CREATE_TIME)
                append_event(outbox, 4, 3, path=PREFIX + r"\second.txt", correlated=CREATE_TIME)
                with self.assertRaises(ValueError):
                    propose_recovery_candidates(outbox.db, pid=PID, process_create_time=CREATE_TIME,
                                                approved_path_prefix=PREFIX, max_files=1)


if __name__ == "__main__":
    unittest.main()
