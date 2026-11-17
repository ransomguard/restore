import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path

from ransomguard.response_ledger import ResponseLedger


class ResponseLedgerTests(unittest.TestCase):
    def test_same_generation_never_auto_retried_even_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.db"
            with closing(sqlite3.connect(path)) as db:
                ledger = ResponseLedger(db)
                self.assertTrue(ledger.claim(incident_id="one", pid=4100,
                                             process_create_time=133000000000000001))
                self.assertFalse(ledger.claim(incident_id="one", pid=4100,
                                              process_create_time=133000000000000001))
            with closing(sqlite3.connect(path)) as db:
                after_crash = ResponseLedger(db)
                self.assertFalse(after_crash.claim(incident_id="different", pid=4100,
                                                   process_create_time=133000000000000001))
                self.assertEqual(after_crash.inspect()[0]["state"], "RESERVED")
                after_crash.finish("one", state="REVIEW_REQUIRED", reason="crash_reconciled")
                self.assertFalse(after_crash.claim(incident_id="one", pid=4100,
                                                   process_create_time=133000000000000001))

    def test_pid_reuse_is_distinct_identity(self):
        with closing(sqlite3.connect(":memory:")) as db:
            ledger = ResponseLedger(db)
            self.assertTrue(ledger.claim(incident_id="first", pid=4100, process_create_time=1))
            ledger.finish("first", state="RELEASED", reason="benign")
            self.assertTrue(ledger.claim(incident_id="second", pid=4100, process_create_time=2))
            self.assertIn("RELEASED", [item["state"] for item in ledger.inspect()])
            self.assertEqual(len(ledger.inspect()), 2)

    def test_bad_identity_rejected_without_insert(self):
        with closing(sqlite3.connect(":memory:")) as db:
            ledger = ResponseLedger(db)
            for pid, stamp in ((0, 1), (True, 1), (1, 0), (1, True),
                               (0x100000000, 1), (1, 0x8000000000000000)):
                with self.assertRaises(ValueError):
                    ledger.claim(incident_id="bad", pid=pid, process_create_time=stamp)
            self.assertEqual(ledger.inspect(), [])

    def test_terminal_once_and_no_implicit_reset(self):
        with closing(sqlite3.connect(":memory:")) as db:
            ledger = ResponseLedger(db)
            self.assertTrue(ledger.claim(incident_id="ok", pid=1, process_create_time=1234))
            with self.assertRaises(ValueError):
                ledger.finish("ok", state="RETRY", reason=None)
            ledger.finish("ok", state="RELEASED", reason="verified")
            with self.assertRaises(ValueError):
                ledger.finish("ok", state="RELEASED", reason="again")
            self.assertEqual(ledger.inspect()[0]["state"], "RELEASED")


if __name__ == "__main__":
    unittest.main()
