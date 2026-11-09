import json
import tempfile
import unittest
from pathlib import Path
from ransomguard.outbox import Outbox, OutboxFull


class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_events_survive_restart_and_require_explicit_ack(self):
        path = self.root / "box.sqlite3"
        with Outbox(path) as box:
            first = box.append("detected", {"pid": 99})
            second = box.append("restored", {"files": 1})
        with Outbox(path) as box:
            self.assertEqual(len(box.pending()), 2)
            with self.assertRaises(ValueError):
                box.acknowledge(["unknown"], sent_ids=[first, second])
            box.acknowledge([first], sent_ids=[first, second])
            self.assertEqual([x["event_id"] for x in box.pending()], [second])
            target = self.root / "events.jsonl"
            self.assertEqual(box.export_jsonl(target), 2)
            self.assertTrue(json.loads(target.read_text().splitlines()[0])["acknowledged_at"])

    def test_capacity_does_not_silently_delete_evidence(self):
        with Outbox(self.root / "box.sqlite3", max_pending=1) as box:
            first = box.append("detected", {})
            with self.assertRaises(OutboxFull):
                box.append("more", {})
            self.assertEqual([x["event_id"] for x in box.pending()], [first])


if __name__ == "__main__":
    unittest.main()
