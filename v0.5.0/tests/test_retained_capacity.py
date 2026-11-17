import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from ransomguard.outbox import Outbox, OutboxFull
from ransomguard.retention import RawRetention


class RetainedCapacityTests(unittest.TestCase):
    def test_protected_completed_raw_does_not_stop_intake_or_fake_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.db'
            with Outbox(path, max_pending=3) as out:
                out.enable_local_diagnostics()
                ret = RawRetention(out.db)
                kept = out.append('kernel_event', {'important': 'recovery failed'})
                ret.begin(kept, SimpleNamespace(pid=4), 123)
                ret.finish(kept, 'rate_limited')
                ret.protect(4, 123, 'recovery_failed')
                unfinished = out.append('kernel_event', {})
                ret.begin(unfinished, SimpleNamespace(pid=5), 124)
                unacked = out.append('kernel_event', {})
                ret.begin(unacked, SimpleNamespace(pid=6), 125)
                ret.finish(unacked, 'sent')  # A send is NOT a commit receipt.
                added = out.append('new_intake', {})
                self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0], 3)
                self.assertEqual(out.db.execute('SELECT acknowledged_at,capacity_released FROM events WHERE event_id=?', (kept,)).fetchone(), (None, 1))
                self.assertEqual(ret.cleanup(now=time.time()+1000, force=True), 0)
                self.assertEqual({x['event_id'] for x in out.pending()}, {kept, unfinished, unacked, added})
                export = Path(directory) / 'export.jsonl'
                self.assertEqual(out.export_jsonl(export), 4)
                self.assertIsNone(next(json.loads(s) for s in export.read_text().splitlines() if kept in s)['acknowledged_at'])
                with self.assertRaises(OutboxFull):
                    out.append('too_many_unprocessed', {})
                # Other connections and real external ACKs do not double-decrement.
                with Outbox(path, max_pending=3) as other:
                    other.acknowledge([kept], sent_ids=[kept])
                    self.assertEqual(other.db.execute('SELECT pending FROM events_capacity').fetchone()[0], 3)
                    other.acknowledge([added], sent_ids=[added])
                    self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0], 2)

    def test_legacy_schema_and_diagnostics_remain_exportable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'legacy.db'
            with closing(sqlite3.connect(path)) as db:
                db.executescript('''CREATE TABLE events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE,incident_id TEXT,occurred_at TEXT,kind TEXT,payload TEXT,acknowledged_at TEXT);
                    CREATE TABLE diagnostic_archive AS SELECT * FROM events;
                    CREATE VIEW all_outbox_events AS SELECT * FROM events UNION ALL SELECT * FROM diagnostic_archive;
                    INSERT INTO events VALUES(1,'old',NULL,'date','kernel_event','{}',NULL);''')
            with Outbox(path, max_pending=1) as out:
                out.enable_local_diagnostics()
                diagnostic = out.append('observer_started', {})
                self.assertEqual({x['event_id'] for x in out.pending()}, {'old', diagnostic})
                with self.assertRaises(OutboxFull): out.append('new', {})
                self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0], 1)

    def test_retained_row_delete_and_capacity_restore_triggers(self):
        with tempfile.TemporaryDirectory() as directory, Outbox(Path(directory)/'db') as out:
            a = out.append('kernel_event', {})
            with out.db:
                out.db.execute('UPDATE events SET capacity_released=1 WHERE event_id=?', (a,))
                self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0], 0)
                out.db.execute('UPDATE events SET capacity_released=0 WHERE event_id=?', (a,))
                self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0], 1)
                out.db.execute('UPDATE events SET capacity_released=1 WHERE event_id=?', (a,))
                out.db.execute('DELETE FROM events WHERE event_id=?', (a,))
            self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0], 0)
