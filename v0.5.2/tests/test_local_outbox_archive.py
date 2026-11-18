import json
import tempfile
import time
import unittest
from pathlib import Path

from ransomguard.buffered_reader import BufferedReader
from ransomguard.outbox import Outbox, OutboxFull


class ArchiveTests(unittest.TestCase):
    def test_full_queue_reclaims_only_diagnostics_and_preserves_export_and_ack(self):
        with tempfile.TemporaryDirectory() as tmp, Outbox(Path(tmp)/'events.db', max_pending=3) as out:
            first = out.append('triage_identity_reset', {'pid': 12})
            protected = out.append('triage_reset', {'x': 1}, incident_id='protected')
            candidate = out.append('track_b_deferred', {'pid': 12})
            with self.assertRaises(OutboxFull): out.append('kernel_event', {})
            self.assertEqual(out.enable_local_diagnostics(), 1)
            new = out.append('kernel_event', {})
            diagnostic = out.append('observer_started', {'restart': True})
            self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0], 3)
            self.assertEqual([x['event_id'] for x in out.pending()], [first, protected, candidate, new, diagnostic])
            with self.assertRaises(OutboxFull): out.append('kernel_event', {})
            target = Path(tmp)/'export.jsonl'
            self.assertEqual(out.export_jsonl(target), 5)
            self.assertTrue(all(x['acknowledged_at'] is None for x in map(json.loads,target.read_text().splitlines())))
            out.acknowledge([first, new], sent_ids=[first, new])
            self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0], 2)
            self.assertEqual(len(out.pending()), 3)
            self.assertEqual(out.enable_local_diagnostics(), 0)

    def test_default_external_queue_does_not_archive_or_bypass_limit(self):
        with tempfile.TemporaryDirectory() as tmp, Outbox(Path(tmp)/'events.db', max_pending=1) as out:
            out.append('observer_started', {})
            with self.assertRaises(OutboxFull): out.append('observer_started', {})
            self.assertEqual(out.db.execute('SELECT COUNT(*) FROM diagnostic_archive').fetchone()[0], 0)

    def test_full_queue_still_preserves_exact_unprocessed_bytes_and_exports(self):
        with tempfile.TemporaryDirectory() as tmp, Outbox(Path(tmp)/'events.db', max_pending=1) as out:
            out.append('track_b_candidate', {'pid': 12})
            out.preserve_intake([b'\x00\xffpayload', b'\x00\xffpayload'])
            self.assertEqual(out.db.execute('SELECT raw FROM intake_unprocessed').fetchall(), [(b'\x00\xffpayload',)])
            self.assertEqual(out.export_jsonl(Path(tmp)/'export.jsonl'), 2)

    def test_startup_exception_preserves_prefetch_and_original_exception(self):
        class Reader:
            def __init__(self): self.i=0; self.closed=False
            def read(self, timeout_ms=100):
                self.i+=1
                return str(self.i).encode()
            def close(self): self.closed=True
        raw=Reader(); saved=[]
        with self.assertRaisesRegex(ValueError, 'startup failed'):
            with BufferedReader(raw, 2, preserve=saved.extend):
                time.sleep(.08)
                raise ValueError('startup failed')
        self.assertEqual(saved, [str(i).encode() for i in range(1,raw.i+1)])
        self.assertTrue(raw.closed)
