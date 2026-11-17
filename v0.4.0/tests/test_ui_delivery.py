import tempfile
import unittest
from pathlib import Path
from ransomguard.ui_delivery import DurableUiDelivery


class Transport:
    def __init__(self):
        self.seen = {}
        self.fail_after_commit = False
        self.bad_ack = False
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def send(self, status): pass
    def exchange(self, items):
        for item in items:
            self.seen.setdefault(item['id'], item['message'])
        if self.fail_after_commit:
            self.fail_after_commit = False
            raise TimeoutError('Lost ACK after commit')
        return ['foreign'] if self.bad_ack else [item['id'] for item in items]


class DeliveryTests(unittest.TestCase):
    def test_lost_ack_restart_deduplicates_and_does_not_ack_raw_outbox(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'outbox.sqlite'
            transport = Transport()
            sink = DurableUiDelivery(path, transport_factory=lambda: transport)
            sink.db.execute('CREATE TABLE events(id TEXT, acknowledged_at TEXT)')
            sink.db.execute("INSERT INTO events VALUES('raw',NULL)"); sink.db.commit()
            sink.send({'type':'ALERT','data':{'path':'한글'}})
            transport.fail_after_commit = True
            with self.assertRaises(TimeoutError): sink.drain_once()
            self.assertEqual(sink.diagnostics()['pending'], 1)
            sink.close()
            sink = DurableUiDelivery(path, transport_factory=lambda: transport)
            sink.drain_once()
            self.assertEqual(len(transport.seen), 1)
            self.assertEqual(sink.diagnostics()['pending'], 0)
            self.assertIsNone(sink.db.execute('SELECT acknowledged_at FROM events').fetchone()[0])
            sink.close()

    def test_foreign_ack_cannot_delete_queue_and_full_queue_fails_explicitly(self):
        with tempfile.TemporaryDirectory() as folder:
            transport = Transport(); transport.bad_ack = True
            sink = DurableUiDelivery(Path(folder)/'queue', transport_factory=lambda: transport, max_pending=1)
            sink.send({'type':'ALERT'})
            with self.assertRaises(ValueError): sink.drain_once()
            self.assertEqual(sink.diagnostics()['pending'], 1)
            with self.assertRaises(RuntimeError): sink.send({'type':'ALERT'})
            sink.close()

    def test_status_coalesces_and_never_replays_after_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'queue'
            sink = DurableUiDelivery(path)
            for i in range(100): sink.send({'type':'SYSTEM_STATUS','timestamp':i})
            self.assertEqual(sink.status['timestamp'], 99)
            self.assertEqual(sink.diagnostics()['pending'], 0)
            sink.close()
            sink = DurableUiDelivery(path)
            self.assertIsNone(sink.status)
            sink.close()
    def test_ack_database_failure_rolls_back_then_retries_without_loss(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as folder:
            sink=DurableUiDelivery(Path(folder)/'queue',transport_factory=Transport)
            sink.send_tracked({'type':'ALERT'},incident_id='incident')
            sink.db.execute("CREATE TRIGGER fail_ack BEFORE DELETE ON ui_pending BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
            sink.db.commit()
            with self.assertRaises(sqlite3.IntegrityError): sink.drain_once()
            self.assertFalse(sink.db.in_transaction)
            self.assertEqual(sink.db.execute('SELECT acked FROM ui_delivery_tracking').fetchone()[0],0)
            self.assertEqual(sink.diagnostics()['pending'],1)
            sink.db.execute('DROP TRIGGER fail_ack');sink.db.commit()
            sink.drain_once()
            self.assertEqual(sink.diagnostics()['pending'],0)
            sink.close()
