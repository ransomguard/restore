import tempfile
import unittest
from pathlib import Path
from ransomguard.ui_delivery import DurableUiDelivery
from ransomguard.ui_pipe import parse_commit_ack, encode_ui_jsonl


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
    def test_real_delivery_thread_drains_after_analysis_exception(self):
        import threading,time
        from types import SimpleNamespace
        from unittest.mock import patch
        from ransomguard.ui_delivery import resident_delivery
        release=threading.Event()
        class PausedTransport(Transport):
            peer_batch_limit=64
            def exchange(self,items):
                if not release.wait(3): raise TimeoutError('test gate')
                return super().exchange(items)
        with tempfile.TemporaryDirectory() as folder:
            transport=PausedTransport()
            sink=DurableUiDelivery(Path(folder)/'queue',transport_factory=lambda:transport)
            owner=SimpleNamespace()
            try:
                with patch('ransomguard.ui_delivery.DurableUiDelivery',return_value=sink):
                    with self.assertRaisesRegex(RuntimeError,'analysis failed'):
                        with resident_delivery(owner,'unused') as active:
                            for i in range(200):active.send({'type':'ALERT','data':{'index':i}})
                            raise RuntimeError('analysis failed')
                    release.set()
                    deadline=time.monotonic()+5
                    while sink.diagnostics()['pending'] and time.monotonic()<deadline:time.sleep(.01)
                    self.assertEqual(sink.diagnostics()['pending'],0)
                    self.assertEqual(sink.diagnostics()['acknowledged'],200)
                    self.assertEqual(sorted(x['data']['index'] for x in transport.seen.values()),list(range(200)))
                    self.assertTrue(sink.thread.is_alive())
                    with resident_delivery(owner,'unused'):pass
                    self.assertFalse(sink.thread.is_alive())
            finally:
                release.set()
                if getattr(owner,'_retained_ui_delivery',None) is not None:sink.close()

    def test_failed_worker_retains_delivery_and_next_worker_reuses_it(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from ransomguard.ui_delivery import resident_delivery
        class Sink:
            enqueue_db = None
            closed = False
            def __enter__(self): return self
            def close(self): self.closed = True
        owner=SimpleNamespace();sink=Sink()
        with patch('ransomguard.ui_delivery.DurableUiDelivery', return_value=sink) as factory:
            with self.assertRaisesRegex(RuntimeError, 'analysis failed'):
                with resident_delivery(owner, 'unused') as active:
                    active.enqueue_db=object()
                    raise RuntimeError('analysis failed')
            self.assertFalse(sink.closed)
            self.assertIsNone(sink.enqueue_db)
            with resident_delivery(owner, 'unused') as active:
                self.assertIs(active,sink)
            self.assertTrue(sink.closed)
            self.assertIsNone(owner._retained_ui_delivery)
            self.assertEqual(factory.call_count,1)

    def test_linear_batch_matches_legacy_prefix_and_wire_bytes(self):
        import json
        from ransomguard.ui_delivery import build_delivery_items
        for text in ('', '한글😀' * 40, 'x' * 4000, 'x' * 65536):
            rows = [(str(i), json.dumps({'type': 'ALERT', 'data': {'text': text, 'index': i}})) for i in range(64)]
            expected = []
            for id_, payload in rows:
                candidate = expected + [{'id': id_, 'message': json.loads(payload)}]
                try:
                    encode_ui_jsonl({'deliveryVersion': 1, 'items': candidate})
                except ValueError:
                    break
                expected = candidate
            actual = build_delivery_items(rows)
            self.assertEqual(actual, expected)
            self.assertEqual(encode_ui_jsonl({'deliveryVersion': 1, 'items': actual}),
                             encode_ui_jsonl({'deliveryVersion': 1, 'items': expected}))

    def test_idle_delivery_does_not_open_pipe_but_status_still_delivers(self):
        with tempfile.TemporaryDirectory() as folder:
            opened = []
            statuses = []
            class StatusTransport(Transport):
                def send(self, status): statuses.append(status)
            def factory():
                opened.append(True)
                return StatusTransport()
            sink = DurableUiDelivery(Path(folder)/'queue', transport_factory=factory)
            for _ in range(10): self.assertFalse(sink.drain_once())
            self.assertEqual(opened, [])
            sink.send({'type': 'SYSTEM_STATUS', 'data': {}})
            sink.drain_once()
            self.assertEqual(len(statuses), 1)
            self.assertEqual(len(opened), 1)
            sink.close()

    def test_larger_batch_requires_ack_capability_and_downgrades_without_loss(self):
        with tempfile.TemporaryDirectory() as folder:
            transport=Transport();transport.peer_batch_limit=64
            sink=DurableUiDelivery(Path(folder)/'queue',transport_factory=lambda:transport)
            for i in range(100):sink.send({'type':'ALERT','data':{'index':i}})
            sink.drain_once()
            self.assertEqual(len(transport.seen),20)
            self.assertEqual(sink.batch_limit,64)
            transport.fail_after_commit=True
            with self.assertRaises(TimeoutError):sink.drain_once()
            self.assertEqual(sink.diagnostics()['pending'],80)
            self.assertEqual(sink.batch_limit,20)
            del transport.peer_batch_limit
            while sink.drain_once():pass
            self.assertEqual(len(transport.seen),100)
            self.assertEqual(sink.batch_limit,20)
            sink.close()

    def test_negotiated_batch_still_respects_wire_byte_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            class SizedTransport(Transport):
                peer_batch_limit=64
                def exchange(self,items):
                    self_size=len(encode_ui_jsonl({'deliveryVersion':1,'items':items}))
                    if self_size>65536:raise AssertionError('oversized envelope')
                    return super().exchange(items)
            transport=SizedTransport()
            sink=DurableUiDelivery(Path(folder)/'queue',transport_factory=lambda:transport)
            for i in range(80):sink.send({'type':'ALERT','data':{'index':i,'text':'x'*4000}})
            while sink.drain_once():pass
            self.assertEqual(len(transport.seen),80)
            sink.close()

    def test_ack_capability_is_bounded_and_legacy_optional(self):
        for cap,expected in [(None,20),(True,20),(0,20),('64',20),(64,64),(1000000,64)]:
            ack,limit=parse_commit_ack({'deliveryVersion':1,'ack':['a'],'maxBatchItems':cap},{'a'})
            self.assertEqual((ack,limit),(['a'],expected))
        self.assertEqual(parse_commit_ack({'deliveryVersion':1,'ack':['a']},{'a'}),(['a'],20))
        with self.assertRaises(ValueError):parse_commit_ack({'deliveryVersion':1,'ack':['foreign'],'maxBatchItems':64},{'a'})

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
