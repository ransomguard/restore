import sqlite3,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from contextlib import closing
from ransomguard.outbox import Outbox
from ransomguard.retention import RawRetention
from ransomguard.ui_delivery import DurableUiDelivery


class AckPipe:
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def exchange(self,items):return [x['id'] for x in items]
    def send(self,message):pass


class AtomicEventStorageTests(unittest.TestCase):
    def test_event_commit_survives_a_slow_concurrent_writer(self):
        # Reproduce the VM's >5s ACK-writer lock. The raw event and UI request
        # must commit together after the writer releases, with no false ACK.
        import threading
        with tempfile.TemporaryDirectory() as directory, Outbox(Path(directory)/'db') as out:
            retention=RawRetention(out.db)
            with DurableUiDelivery(out.path,transport_factory=AckPipe) as sink:
                sink.use_enqueue_connection(out.db)
                held=threading.Event();errors=[]
                def writer():
                    try:
                        with closing(sqlite3.connect(out.path)) as db:
                            db.execute('BEGIN IMMEDIATE');held.set()
                            threading.Event().wait(5.4)
                            db.commit()
                    except BaseException as error:errors.append(error);held.set()
                thread=threading.Thread(target=writer);thread.start()
                try:
                    self.assertTrue(held.wait(3))
                    with out.db.atomic_record():
                        event_id=out.append('kernel_event',{'pid':101})
                        retention.begin(event_id,SimpleNamespace(pid=101),456)
                        sink.send_tracked({'type':'PROCESS_CREATE','data':{'processId':101}},event_id=event_id)
                        retention.finish(event_id,'sent')
                finally:thread.join(10)
                self.assertEqual(errors,[])
                self.assertFalse(thread.is_alive())
                # Delivery can race the assertion, but only a real transport
                # commit can mark this event acknowledged.
                sink.drain_once()
                self.assertEqual(out.db.execute('SELECT ui_state FROM raw_retention WHERE event_id=?',(event_id,)).fetchone()[0],'acked')
                self.assertEqual(len(out.pending()),1)

    def exercise(self,abort):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'outbox.db'
            with Outbox(path) as out, DurableUiDelivery(path,transport_factory=AckPipe) as sink, closing(sqlite3.connect(path)) as audit:
                retention=RawRetention(out.db);sink.use_enqueue_connection(out.db)
                try:
                    with out.db.atomic_record():
                        event_id=out.append('kernel_event',{'pid':99})
                        retention.begin(event_id,SimpleNamespace(pid=99),123)
                        sink.send_tracked({'type':'FILE_WRITE','timestamp':1,'data':{}},event_id=event_id)
                        retention.finish(event_id,'sent')
                        # Neither another reader nor the running ACK worker can
                        # observe a raw event or UI request before this commit.
                        for table in ('events','raw_retention','ui_pending','ui_delivery_tracking'):
                            self.assertEqual(audit.execute('SELECT COUNT(*) FROM '+table).fetchone()[0],0)
                        if abort:raise RuntimeError('simulated failure before commit')
                except RuntimeError:
                    if not abort:raise
                self.assertFalse(out.db.in_transaction)
                self.assertEqual(audit.execute('SELECT COUNT(*) FROM events').fetchone()[0],int(not abort))
                self.assertEqual(audit.execute('SELECT COUNT(*) FROM raw_retention').fetchone()[0],int(not abort))
                if abort:
                    self.assertEqual(audit.execute('SELECT COUNT(*) FROM ui_pending').fetchone()[0],0)
                    self.assertEqual(audit.execute('SELECT COUNT(*) FROM ui_delivery_tracking').fetchone()[0],0)
                    self.assertEqual(audit.execute('SELECT pending FROM events_capacity').fetchone()[0],0)
                else:
                    sink.drain_once()
                    self.assertEqual(audit.execute('SELECT ui_state FROM raw_retention WHERE event_id=?',(event_id,)).fetchone()[0],'acked')

    def test_raw_retention_and_ui_delivery_become_visible_atomically(self):self.exercise(False)
    def test_mid_record_failure_rolls_back_all_tables_and_capacity(self):self.exercise(True)

    def test_caught_inner_sql_failure_cannot_commit_partial_record(self):
        with tempfile.TemporaryDirectory() as directory, Outbox(Path(directory)/'db') as out:
            with self.assertRaises(RuntimeError):
                with out.db.atomic_record():
                    out.append('first',{})
                    try:
                        with out.db:out.db.execute('INSERT INTO table_that_does_not_exist VALUES(1)')
                    except sqlite3.Error:pass
                    out.append('second',{})
            self.assertEqual(out.pending(),[])

    def test_batched_events_commit_together_and_flush_tail(self):
        from ransomguard.storage_transaction import PassiveBatch
        with tempfile.TemporaryDirectory() as directory, Outbox(Path(directory)/'db') as out, closing(sqlite3.connect(out.path)) as audit:
            batch=PassiveBatch(out,limit=2,clock=lambda:0)
            with batch.record(b'first'):out.append('kernel_event',{'n':1})
            self.assertEqual(audit.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)
            with batch.record(b'second'):out.append('kernel_event',{'n':2})
            self.assertEqual(audit.execute('SELECT COUNT(*) FROM events').fetchone()[0],2)
            with batch.record(b'tail'):out.append('kernel_event',{'n':3})
            batch.flush()
            self.assertEqual(audit.execute('SELECT COUNT(*) FROM events').fetchone()[0],3)

    def test_batch_failure_preserves_every_raw_and_rolls_back_queued_ui(self):
        from ransomguard.storage_transaction import PassiveBatch
        with tempfile.TemporaryDirectory() as directory, Outbox(Path(directory)/'db') as out:
            batch=PassiveBatch(out,clock=lambda:0)
            with batch.record(b'first'):out.append('kernel_event',{'n':1})
            with self.assertRaises(RuntimeError):
                with batch.record(b'second'):
                    out.append('kernel_event',{'n':2})
                    raise RuntimeError('interrupted second record')
            self.assertEqual(out.pending(),[])
            self.assertEqual({r[0] for r in out.db.execute('SELECT raw FROM intake_unprocessed')},{b'first',b'second'})
            self.assertFalse(out.db.in_transaction)

    def test_batch_time_bound_flushes_before_size_limit(self):
        from ransomguard.storage_transaction import PassiveBatch
        clock=[0]
        with tempfile.TemporaryDirectory() as directory, Outbox(Path(directory)/'db') as out:
            batch=PassiveBatch(out,clock=lambda:clock[0])
            with batch.record(b'first'):
                out.append('kernel_event',{})
                clock[0]=.021
            self.assertFalse(out.db.in_transaction)

    def test_durable_ui_observer_executes_cleanup_and_commits_batched_tail(self):
        import argparse,contextlib,io,queue
        from unittest.mock import patch
        from ransomguard.cli import _observe
        from ransomguard.protocol import MAGIC,VERSION
        from tests.test_cli_integration import event_stream
        class Reader:
            def __init__(self):
                self.queue=queue.Queue()
                for raw in event_stream():self.queue.put(raw)
            def read(self):return self.queue.get_nowait()
            def status(self):return dict(magic=MAGIC,version=VERSION,engine_pid=800,fastpath_mode=1,self_protect_enabled=0,queue_depth=0,events_generated=3,events_delivered=3,events_dropped=0,events_flushed=0,processes_blocked=0,termination_requests_succeeded=0)
            def diagnostics(self):return {'capacity':8192}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'events.db'
            args=argparse.Namespace(config=None,db=str(path),live_track_a=False,live_track_b=False,ui=True,ui_durable=True,prefetch_events=8192,ready_file=None,ui_file_rate=10,limit=3,status_every=100,quiet_events=True)
            with patch('ransomguard.ui_delivery.WindowsUiPipe',return_value=AckPipe()),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(_observe(args,shared_reader=Reader()),0)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE kind='kernel_event'").fetchone()[0],3)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM raw_retention WHERE processed IS NOT NULL').fetchone()[0],3)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM ui_delivery_tracking').fetchone()[0],3)
