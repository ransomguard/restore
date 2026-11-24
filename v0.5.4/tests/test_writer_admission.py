from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from ransomguard.writer_admission import WriterAdmission, for_database
from ransomguard.outbox import Outbox


class AdmissionTests(unittest.TestCase):
    def test_waiting_response_cannot_be_overtaken_by_next_passive_batch(self):
        gate=WriterAdmission(); first=object(); response=object(); passive=object();order=[]
        gate.acquire(first)
        def take(owner,label):
            gate.acquire(owner)
            try:order.append(label)
            finally:gate.release(owner)
        a=threading.Thread(target=take,args=(response,'response'));a.start()
        deadline=time.monotonic()+2
        while True:
            with gate.condition:queued=len(gate.waiters)
            if queued==1:break
            if time.monotonic()>deadline:self.fail('Waiter was not queued')
            time.sleep(.001)
        b=threading.Thread(target=take,args=(passive,'passive'));b.start()
        gate.release(first);a.join(2);b.join(2)
        self.assertEqual(order,['response','passive'])

    def test_timeout_does_not_block_subsequent_writer(self):
        gate=WriterAdmission();a=object();b=object();gate.acquire(a)
        with self.assertRaises(sqlite3.OperationalError):gate.acquire(b,timeout=.01)
        gate.release(a);gate.acquire(b);gate.release(b)
        self.assertFalse(gate.waiters)

    def test_commit_rollback_context_and_close_release_admission(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'events.db'
            box=Outbox(path)
            for finish in ('commit','rollback','context','close'):
                box.db.execute('BEGIN IMMEDIATE')
                self.assertIs(box.db.writer_admission.owner,box.db)
                if finish=='context':
                    with box.db:box.db.execute('SELECT 1')
                else:getattr(box.db,finish)()
                self.assertIsNone(for_database(path).owner)

    def test_atomic_record_keeps_admission_until_real_commit(self):
        with tempfile.TemporaryDirectory() as temp,Outbox(Path(temp)/'events.db') as box:
            with box.db.atomic_record():
                box.append('kernel_event',{'test':True})
                self.assertIs(box.db.writer_admission.owner,box.db)
            self.assertIsNone(box.db.writer_admission.owner)
            self.assertEqual(box.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)
            self.assertEqual(box.db.execute('PRAGMA synchronous').fetchone()[0],2)

    def test_failed_transaction_releases_slot_and_retains_rollback_semantics(self):
        with tempfile.TemporaryDirectory() as temp,Outbox(Path(temp)/'events.db') as box:
            with self.assertRaises(ValueError):
                with box.db.atomic_record():
                    box.append('kernel_event',{'test':True})
                    raise ValueError('test failure')
            self.assertIsNone(box.db.writer_admission.owner)
            self.assertEqual(box.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)

    def test_separate_databases_never_share_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertIsNot(for_database(Path(temp)/'a'),for_database(Path(temp)/'b'))

    def test_sql_commit_and_script_implicit_commit_release_gate(self):
        with tempfile.TemporaryDirectory() as temp,Outbox(Path(temp)/'events.db') as box:
            box.db.execute('BEGIN IMMEDIATE');box.db.execute('COMMIT')
            self.assertIsNone(box.db.writer_admission.owner)
            box.db.execute('BEGIN IMMEDIATE');box.db.executescript('SELECT 1;')
            self.assertIsNone(box.db.writer_admission.owner)

if __name__=='__main__':unittest.main()
