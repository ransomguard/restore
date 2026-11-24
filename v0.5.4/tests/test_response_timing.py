import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from ransomguard.response_timing import ResponseOutbox


class TimingTests(unittest.TestCase):
    def test_writer_lock_wait_is_measured_and_record_retained(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'events.sqlite3'
            with ResponseOutbox(path) as box:
                ready=threading.Event()
                def hold():
                    db=sqlite3.connect(path)
                    try:
                        db.execute('BEGIN IMMEDIATE');ready.set();time.sleep(.15);db.commit()
                    finally:db.close()
                thread=threading.Thread(target=hold);thread.start();self.assertTrue(ready.wait(2))
                box.start_response_timing()
                box.append('termination_requested',{'pid':123},incident_id='test')
                thread.join(2)
                trace=box.db.response_trace
                self.assertGreater(next(x['seconds'] for x in trace if x['phase']=='begin_immediate'),.08)
                box.finish_response_timing('test')
                self.assertEqual(box.db.execute('SELECT count(*) FROM events').fetchone()[0],2)
                self.assertIsNone(box.db.response_trace)

    def test_trace_is_bounded_and_cleared_per_incident(self):
        with tempfile.TemporaryDirectory() as temp, ResponseOutbox(Path(temp)/'events.db') as box:
            box.start_response_timing()
            for _ in range(250):box.db.execute('SELECT 1')
            self.assertEqual(len(box.db.response_trace),192)
            box.start_response_timing()
            self.assertEqual(box.db.response_trace,[])

    def test_full_durability_unchanged(self):
        with tempfile.TemporaryDirectory() as temp, ResponseOutbox(Path(temp)/'events.db') as box:
            self.assertEqual(box.db.execute('PRAGMA synchronous').fetchone()[0],2)
            self.assertIsNone(box.db.response_trace)

if __name__=='__main__':unittest.main()
