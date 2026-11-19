import sqlite3,tempfile,unittest
from pathlib import Path
from ransomguard.outbox import Outbox,OutboxFull
from ransomguard.ui_delivery import DurableUiDelivery

class CapacityTests(unittest.TestCase):
    def test_cross_connection_ack_delete_and_rollback(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'db'
            with Outbox(p,max_pending=2) as a,Outbox(p,max_pending=2) as b:
                x=a.append('a',{}); y=b.append('b',{})
                with self.assertRaises(OutboxFull): a.append('c',{})
                b.acknowledge([x],sent_ids=[x]); z=a.append('c',{})
                a.db.execute('BEGIN IMMEDIATE'); a.db.execute('delete from events where event_id=?',(z,)); a.db.rollback()
                self.assertEqual(a.db.execute('select pending from events_capacity').fetchone()[0],2)
                with b.db: b.db.execute('delete from events where event_id=?',(y,))
                self.assertEqual(a.db.execute('select pending from events_capacity').fetchone()[0],1)
                self.assertEqual(a.db.execute('select count(*) from events where acknowledged_at is null').fetchone()[0],1)

    def test_existing_database_and_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'db'
            db=sqlite3.connect(p)
            db.execute('create table events(sequence integer primary key autoincrement,event_id text unique,incident_id text,occurred_at text,kind text,payload text,acknowledged_at text)')
            db.executemany('insert into events(event_id,acknowledged_at) values(?,?)',[('a',None),('b','acked')]);db.commit();db.close()
            for _ in range(2):
                with Outbox(p) as a:self.assertEqual(a.db.execute('select pending from events_capacity').fetchone()[0],1)

    def test_ui_capacity_after_delete_and_full_queue(self):
        with tempfile.TemporaryDirectory() as d:
            s=DurableUiDelivery(Path(d)/'db',max_pending=1)
            try:
                s.send({'type':'ALERT'})
                with self.assertRaises(RuntimeError):s.send({'type':'ALERT'})
                with s.db:s.db.execute('delete from ui_pending')
                self.assertEqual(s.diagnostics()['pending'],0)
                s.send({'type':'ALERT'});self.assertEqual(s.diagnostics()['pending'],1)
            finally:s.close()
