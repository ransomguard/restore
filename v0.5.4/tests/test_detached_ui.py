import tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from ransomguard.outbox import Outbox
from ransomguard.retention import RawRetention
from ransomguard.ui_delivery import DurableUiDelivery
from ransomguard.delivery_pressure import DeliveryPressure

class DetachedUiTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'events.db'
  self.out=Outbox(self.path,max_pending=10)
  self.ret=RawRetention(self.out.db,detached_ui=True)
  self.sink=DurableUiDelivery(self.path,max_pending=2)
  self.sink.enable_detached_spool();self.sink.use_enqueue_connection(self.out.db)
 def tearDown(self):
  self.sink.close();self.out.close();self.tmp.cleanup()
 def event(self,finish=True):
  e=self.out.append('kernel_event',{'pid':7})
  self.ret.begin(e,SimpleNamespace(pid=7),8)
  self.sink.send_tracked({'type':'FILE_WRITE','timestamp':1,'data':{}},event_id=e)
  if finish:self.ret.finish(e,'sent')
  return e
 def test_disconnected_ui_preserves_all_rows_without_blocking_processed_intake(self):
  ids=[self.event() for _ in range(30)]
  self.assertEqual(self.out.db.execute('SELECT pending FROM events_capacity').fetchone()[0],0)
  self.assertEqual(self.out.db.execute('SELECT pending FROM ui_pending_capacity').fetchone()[0],30)
  self.assertFalse(DeliveryPressure(self.out.db,10,detached_ui=True).blocked())
  self.assertEqual(self.ret.cleanup(now=time.time()+200,force=True),0)
  self.assertEqual(self.out.db.execute('SELECT COUNT(*) FROM events WHERE acknowledged_at IS NULL').fetchone()[0],30)
  self.assertEqual(self.out.db.execute('SELECT COUNT(*) FROM ui_delivery_tracking WHERE acked=0').fetchone()[0],30)
 def test_unprocessed_event_keeps_its_slot(self):
  self.event(finish=False)
  self.assertEqual(self.out.db.execute('SELECT pending FROM events_capacity').fetchone()[0],1)
 def test_no_ui_payload_means_no_early_release(self):
  e=self.out.append('kernel_event',{})
  self.ret.begin(e,SimpleNamespace(pid=7),8);self.ret.finish(e,'sent')
  self.assertEqual(self.out.db.execute('SELECT pending FROM events_capacity').fetchone()[0],1)
 def test_spool_budget_rejects_without_evicting_old_evidence(self):
  self.event();before=self.out.db.execute('SELECT * FROM ui_pending').fetchall()
  self.sink.spool_byte_limit=1
  with self.assertRaisesRegex(RuntimeError,'byte budget'):self.sink.send({'type':'ALERT'})
  self.assertEqual(before,self.out.db.execute('SELECT * FROM ui_pending').fetchall())
 def test_byte_counter_rollback_and_ack_delete(self):
  self.event();used=self.out.db.execute('SELECT bytes FROM ui_spool_bytes').fetchone()[0]
  self.out.db.execute('BEGIN IMMEDIATE');self.out.db.execute('DELETE FROM ui_pending');self.out.db.rollback()
  self.assertEqual(self.out.db.execute('SELECT bytes FROM ui_spool_bytes').fetchone()[0],used)
  with self.out.db:self.out.db.execute('DELETE FROM ui_pending')
  self.assertEqual(self.out.db.execute('SELECT bytes FROM ui_spool_bytes').fetchone()[0],0)
 def test_disk_reserve_fails_closed_without_deleting(self):
  self.sink._disk_checked=0
  with patch('ransomguard.ui_delivery.shutil.disk_usage',return_value=SimpleNamespace(free=0)):
   with self.assertRaisesRegex(RuntimeError,'disk reserve'):self.sink.send({'type':'ALERT'})
 def test_restart_keeps_pending_payloads_and_correct_budget(self):
  self.event();old=self.out.db.execute('SELECT * FROM ui_pending').fetchall()
  self.sink.close();self.sink=DurableUiDelivery(self.path);self.sink.enable_detached_spool()
  self.assertEqual(old,self.sink.db.execute('SELECT * FROM ui_pending').fetchall())
  self.assertEqual(self.sink.db.execute('SELECT bytes FROM ui_spool_bytes').fetchone()[0],sum(len(r[2].encode()) for r in old))
 def test_upgrade_releases_only_finished_durably_queued_records(self):
  self.ret.detached_ui=False
  for _ in range(8):self.event()
  unfinished=self.event(finish=False)
  gate=DeliveryPressure(self.out.db,10,detached_ui=True)
  self.assertFalse(gate.blocked())
  self.assertEqual(self.out.db.execute('SELECT pending FROM events_capacity').fetchone()[0],1)
  self.assertEqual(self.out.db.execute('SELECT capacity_released FROM events WHERE event_id=?',(unfinished,)).fetchone()[0],0)
  self.assertEqual(self.out.db.execute('SELECT COUNT(*) FROM ui_pending').fetchone()[0],9)
 def test_failed_atomic_record_rolls_back_slot_payload_and_tracking_together(self):
  with self.assertRaisesRegex(ValueError,'abort'):
   with self.out.db.atomic_record():
    self.event()
    raise ValueError('abort')
  for table in ('events','raw_retention','ui_pending','ui_delivery_tracking'):
   self.assertEqual(self.out.db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0],0)
  self.assertEqual(self.out.db.execute('SELECT bytes FROM ui_spool_bytes').fetchone()[0],0)
