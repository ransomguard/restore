import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from ransomguard.outbox import Outbox
from ransomguard.live_pipeline import LivePipeline
from ransomguard.live_response import ResponseResult
from ransomguard.incidents import ProcessInstance
from ransomguard.ui_delivery import DurableUiDelivery

class ResponseDetachedTests(unittest.TestCase):
 def test_response_publishes_above_legacy_count_without_losing_terminal_state(self):
  with tempfile.TemporaryDirectory() as d, Outbox(Path(d)/'events.db') as out:
   with DurableUiDelivery(out.path) as init:
    init.enable_detached_spool()
   # Use a reduced limit to exercise exactly the same legacy overflow branch.
   factory=DurableUiDelivery
   def sink(path):return factory(path,max_pending=1)
   p=LivePipeline.__new__(LivePipeline)
   p.args=SimpleNamespace(response_no_recovery_required=True,response_manifest_template=None,
      response_state_db='unused',ui=True,ui_durable=True)
   p.profile=SimpleNamespace(jev_url='https://example.invalid');p.thresholds=None
   p.driver=None;p.config={};p.invalid=threading.Event();p.baseline=(0,0)
   result=ResponseResult('case','A',ProcessInstance(123,456))
   result.state='RELEASED';result.reason='exit_and_restore_verified'
   result.exit_confirmed=True;result.recovery_verified=True
   result.kernel_termination_accepted=True;result.recovery_snapshot_id='snapshot'
   result.recovered_files=['C:\\test\\one.txt'];result.recovery_root='C:\\test'
   with factory(out.path) as existing:
    existing.enable_detached_spool();existing.send({'type':'ALERT','data':{}})
   with patch('ransomguard.live_pipeline.FirewallHoldManager'),patch('ransomguard.live_pipeline.LiveResponseCoordinator') as coord,patch('ransomguard.live_pipeline.DurableUiDelivery',side_effect=sink):
    coord.return_value.respond.return_value=result
    state,reason=p._respond(dict(track='A',pid=123,generation=456,evidence={},path='C:\\test\\one.txt',filetime=1,deadline=0,id='case'),out,threading.Event())
   self.assertEqual(state,'RELEASED')
   self.assertGreater(out.db.execute('SELECT count(*) FROM ui_pending').fetchone()[0],1)
   self.assertGreater(out.db.execute("SELECT count(*) FROM ui_delivery_tracking WHERE incident_id='case'").fetchone()[0],0)
 def test_reopen_reuses_accounting_without_full_payload_scan(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'events.db'
   with DurableUiDelivery(path) as first:first.enable_detached_spool()
   with DurableUiDelivery(path) as second:
    sql=[];second.db.set_trace_callback(sql.append);second.enable_detached_spool()
    self.assertTrue(second.detached_ui)
    self.assertFalse(any('SUM(' in q.upper() or 'BEGIN IMMEDIATE' in q.upper() for q in sql))
