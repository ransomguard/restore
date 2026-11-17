import tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from ransomguard.outbox import Outbox
from ransomguard.retention import RawRetention
from ransomguard.ui_delivery import DurableUiDelivery

class AckPipe:
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def exchange(self,items):return [x['id'] for x in items]
    def send(self,message):pass

class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'outbox'
        self.out=Outbox(self.path);self.ret=RawRetention(self.out.db)
        self.sink=DurableUiDelivery(self.path,transport_factory=AckPipe)
    def tearDown(self):self.sink.close();self.out.close();self.tmp.cleanup()
    def event(self,pid=123,generation=456,finish=True):
        id_=self.out.append('kernel_event',{'pid':pid})
        self.ret.begin(id_,SimpleNamespace(pid=pid),generation)
        self.sink.send_tracked({'type':'FILE_WRITE','timestamp':1,'data':{}},event_id=id_)
        if finish:self.ret.finish(id_,'sent')
        return id_
    def cleanup(self):return self.ret.cleanup(now=time.time()+121,force=True)
    def exists(self,id_):return self.out.db.execute('SELECT 1 FROM events WHERE event_id=?',(id_,)).fetchone() is not None
    def test_requires_processed_and_real_ui_commit_ack(self):
        pending=self.event();unfinished=self.event(finish=False)
        self.assertEqual(self.cleanup(),0)
        self.sink.drain_once()
        self.assertEqual(self.cleanup(),1)
        self.assertFalse(self.exists(pending));self.assertTrue(self.exists(unfinished))
    def test_analysis_and_failed_recovery_are_preserved(self):
        id_=self.event();self.ret.protect(123,456,'candidate');self.sink.drain_once()
        result=SimpleNamespace(process=SimpleNamespace(pid=123,create_time=456),incident_id='failed',state='REVIEW_REQUIRED')
        self.ret.resolution(result,['sent'])
        self.assertEqual(self.cleanup(),0);self.assertTrue(self.exists(id_))
    def test_released_requires_all_result_messages_acknowledged(self):
        id_=self.event();self.ret.protect(123,456,'candidate');self.sink.drain_once()
        result=SimpleNamespace(process=SimpleNamespace(pid=123,create_time=456),incident_id='done',state='RELEASED')
        self.sink.send_tracked({'type':'ALERT'},incident_id='done')
        self.sink.send_tracked({'type':'VSS_STATUS'},incident_id='done')
        self.ret.resolution(result,['sent','sent'])
        self.assertEqual(self.cleanup(),0)
        self.sink.drain_once();self.assertEqual(self.cleanup(),1);self.assertFalse(self.exists(id_))
    def test_legacy_untracked_and_unrelated_records_never_deleted(self):
        old=self.out.append('kernel_event',{});failed=self.out.append('restore_failed',{},incident_id='incident')
        self.assertEqual(self.cleanup(),0);self.assertTrue(self.exists(old));self.assertTrue(self.exists(failed))
    def test_existing_ui_sampling_is_distinct_from_delivery_ack(self):
        id_=self.out.append('kernel_event',{})
        self.ret.begin(id_,SimpleNamespace(pid=123),456);self.ret.finish(id_,'rate_limited')
        self.assertEqual(self.ret.cleanup(force=True),0)
        self.assertEqual(self.cleanup(),1)
    def test_unknown_generation_hold_protects_reused_pid_conservatively(self):
        id_=self.event();self.ret.protect(123,None,'identity_unknown');self.sink.drain_once()
        self.assertEqual(self.cleanup(),0);self.assertTrue(self.exists(id_))
