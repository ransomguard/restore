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

    def test_cleanup_has_no_history_sized_temporary_sort(self):
        from ransomguard.retention import CLEANUP_QUERY
        plan=self.out.db.execute('EXPLAIN QUERY PLAN '+CLEANUP_QUERY,(time.time(),0,'',0,2000)).fetchall()
        self.assertFalse(any('TEMP B-TREE' in row[3] for row in plan),plan)
        self.assertTrue(any('raw_retention_due' in row[3] for row in plan),plan)

    def test_cleanup_is_bounded_and_preserves_held_and_unfinished_rows(self):
        now=time.time()
        with self.out.db:
            self.out.db.executemany("INSERT INTO events(event_id,occurred_at,kind,payload) VALUES(?,'fixture','kernel_event','{}')",[(str(i),) for i in range(2010)])
            self.out.db.executemany("INSERT INTO raw_retention VALUES(?,?,?,?,?)",[(str(i),9000+i,1,now-500+i/100,'not_required') for i in range(2010)])
            self.out.db.execute('INSERT INTO retention_holds VALUES(9000,1,\'candidate\')')
            self.out.db.execute('UPDATE raw_retention SET processed=NULL WHERE event_id=\'1\'')
        self.assertEqual(self.ret.cleanup(now=now,force=True),2000)
        self.assertTrue(self.exists('0'));self.assertTrue(self.exists('1'))
        self.assertEqual(self.ret.cleanup(now=now,force=True),8)

    def test_small_slices_eventually_reclaim_only_finished_unheld_evidence(self):
        now=time.time()
        with self.out.db:
            self.out.db.executemany("INSERT INTO events(event_id,occurred_at,kind,payload) VALUES(?,'fixture','kernel_event','{}')",[(str(i),) for i in range(12)])
            self.out.db.executemany("INSERT INTO raw_retention VALUES(?,?,?,?,?)",[(str(i),100+i,1,now-500,'not_required') for i in range(12)])
            self.out.db.execute("INSERT INTO retention_holds VALUES(100,1,'analysis')")
            self.out.db.execute("UPDATE raw_retention SET processed=NULL WHERE event_id='1'")
        ret=RawRetention(self.out.db,batch_limit=3,capacity_limit=2,interval=1)
        deleted=[ret.cleanup(now=now+i) for i in range(5)]
        self.assertEqual(deleted,[3,3,3,1,0])
        self.assertEqual({r[0] for r in self.out.db.execute('SELECT event_id FROM events')},{'0','1'})

    def test_capacity_release_is_bounded_without_deleting_held_evidence(self):
        now=time.time()
        with self.out.db:
            self.out.db.executemany("INSERT INTO events(event_id,occurred_at,kind,payload) VALUES(?,'fixture','kernel_event','{}')",[(str(i),) for i in range(10)])
            self.out.db.executemany("INSERT INTO raw_retention VALUES(?,?,?,?,?)",[(str(i),100,1,now-500,'not_required') for i in range(10)])
            self.out.db.execute("INSERT INTO retention_holds VALUES(100,1,'analysis')")
        ret=RawRetention(self.out.db,batch_limit=3,capacity_limit=2,interval=1)
        self.assertEqual(ret.cleanup(now=now),0)
        self.assertEqual(self.out.db.execute('SELECT SUM(capacity_released) FROM events').fetchone()[0],2)
        self.assertEqual(ret.cleanup(now=now+.5),0)
        self.assertEqual(self.out.db.execute('SELECT SUM(capacity_released) FROM events').fetchone()[0],2)
        self.assertEqual(ret.cleanup(now=now+1),0)
        self.assertEqual(self.out.db.execute('SELECT SUM(capacity_released) FROM events').fetchone()[0],4)
        self.assertEqual(self.out.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],10)

    def test_protected_prefix_does_not_force_one_unbounded_cleanup_scan(self):
        now=time.time()
        with self.out.db:
            self.out.db.executemany("INSERT INTO events(event_id,occurred_at,kind,payload) VALUES(?,'fixture','kernel_event','{}')",[(str(i),) for i in range(51)])
            self.out.db.executemany('INSERT INTO raw_retention VALUES(?,?,?,?,?)',[(str(i),100 if i<50 else 200,1,now-500+i,'not_required') for i in range(51)])
            self.out.db.execute("INSERT INTO retention_holds VALUES(100,1,'failed_recovery')")
        bounded=RawRetention(self.out.db,batch_limit=3,capacity_limit=2,interval=1)
        self.assertEqual(bounded.cleanup(now=now,force=True),0)
        self.assertTrue(self.exists('50'))
        reclaimed=sum(bounded.cleanup(now=now+n,force=True) for n in range(1,6))
        self.assertEqual(reclaimed,1)
        self.assertTrue(all(self.exists(str(i)) for i in range(50)))

    def test_repeated_diagnostic_startup_does_not_scan_raw_history(self):
        with self.out.db:
            self.out.db.executemany("INSERT INTO events(event_id,occurred_at,kind,payload) VALUES(?,'fixture','kernel_event','{}')",[(str(i),) for i in range(10000)])
        self.out.append('observer_started',{'fixture':True})
        self.assertEqual(self.out.enable_local_diagnostics(),1)
        callbacks=[]
        self.out.db.set_progress_handler(lambda:callbacks.append(1) or 0,100)
        try:self.assertEqual(self.out.enable_local_diagnostics(),0)
        finally:self.out.db.set_progress_handler(None,0)
        self.assertLess(len(callbacks),200)
        self.assertEqual(self.out.db.execute('SELECT count(*) FROM events').fetchone()[0],10000)
