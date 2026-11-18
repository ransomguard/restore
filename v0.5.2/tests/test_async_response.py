import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from ransomguard.evidence_window import EvidenceWindow
from ransomguard.protocol import Event, ProcessRegistry
from ransomguard.outbox import Outbox
from ransomguard.response_jobs import ResponseJobs
from ransomguard.triage import TriageIntake
from tests.test_live_response import ResponseTests, FakeJev
from unittest.mock import patch,MagicMock
from types import SimpleNamespace


def event(kind, sequence, pid=50, **fields):
    return Event(kind, 'fixture', sequence, 1000 + sequence, pid, fields)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.prefix = r'\Device\HarddiskVolume3\lab'
        self.window = EvidenceWindow(self.prefix, clock=lambda: self.now)
        self.registry = ProcessRegistry()
        self.triage = TriageIntake()
        self.registry.update(event(1, 1, process_create_time=1000))
        self.triage.ingest(event(1, 1, process_create_time=1000), correlated_create_time=1000)
        first = event(4, 2, path=self.prefix+r'\a.bin', flags=8)
        self.registry.update(first)
        self.payload = self.triage.ingest(first, correlated_create_time=1000)[0].payload
        self.assertEqual(self.window.begin(self.payload), 'collecting')

    def test_automatic_facts_and_boundaries(self):
        for e in (event(5,3,path=self.prefix+r'\a.bin'),
                  event(4,4,path=self.prefix+r'\b.bin',flags=8),
                  event(3,5,pid=51,parent_pid=50,creator_pid=50,matched_rule_id=1001,process_create_time=1004)):
            self.registry.update(e); self.window.observe(e,self.registry)
        self.assertEqual(self.window.due(), [])
        self.now = 2.1
        item, = self.window.due()
        self.assertEqual(item['counts']['write_attempts'],2)
        self.assertEqual(item['counts']['rename_attempts'],1)
        self.assertEqual(len(item['corroborating_kernel_events']),1)
        self.assertFalse(item['complete_event_coverage'])
        self.assertEqual(item['evidence']['operation_result'],'unknown_pre_operation')
        self.assertNotIn('verified_write_effects',item)

    def test_pid_reuse_invalidates_not_reassigns(self):
        e=event(1,3,process_create_time=1003)
        self.registry.update(e)
        rejected=self.window.observe(e,self.registry)
        self.assertEqual(rejected[0]['deferred_reason'],'process_generation_ended')
        self.now=3
        self.assertEqual(self.window.due(),[])

    def test_gap_invalidates_and_does_not_create_evidence(self):
        e=event(4,4,path=self.prefix+r'\a.bin',flags=8)
        self.registry.update(e)
        self.assertEqual(self.window.observe(e,self.registry)[0]['deferred_reason'],'sequence_or_driver_loss')
        self.assertEqual(self.window.pending,{})

    def test_live_policy_original_survives_worker_reload(self):
        from ransomguard.live_pipeline import LivePipeline
        import struct
        args=SimpleNamespace(response_path_prefix=self.prefix,live_track_a=True)
        driver=SimpleNamespace(_ioctl=MagicMock())
        passive={'events_dropped':7,'events_flushed':0,'fastpath_mode':1,'self_protect_enabled':0}
        with patch('ransomguard.live_pipeline.ResponseJobs'):
            first=LivePipeline(None,driver,args,None,None,{},passive)
            second=LivePipeline(None,driver,args,None,None,{},passive|{'fastpath_mode':2})
            second.close()
        self.assertEqual(struct.unpack('<IIIII',driver._ioctl.call_args.args[1])[2:],(1,1,0))

    def test_recovery_writer_never_queues_a_response_against_collector(self):
        import os
        from ransomguard.live_pipeline import LivePipeline
        pipeline=LivePipeline.__new__(LivePipeline)
        pipeline.outbox=MagicMock();pipeline.jobs=MagicMock();pipeline.window=MagicMock()
        pipeline.candidate_b({'pid':os.getpid()})
        pipeline.submit('A',{},pid=os.getpid(),generation=1000,path=self.prefix,filetime=1000)
        pipeline.jobs.enqueue.assert_not_called();pipeline.window.begin.assert_not_called()
        self.assertEqual(pipeline.outbox.append.call_count,2)

    def test_different_creator_is_not_corroboration(self):
        e=event(3,3,pid=51,parent_pid=50,creator_pid=70,matched_rule_id=1001,process_create_time=1003)
        self.registry.update(e);self.window.observe(e,self.registry)
        self.now=3
        self.assertEqual(self.window.due()[0]['corroborating_kernel_events'],[])


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.box=Outbox(Path(self.temp.name)/'events.sqlite3')
        self.release=threading.Event()
        self.entered=threading.Event()
        self.calls=[]
        self.worker=None

    def tearDown(self):
        self.release.set()
        if self.worker:
            self.worker.request_stop()
            self.worker.thread.join(5)
            self.worker.close()
        self.box.close();self.temp.cleanup()

    def callback(self,job,outbox,cancel):
        self.calls.append(job['id']);self.entered.set()
        self.release.wait(4)
        return 'REVIEW_REQUIRED','test_no_external_actions'

    @staticmethod
    def job(id_='one',pid=50,track='B'):
        return dict(id=id_,pid=pid,generation=1000,track=track,evidence={})

    def wait_finished(self,id_):
        until=time.monotonic()+4
        while time.monotonic()<until:
            state=self.box.db.execute('SELECT state FROM response_jobs WHERE id=?',(id_,)).fetchone()[0]
            if state not in ('READY','RUNNING'):return state
            time.sleep(.01)
        self.fail('Worker did not finish')

    def test_slow_external_work_does_not_block_raw_commit_and_deduplicates_tracks(self):
        self.worker=ResponseJobs(self.box,self.callback).start()
        self.assertEqual(self.worker.enqueue(self.job()),'READY')
        self.assertTrue(self.entered.wait(2))
        self.assertEqual(self.worker.enqueue(self.job('two',track='A')),'duplicate')
        for i in range(100):self.box.append('kernel_event',{'sequence':i})
        self.assertEqual(self.box.db.execute("SELECT count(*) FROM events WHERE kind='kernel_event'").fetchone()[0],100)
        self.assertFalse(self.release.is_set())
        self.release.set()
        self.assertEqual(self.wait_finished('one'),'REVIEW_REQUIRED')
        self.assertEqual(self.calls,['one'])

    def test_uncommitted_job_cannot_run(self):
        from ransomguard.storage_transaction import PassiveBatch
        self.worker=ResponseJobs(self.box,self.callback).start()
        batch=PassiveBatch(self.box,limit=64,max_seconds=.05)
        with batch.record(b'fixture'):
            self.worker.enqueue(self.job())
            self.assertFalse(self.entered.wait(.15))
        batch.flush()
        self.assertTrue(self.entered.wait(2))

    def test_capacity_and_restart_retain_review_without_replay(self):
        self.worker=ResponseJobs(self.box,self.callback,max_pending=1).start()
        self.worker.enqueue(self.job())
        self.assertTrue(self.entered.wait(2))
        self.assertEqual(self.worker.enqueue(self.job('two',51)),'REVIEW_REQUIRED')
        self.release.set();self.wait_finished('one')
        self.worker.close()
        self.worker=ResponseJobs(self.box,self.callback).start()
        self.assertEqual(self.worker.enqueue(self.job()),'duplicate')
        self.assertEqual(self.calls,['one'])

    def test_old_ready_and_running_are_never_replayed(self):
        queue=ResponseJobs(self.box,self.callback)
        queue.enqueue(self.job())
        with self.box.db:self.box.db.execute("UPDATE response_jobs SET state='RUNNING'")
        self.worker=ResponseJobs(self.box,self.callback).start()
        self.assertEqual(self.wait_finished('one'),'REVIEW_REQUIRED')
        self.assertEqual(self.calls,[])


class GuardTests(ResponseTests):
    # Inherit the actual response fixture; only these new cases are added by
    # this subclass's loader below, avoiding redundant inherited test runs.
    def test_loss_while_jev_pending_never_kills_or_releases_hold(self):
        from ransomguard.live_response import LiveResponseCoordinator
        from ransomguard.incidents import ProcessInstance
        valid=[True]
        fake=FakeJev(.99)
        original=fake.evaluate
        def evaluate(evidence):
            valid[0]=False
            return original(evidence)
        fake.evaluate=evaluate
        # Use the existing fixture's coordinator with its real hold database.
        coordinator=self.coordinator
        coordinator.jev=fake
        coordinator.decision_guard=lambda:valid[0]
        result=coordinator.respond(track='B',process=self.process,jev_state={'test':True},
            recovery_required=False,explicit_authorization=True)
        self.assertEqual(result.state,'REVIEW_REQUIRED')
        self.assertTrue(result.firewall_hold_retained)
        self.assertEqual(self.driver.calls,[])


def load_tests(loader, tests, pattern):
    suite=unittest.TestSuite()
    for cls in (EvidenceTests,DispatchTests):suite.addTests(loader.loadTestsFromTestCase(cls))
    suite.addTest(GuardTests('test_loss_while_jev_pending_never_kills_or_releases_hold'))
    return suite
