import threading,unittest
from types import SimpleNamespace
from unittest.mock import Mock
from ransomguard.response_rearm import ResponseRearm
from ransomguard.live_pipeline import LivePipeline

class RearmTests(unittest.TestCase):
    def setUp(self):
        self.now=0
        self.p=SimpleNamespace(baseline=(7,0),invalid=threading.Event(),jobs=SimpleNamespace(active=threading.Event()))
        self.request=Mock(return_value={'id':'fresh'})
        self.r=ResponseRearm('ready.json',self.p,resident=True,clock=lambda:self.now,request=self.request)
        self.status={'events_dropped':8,'events_flushed':0,'queue_depth':0}
    def test_rearms_after_stable_drained_interval_without_clearing_invalid_old_worker(self):
        self.assertIsNone(self.r.tick(self.status,0));self.assertTrue(self.p.invalid.is_set())
        self.now=4;self.assertIsNone(self.r.tick(self.status,0))
        self.now=5;self.assertEqual(self.r.tick(self.status,0)['request_id'],'fresh')
        self.assertTrue(self.p.invalid.is_set());self.assertIsNone(self.r.tick(self.status,0))
        self.request.assert_called_once()
    def test_busy_queue_active_response_and_further_loss_restart_stability_window(self):
        for busy in ('queue','pending','active','loss'):
            with self.subTest(busy=busy):
                self.setUp();self.r.tick(self.status,0);self.now=10
                s=dict(self.status);pending=0
                if busy=='queue':s['queue_depth']=1
                if busy=='pending':pending=1
                if busy=='active':self.p.jobs.active.set()
                if busy=='loss':s['events_dropped']=9
                self.assertIsNone(self.r.tick(s,pending));self.request.assert_not_called()
                self.p.jobs.active.clear();self.now=11;self.assertIsNone(self.r.tick(s|{'queue_depth':0},0))
    def test_no_loss_or_nonresident_never_requests(self):
        self.r.tick(self.status|{'events_dropped':7},0);self.now=20
        self.r.tick(self.status|{'events_dropped':7},0);self.request.assert_not_called()
        self.r.enabled=False;self.r.tick(self.status,0);self.request.assert_not_called()
    def test_busy_reload_control_preserves_invalid_state_and_retries_later(self):
        self.request.side_effect=[PermissionError('busy'),{'id':'retry'}]
        self.r.tick(self.status,0);self.now=5
        self.assertIsNone(self.r.tick(self.status,0));self.assertTrue(self.p.invalid.is_set())
        self.assertEqual(self.r.last_error,'PermissionError')
        self.now=10;self.assertEqual(self.r.tick(self.status,0)['request_id'],'retry')
    def test_pre_worker_evidence_never_enters_new_response_epoch(self):
        p=LivePipeline.__new__(LivePipeline);p.started_filetime=100;p.outbox=Mock();p.jobs=Mock();p.window=Mock()
        p.candidate_b({'pid':50,'source_filetime':99})
        p.submit('A',{},pid=50,generation=1,path='x',filetime=99)
        p.jobs.enqueue.assert_not_called();p.window.begin.assert_not_called()
        self.assertEqual(p.outbox.append.call_count,2)
