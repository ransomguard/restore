import json
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from ransomguard.buffered_reader import RawQueue
from ransomguard.evidence_peek import pending_evidence
from ransomguard.evidence_window import EvidenceWindow
from ransomguard.protocol import Event, ProcessRegistry, decode_event
from ransomguard.outbox import Outbox
from ransomguard.response_jobs import ResponseJobs
from tests.test_protocol import file_record, process_record
from tests.test_async_response import EvidenceTests
from unittest.mock import MagicMock


class BacklogWindowTests(EvidenceTests):
    def test_tick_cannot_peek_around_a_malformed_raw_invalidation(self):
        from ransomguard.live_pipeline import LivePipeline
        pipeline=LivePipeline.__new__(LivePipeline)
        pipeline.registry=self.registry;pipeline.registry.invalidate()
        pipeline.window=self.window;pipeline.invalid=threading.Event()
        pipeline.reader=SimpleNamespace(queue=RawQueue(10))
        pipeline.args=SimpleNamespace(live_track_a=True)
        pipeline.jobs=MagicMock(error=None);pipeline.outbox=MagicMock()
        pipeline.tick()
        self.assertTrue(pipeline.invalid.is_set())
        self.assertEqual(self.window.pending,{})
        pipeline.jobs.enqueue.assert_not_called()

    def test_wait_for_queue_and_count_peeked_event_only_once(self):
        e = Event(4, 'file_write_attempted', 3, 1003, 50, {'path': self.prefix+r'\b', 'flags': 8})
        self.registry.update(e)
        self.window.observe(e, self.registry)
        self.window.observe(e, self.registry)
        self.now = 3
        self.assertEqual(self.window.due(caught_up=False), [])
        item, = self.window.due(caught_up=True)
        self.assertEqual(item['counts']['write_attempts'], 2)

    def test_source_time_window_does_not_expand_under_backlog(self):
        e = Event(4, 'file_write_attempted', 3, 30_001_003, 50, {'path': self.prefix+r'\b', 'flags': 8})
        self.registry.update(e); self.window.observe(e, self.registry)
        self.now = 3
        self.assertEqual(self.window.due()[0]['counts']['write_attempts'], 1)

    def test_corroborated_rule_promotes_without_waiting_wall_clock(self):
        e = Event(3, 'process_creation_blocked', 3, 1003, 51,
                  dict(parent_pid=50, creator_pid=50, matched_rule_id=1001, process_create_time=1002))
        self.registry.update(e); self.window.observe(e, self.registry)
        proof, = self.window.confirmed_a()
        self.assertEqual(proof['create_time'], 1000)
        self.assertEqual(self.window.pending, {})


class PeekTests(unittest.TestCase):
    def test_120k_fifo_is_unchanged_and_only_related_record_decoded(self):
        queue = RawQueue(131072)
        for seq in range(2, 120002):
            raw = bytearray(file_record(sequence=seq))
            struct.pack_into('<I', raw, 32, 900)
            queue.put(bytes(raw))
        queue.put(file_record(sequence=120002))
        registry = ProcessRegistry(); registry.update(decode_event(process_record()))
        before = queue.qsize(), queue.bytes
        events, metrics = pending_evidence(SimpleNamespace(queue=queue), registry, {1234:999})
        found = [(e.sequence, r.generation_for(e.pid)) for e, r in events]
        self.assertEqual(found, [(120002,999)])
        self.assertEqual((queue.qsize(),queue.bytes), before)
        self.assertEqual(registry._last_sequence, 1)
        self.assertEqual(metrics['records'], 120001)
        repeated, second = pending_evidence(SimpleNamespace(queue=queue), registry, {1234:999},
                                            validated_through=metrics['validated_through'])
        self.assertEqual(list(repeated), [])
        self.assertEqual(second['scanned'], 0)
        queue.put(file_record(sequence=120003))
        tail, third = pending_evidence(SimpleNamespace(queue=queue), registry, {1234:999},
                                       validated_through=metrics['validated_through'])
        self.assertEqual([e.sequence for e,_ in tail], [120003])
        self.assertEqual(third['scanned'], 1)

    def test_gap_rejected_before_any_evidence_is_exposed(self):
        queue = RawQueue(10); queue.put(file_record(sequence=3))
        registry = ProcessRegistry(); registry.update(decode_event(process_record()))
        with self.assertRaises(ValueError):
            pending_evidence(SimpleNamespace(queue=queue), registry, {1234:999})

    def test_private_registry_observes_reused_pid(self):
        queue = RawQueue(10)
        queue.put(process_record(sequence=2,created=2000)); queue.put(file_record(sequence=3))
        registry = ProcessRegistry(); registry.update(decode_event(process_record()))
        events, _ = pending_evidence(SimpleNamespace(queue=queue), registry, {1234:999})
        self.assertEqual([r.generation_for(e.pid) for e,r in events], [2000,2000])
        self.assertEqual(registry.generation_for(1234),999)


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.box = Outbox(Path(self.temp.name)/'events.db')
        self.worker = None
        self.release = threading.Event()
        stamp = int((time.time()+11644473600)*10_000_000)
        self.b = dict(id='incident-b',track='B',pid=50,generation=1000,path='protected',filetime=stamp,
                      deadline=time.time()+30,evidence={'facts': True})
        self.a = self.b | dict(id='incident-a',track='A',evidence=dict(pid=50,create_time=1000,
                      parent_pid=50,creator_pid=50,path='protected',high_entropy_write=True,
                      matched_rule_id=1001,blocked_child_pid=51,write_filetime=stamp-100,rule_filetime=stamp))

    def tearDown(self):
        self.release.set()
        if self.worker:
            self.worker.request_stop()
            if self.worker.thread:self.worker.thread.join(5)
            self.worker.close()
        self.box.close();self.temp.cleanup()

    def wait_for(self, predicate):
        until=time.monotonic()+4
        while time.monotonic()<until:
            if predicate():return
            time.sleep(.01)
        self.fail('worker timed out')

    def test_ready_upgrade_keeps_incident_identity(self):
        calls=[]
        self.worker=ResponseJobs(self.box,lambda j,*_: (calls.append(j) or ('RELEASED','done')))
        self.worker.enqueue(self.b)
        self.assertEqual(self.worker.enqueue(self.a),'TRACK_A_PROMOTED')
        self.worker.start();self.wait_for(lambda: len(calls)==1)
        self.assertEqual((calls[0]['id'],calls[0]['track']),('incident-b','A'))

    def test_running_jev_review_upgrades_once_and_preserves_original_ledger(self):
        calls=[];entered=threading.Event()
        def callback(job,*_):
            calls.append(job['track']);entered.set()
            if job['track']=='B':
                self.release.wait(3)
                return 'REVIEW_REQUIRED','jev_ambiguous_demo_threshold'
            return 'RELEASED','exit_and_restore_verified'
        self.worker=ResponseJobs(self.box,callback).start();self.worker.enqueue(self.b)
        self.assertTrue(entered.wait(2))
        self.assertEqual(self.worker.enqueue(self.a),'TRACK_A_EVIDENCE_RETAINED')
        self.release.set()
        self.wait_for(lambda: self.box.db.execute("SELECT state FROM response_jobs WHERE id='incident-b'").fetchone()==('RELEASED',))
        self.assertEqual(calls,['B','A'])
        self.assertEqual(self.worker.enqueue(self.a),'duplicate')
        self.assertEqual(self.box.db.execute('SELECT state,reason FROM track_a_upgrade_history').fetchone(),
                         ('REVIEW_REQUIRED','jev_ambiguous_demo_threshold'))

    def test_termination_failure_must_not_be_retried(self):
        self.worker=ResponseJobs(self.box,lambda *_:('REVIEW_REQUIRED','process_exit_not_confirmed')).start()
        self.worker.enqueue(self.b)
        self.wait_for(lambda: self.box.db.execute("SELECT state FROM response_jobs WHERE id='incident-b'").fetchone()==('REVIEW_REQUIRED',))
        self.worker.enqueue(self.a)
        self.assertEqual(self.box.db.execute('SELECT track,state FROM response_jobs').fetchone(),('B','REVIEW_REQUIRED'))

    def test_old_worker_and_forged_creator_do_not_upgrade(self):
        self.worker=ResponseJobs(self.box,lambda *_:('RELEASED','done'))
        self.worker.enqueue(self.b)
        bad=self.a | {'evidence':self.a['evidence'] | {'creator_pid':999}}
        self.assertEqual(self.worker.enqueue(bad),'duplicate')
        self.worker.owner='new-worker'
        self.assertEqual(self.worker.enqueue(self.a),'duplicate')
