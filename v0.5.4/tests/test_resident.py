import argparse
import contextlib
import io
import json
import sqlite3
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from ransomguard import resident
from ransomguard.cli import _observe
from tests.test_cli_integration import event_stream


class ResidentTests(unittest.TestCase):
    def test_new_owner_resumes_process_monitor_without_resetting_counters_or_mode(self):
        import struct
        from ransomguard.protocol import UPDATE_POLICY,MAGIC,VERSION
        class Reader:
            def __init__(self):self.records=iter(event_stream());self.calls=[]
            def read(self):return next(self.records)
            def status(self):return {'events_dropped':51879,'events_flushed':0,'fastpath_mode':1,'self_protect_enabled':0}
            def diagnostics(self):return {}
            def _ioctl(self,*args):self.calls.append(args)
        with tempfile.TemporaryDirectory() as directory:
            args=argparse.Namespace(config=None,db=str(Path(directory)/'db'),live_track_a=False,
                live_track_b=False,ui=False,ui_durable=False,prefetch_events=8192,ready_file=None,
                ui_file_rate=10,limit=3,status_every=50,quiet_events=True,
                _resident_info={'worker_generation':1})
            reader=Reader()
            with contextlib.redirect_stdout(io.StringIO()):_observe(args,shared_reader=reader)
            self.assertEqual(len(reader.calls),1)
            code,data,size,timeout=reader.calls[0]
            self.assertEqual(code,UPDATE_POLICY)
            self.assertEqual(struct.unpack('<IIIII',data),(MAGIC,VERSION,1,1,0))
            self.assertEqual(reader.status()['events_dropped'],51879)

    def test_registration_wait_retries_vm_busy_error_but_still_expires(self):
        error=OSError('VM exclusive engine busy');error.winerror=1359
        expected=object()
        with patch('time.sleep'),patch('time.monotonic',side_effect=[0,1,2]):
            factory=unittest.mock.Mock(side_effect=[error,error,expected])
            self.assertIs(resident.open_reader_wait(factory),expected)
        with patch('time.monotonic',side_effect=[0,31]):
            with self.assertRaises(OSError):resident.open_reader_wait(lambda: (_ for _ in ()).throw(error))

    def test_slow_processing_polls_real_status_before_record_count_threshold(self):
        clock=[0.0]
        class Reader:
            def __init__(self):self.records=iter(event_stream());self.reads=0;self.polls=[]
            def read(self):
                self.reads+=1;clock[0]+=2
                return next(self.records)
            def status(self):
                self.polls.append(self.reads)
                return {'events_dropped':17,'events_flushed':3}
            def diagnostics(self):return {'capacity':8192}
        with tempfile.TemporaryDirectory() as directory:
            args=argparse.Namespace(config=None,db=str(Path(directory)/'events.db'),live_track_a=False,
                live_track_b=False,ui=False,ui_durable=False,prefetch_events=8192,ready_file=None,
                ui_file_rate=10,limit=3,status_every=50,quiet_events=True)
            reader=Reader()
            with patch('time.monotonic',side_effect=lambda:clock[0]),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(_observe(args,shared_reader=reader),0)
            # All three slow records trigger a real status read; a synthetic
            # heartbeat or the old 50-record-only policy cannot satisfy this.
            self.assertEqual(reader.polls[:4],[0,1,2,3])

    def test_handshake_survives_transient_windows_share_violation(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'request.json';path.write_text('{"old":true}')
            original=Path.replace;attempts=[]
            def replace(source,target):
                attempts.append(1)
                if len(attempts)==1:
                    self.assertEqual(json.loads(path.read_text()),{'old':True})
                    raise PermissionError('temporary FILE_SHARE_DELETE conflict')
                return original(source,target)
            with patch.object(Path,'replace',replace):resident.write_json(path,{'new':True})
            self.assertEqual(json.loads(path.read_text()),{'new':True})
            self.assertEqual(len(attempts),2)

    def test_borrowed_reader_is_not_stopped_or_closed_at_worker_boundary(self):
        class Borrowed:
            def __init__(self): self.records=iter(event_stream()); self.calls=0
            def read(self): self.calls+=1; return next(self.records)
            def status(self): return {'events_dropped':17,'events_flushed':3}
            def diagnostics(self): return {'capacity':8192}
            def stop_and_drain(self): raise AssertionError('Worker stopped resident intake')
            def close(self): raise AssertionError('Worker unregistered the engine')
        with tempfile.TemporaryDirectory() as directory:
            args=argparse.Namespace(config=None,db=str(Path(directory)/'events.db'),live_track_a=False,
                live_track_b=False,ui=False,ui_durable=False,prefetch_events=8192,ready_file=None,
                ui_file_rate=10,limit=0,status_every=1,quiet_events=True)
            args._resident_info={'resident':True,'worker_generation':7,'worker_revision':'verified-revision'}
            reader=Borrowed()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(_observe(args,shared_reader=reader,reload_requested=lambda:reader.calls>=2),0)
            self.assertEqual(reader.calls,2)
            # The next raw record is still owned by the same resident reader.
            self.assertEqual(reader.read(),event_stream()[2])
            with contextlib.closing(sqlite3.connect(args.db)) as db:
                logs=[json.loads(r[0]) for r in db.execute("SELECT payload FROM events WHERE kind IN ('observer_started','observer_stopped') ORDER BY sequence")]
            self.assertEqual([r['resident_worker']['worker_generation'] for r in logs],[7,7])
            self.assertTrue(logs[-1]['driver_connection_retained'])

    def test_real_source_replacement_preserves_fifo_and_single_driver_owner(self):
        code='''import time
from pathlib import Path
VERSION = {version}
def _observe(args, *, shared_reader=None, reload_requested=None):
    while True:
        if reload_requested(): return 0
        raw=shared_reader.read()
        if raw is None: continue
        args.received.append((VERSION,int(raw)))
        if len(args.received)==20:
            args.reached.set(); assert args.changed.wait(5); time.sleep(.3)
        if len(args.received)==200:
            Path(args.ready_file).with_suffix('.stop').touch(); return 0
'''
        class Reader:
            def __init__(self): self.i=0; self.closed=0
            def read(self,timeout_ms=100):
                if self.i==200: time.sleep(.002); return None
                self.i+=1; return str(self.i).encode()
            def status(self):return {'engine_pid':123,'events_dropped':19,'events_flushed':7}
            def close(self):self.closed+=1
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);src=root/'src';src.mkdir()
            for name in (*resident.PINNED,'__init__.py'):(src/name).write_text('# immutable\n')
            (src/'cli.py').write_text(code.format(version=1))
            args=argparse.Namespace(live_track_a=False,live_track_b=False,prefetch_events=256,
                ready_file=str(root/'ready.json'),db=str(root/'outbox.db'),limit=0,
                received=[],reached=threading.Event(),changed=threading.Event())
            driver=Reader();errors=[]
            def target():
                try:resident.run(args,factory=lambda:driver)
                except BaseException as error:errors.append(error)
            with patch.object(resident,'__file__',str(src/'resident.py')):
                thread=threading.Thread(target=target);thread.start()
                try:
                    self.assertTrue(args.reached.wait(5));self.assertEqual(driver.closed,0)
                    (src/'cli.py').write_text(code.format(version=2))
                    resident.write_json(root/'ready.reload.json',{'id':'upgrade','expires':time.time()+30,
                        'revision':resident.source_revision(src)})
                    args.changed.set();thread.join(10)
                    self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
                finally:
                    (root/'ready.stop').touch();args.changed.set();thread.join(5)
            self.assertEqual([n for _,n in args.received],list(range(1,201)))
            self.assertEqual({v for v,_ in args.received},{1,2})
            self.assertEqual(driver.closed,1)  # Only final shutdown, never handover.

    def test_invalid_candidate_does_not_request_handover(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);src=root/'src';src.mkdir()
            for name in (*resident.PINNED,'__init__.py'):(src/name).write_text('# pinned\n')
            pinned={n:resident.fingerprint(src/n) for n in resident.PINNED}
            (src/'cli.py').write_text('invalid python syntax !!!!')
            path=root/'request.json'
            resident.write_json(path,{'id':'bad','expires':time.time()+30,'revision':resident.source_revision(src)})
            handover=resident.Handover(src,root/'cache',path,pinned,root/'result.json')
            self.assertFalse(handover.requested());self.assertIsNone(handover.pending)
            self.assertTrue(json.loads((root/'result.json').read_text())['old_worker_retained'])

    def test_driver_abi_changes_are_rejected_before_switch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);src=root/'src';src.mkdir()
            for name in (*resident.PINNED,'__init__.py'):(src/name).write_text('# pinned\n')
            pinned={n:resident.fingerprint(src/n) for n in resident.PINNED}
            (src/'protocol.py').write_text('# changed ABI\n')
            (src/'cli.py').write_text('def _observe(args, *, shared_reader=None, reload_requested=None): pass')
            with self.assertRaisesRegex(ValueError,'ABI'):
                resident.Worker(src,root/'cache',pinned)

    def test_live_resident_is_rejected_before_opening_driver(self):
        args=argparse.Namespace(live_track_a=True,live_track_b=False,prefetch_events=8192,ready_file='x')
        with self.assertRaises(ValueError):resident.run(args,factory=lambda:self.fail('opened driver'))
