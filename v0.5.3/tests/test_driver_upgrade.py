import json
import os
from pathlib import Path
import queue
import tempfile
import time
import unittest
from unittest.mock import patch

from ransomguard.counter_history import COUNTERS, CounterHistory
from ransomguard.driver_maintenance import DriverMaintenance


def status(generated=100, delivered=90, dropped=7, flushed=3):
    return dict(zip(COUNTERS, (generated, delivered, dropped, flushed, 0, 0)),
                queue_depth=0, fastpath_mode=1, self_protect_enabled=0)


class UpgradeTests(unittest.TestCase):
    def test_old_losses_survive_driver_reset_and_worker_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'counters.json'
            h = CounterHistory(path)
            old = status()
            self.assertEqual(h.observe(old, force=True), old)
            self.assertEqual(CounterHistory(path).observe(old), old)
            h = CounterHistory(path)
            new = status(20, 18, 2, 0)
            totals = h.observe(new, force=True)
            self.assertEqual((totals['events_dropped'], totals['events_flushed']), (9, 3))
            self.assertEqual(new['events_dropped'], 2)  # raw epoch unchanged
            self.assertEqual(CounterHistory(path).observe(new), totals)
            self.assertEqual(len(h.state['epochs']), 1)
            self.assertEqual(h.state['epochs'][0]['last']['events_flushed'], 3)

    def test_corrupt_history_is_not_silently_replaced_with_zero(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'counters.json'; path.write_text('{bad')
            with self.assertRaises(ValueError): CounterHistory(path)
            self.assertEqual(path.read_text(), '{bad')

    def test_explicit_unload_does_not_depend_on_a_smaller_new_counter(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'history.json'; h=CounterHistory(path)
            h.observe(status(10,10,0,0),force=True); epoch=h.state['current']['id']
            h.close_epoch(epoch,reason='SCM confirmed stopped')
            CounterHistory(path).close_epoch(epoch,reason='retry')
            h=CounterHistory(path)
            self.assertEqual(h.observe(status(50,50,0,0))['events_generated'],60)

    def test_busy_health_file_does_not_stop_intake(self):
        from ransomguard.observer_health import ObserverHealth
        with tempfile.TemporaryDirectory() as d:
            h=ObserverHealth(Path(d)/'ready.json',Path(d)/'db')
            with patch('ransomguard.counter_history.atomic_json',side_effect=PermissionError('busy')):
                h.publish(status(),force=True)
            h.publish(status(),force=True)
            self.assertTrue(h.path.exists())

    def test_status_coalescing_keeps_latest_total_and_does_not_delay_events(self):
        from ransomguard.ui_bridge import UiBestEffortPublisher
        from tests.test_ui_bridge import MockSink,status as ui_status,process_event
        now=[0.0];sink=MockSink();publisher=UiBestEffortPublisher(sink,clock=lambda:now[0])
        first=ui_status();self.assertEqual(publisher.publish_status(first),'sent')
        latest={**first,'events_dropped':1000}
        now[0]=.5;self.assertEqual(publisher.publish_status(latest),'status_coalesced')
        self.assertEqual(publisher.publish_event(process_event()),'sent')
        now[0]=2.;self.assertEqual(publisher.publish_status(latest),'sent')
        self.assertEqual(sink.messages[-1]['data']['eventsDropped'],1000)

    def test_expired_or_wrong_owner_request_never_pauses(self):
        with tempfile.TemporaryDirectory() as d:
            ready = Path(d)/'ready.json'; r = FakeReader()
            m = DriverMaintenance(ready, r, session='current', enabled=True)
            m.path.write_text(json.dumps(dict(id='x', pid=os.getpid(), session='old',
                action='pause_and_drain', expires=time.time()+30)))
            m.tick(status(), idle=True)
            self.assertEqual(r.calls, [])

    def test_pause_waits_for_empty_queues_and_expiry_resumes(self):
        with tempfile.TemporaryDirectory() as d:
            ready = Path(d)/'ready.json'; r = FakeReader()
            m = DriverMaintenance(ready, r, session='current', enabled=True)
            m.path.write_text(json.dumps(dict(id='x', pid=os.getpid(), session='current',
                action='pause_and_drain', expires=time.time()+30)))
            m.tick(status(), idle=True)
            self.assertEqual(r.calls[-1], 0)
            r.queue.put(b'undelivered')
            m.tick(status(), idle=True)
            self.assertFalse(m.drained)
            r.queue.get()
            with patch('ransomguard.driver_maintenance.time.monotonic', return_value=10):
                m.tick(status(), idle=True)
            with patch('ransomguard.driver_maintenance.time.monotonic', return_value=13):
                m.tick(status(), idle=True)
            self.assertTrue(m.drained)
            self.assertEqual(json.loads(m.path.with_suffix('.result.json').read_text())['state'], 'drained')
            m.active['expires'] = 0
            m.tick(status(), idle=True)
            self.assertEqual(r.calls[-1], 1)
            self.assertFalse(m.drained)

    def test_worker_error_restores_monitor_even_after_drain(self):
        with tempfile.TemporaryDirectory() as d:
            r = FakeReader(); m = DriverMaintenance(Path(d)/'r.json', r, session='s', enabled=True)
            m.active = {'id':'x', 'status':status()}; m.drained = True
            m.close(stopping=False)
            self.assertEqual(r.calls, [1])


class FakeReader:
    def __init__(self): self.calls=[]; self.queue=queue.Queue()
    def _ioctl(self, code, payload, output, timeout):
        import struct
        self.calls.append(struct.unpack('<IIIII', payload)[3])
