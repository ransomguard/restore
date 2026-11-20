import tempfile,unittest
from pathlib import Path
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import patch
from ransomguard.outbox import Outbox
from ransomguard.retention import RawRetention
from ransomguard.ui_delivery import DurableUiDelivery
from ransomguard.observer_health import ObserverHealth

class Pipe:
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def exchange(self,items):return [i['id'] for i in items]
    def send(self,message):pass

class CompletionCapacityTests(unittest.TestCase):
    def test_ack_and_processing_order_both_release_without_deleting_held_raw(self):
        for ack_first in (False,True):
            with self.subTest(ack_first=ack_first),tempfile.TemporaryDirectory() as folder:
                path=Path(folder)/'db'
                with Outbox(path) as out,closing(DurableUiDelivery(path,transport_factory=Pipe)) as ui:
                    ret=RawRetention(out.db);ret.protect(99,123,'recovery_failed')
                    event=out.append('kernel_event',{'pid':99});ret.begin(event,SimpleNamespace(pid=99),123)
                    ui.send_tracked({'type':'FILE_WRITE','timestamp':1,'data':{}},event_id=event)
                    if ack_first:ui.drain_once()
                    self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0],1)
                    ret.finish(event,'sent')
                    if not ack_first:
                        self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0],1)
                        ui.drain_once()
                    self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0],0)
                    self.assertEqual(out.db.execute('SELECT acknowledged_at,capacity_released FROM events WHERE event_id=?',(event,)).fetchone(),(None,1))
                    self.assertEqual(ret.cleanup(now=10**12,force=True),0)
    def test_sampling_completion_releases_without_claiming_receipt(self):
        with tempfile.TemporaryDirectory() as folder,Outbox(Path(folder)/'db') as out:
            ret=RawRetention(out.db);event=out.append('kernel_event',{})
            ret.begin(event,SimpleNamespace(pid=99),123);ret.finish(event,'rate_limited')
            self.assertEqual(out.db.execute('SELECT pending FROM events_capacity').fetchone()[0],0)
            self.assertEqual(out.db.execute('SELECT ui_state FROM raw_retention').fetchone()[0],'not_required')
            self.assertIsNone(out.db.execute('SELECT acknowledged_at FROM events').fetchone()[0])
    def test_stop_file_checks_are_bounded_but_latch_within_interval(self):
        now=[10.0];h=ObserverHealth('ready.json','db',clock=lambda:now[0],stop_check_interval=.1)
        with patch.object(Path,'is_file',side_effect=[False,True]) as exists:
            for _ in range(1000):self.assertFalse(h.stop_requested())
            self.assertEqual(exists.call_count,1)
            now[0]=10.11;self.assertTrue(h.stop_requested())
            for _ in range(1000):self.assertTrue(h.stop_requested())
            self.assertEqual(exists.call_count,2)
