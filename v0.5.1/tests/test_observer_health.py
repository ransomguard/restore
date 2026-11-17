import json
import tempfile
import unittest
from pathlib import Path
from ransomguard.observer_health import ObserverHealth


class HealthTests(unittest.TestCase):
    def test_reports_actual_counters_without_resetting_and_bounds_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'ready.json';now=[10]
            h=ObserverHealth(path,Path(tmp)/'outbox.db',clock=lambda:now[0])
            h.publish({'events_dropped':12345},intake={'peak_buffer':3})
            before=path.read_bytes()
            now[0]=11;h.publish({'events_dropped':12346})
            self.assertEqual(path.read_bytes(),before)
            now[0]=15;h.publish({'events_dropped':12346})
            data=json.loads(path.read_text())
            self.assertEqual(data['driver_status']['events_dropped'],12346)
            self.assertTrue(data['driver_registered'])
            self.assertFalse(path.with_suffix('.json.tmp').exists())

    def test_stop_request_has_no_effect_until_explicit_file_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'ready.json';h=ObserverHealth(path,Path(tmp)/'db')
            self.assertFalse(h.stop_requested())
            path.with_suffix('.stop').write_text('maintenance')
            self.assertTrue(h.stop_requested())
            self.assertFalse(ObserverHealth(None,Path(tmp)/'db').stop_requested())
