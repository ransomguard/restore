import types,unittest
from unittest.mock import Mock,patch
from ransomguard.intake_scheduling import intake_priority
class IntakeSchedulingTests(unittest.TestCase):
 def test_priority_restored_on_worker_failure(self):
  restore=Mock();r=types.SimpleNamespace(thread=types.SimpleNamespace(native_id=123))
  with patch('ransomguard.intake_scheduling.os.name','nt'),patch('ransomguard.intake_scheduling._boost',return_value=restore) as boost:
   with self.assertRaises(RuntimeError):
    with intake_priority(r):
     self.assertEqual(r.intake_priority,'above_normal');raise RuntimeError('worker failed')
  boost.assert_called_once_with(123);restore.assert_called_once_with()
 def test_nonresident_does_not_open_thread(self):
  with patch('ransomguard.intake_scheduling._boost') as boost,intake_priority(None):pass
  boost.assert_not_called()
 def test_optional_priority_failure_does_not_stop_intake(self):
  r=types.SimpleNamespace(thread=types.SimpleNamespace(native_id=123))
  with patch('ransomguard.intake_scheduling.os.name','nt'),patch('ransomguard.intake_scheduling._boost',side_effect=OSError('denied')),intake_priority(r):
   self.assertTrue(r.intake_priority.startswith('unchanged:'))
