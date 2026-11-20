import tempfile,unittest,json
from pathlib import Path
from datetime import datetime,timedelta,timezone
from ransomguard.snapshot_settings import interval_minutes,schedule_path,MINUTES
from ransomguard.snapshots import HourlySnapshotCoordinator
VOLUME='\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\'
class SettingsTests(unittest.TestCase):
 def test_each_interval_has_durable_boundary(self):
  for minutes in MINUTES:
   with self.subTest(minutes=minutes),tempfile.TemporaryDirectory() as tmp:
    db=Path(tmp)/'snapshots.sqlite3';schedule_path(db).write_text(json.dumps({'schema_version':1,'interval_minutes':minutes}))
    now=[datetime(2026,11,19,tzinfo=timezone.utc)]
    c=HourlySnapshotCoordinator(db,clock=lambda:now[0]);first=c._claim('C:\\',VOLUME)
    first.update(status='failed',requires_reconciliation=False);c._finish(first)
    now[0]+=timedelta(minutes=minutes,seconds=-1)
    self.assertFalse(c._claim('C:\\',VOLUME)['attempted'])
    now[0]+=timedelta(seconds=1)
    self.assertTrue(c._claim('C:\\',VOLUME)['attempted'])
 def test_unknown_attempt_blocks_even_after_interval_change(self):
  with tempfile.TemporaryDirectory() as tmp:
   db=Path(tmp)/'s.sqlite3';now=[datetime(2026,11,19,tzinfo=timezone.utc)]
   c=HourlySnapshotCoordinator(db,clock=lambda:now[0]);c._claim('C:\\',VOLUME)
   schedule_path(db).write_text(json.dumps({'schema_version':1,'interval_minutes':15}));now[0]+=timedelta(hours=4)
   self.assertEqual(c._claim('C:\\',VOLUME)['reason'],'unresolved_previous_attempt')
 def test_default_and_invalid_values(self):
  with tempfile.TemporaryDirectory() as tmp:
   db=Path(tmp)/'s.sqlite3';self.assertEqual(interval_minutes(db),60)
   for value in (True,1,45,0,'15',None):
    schedule_path(db).write_text(json.dumps({'schema_version':1,'interval_minutes':value}))
    with self.assertRaises(ValueError):interval_minutes(db)
if __name__=='__main__':unittest.main()
