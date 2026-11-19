import json,tempfile,time,unittest,uuid
from pathlib import Path
from unittest.mock import patch
from contextlib import nullcontext,closing
import sqlite3
from ransomguard import manual_restore as m,scope_settings as s
from ransomguard.recovery import RecoveryEngine,LocalSnapshotBackend,RecoveryValidationError
from test_recovery import plan
class ManualRestoreTests(unittest.TestCase):
 def test_requires_explicit_confirmation(self):
  with self.assertRaises(ValueError):m.execute('unused',str(uuid.uuid4()),False)
 def test_engine_manual_permission_does_not_change_automatic_default(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);source=root/'snapshot';dest=root/'live'
   (source/'protected').mkdir(parents=True);(dest/'protected').mkdir(parents=True)
   (source/'protected/a.txt').write_text('before');(dest/'protected/a.txt').write_text('after')
   engine=RecoveryEngine(backend=LocalSnapshotBackend(source,dest));p=plan(['a.txt'])
   with self.assertRaises(RecoveryValidationError):engine.execute(p,allow_local_test=True)
   self.assertEqual((dest/'protected/a.txt').read_text(),'after')
   result=engine.execute(p,allow_local_test=True,manual_restore_confirmed=True)
   self.assertTrue(result['verified']);self.assertEqual((dest/'protected/a.txt').read_text(),'before')
 def test_expired_changed_and_consumed_previews_never_execute(self):
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp);(base/'protection.json').write_text('{}');token=str(uuid.uuid4());folder=base/'manual-restores';folder.mkdir()
   good={'state':'prepared','expires':time.time()+100,'scope_digest':m.scope_digest(base)}
   for update in ({'expires':0},{'scope_digest':'different'},{'state':'verified'}):
    (folder/(token+'.json')).write_text(json.dumps(good|update))
    with patch('ransomguard.snapshots.require_admin'),patch.object(m,'scope_lock',return_value=nullcontext()),patch.object(m,'assert_idle'),patch('ransomguard.recovery.RecoveryEngine.execute') as execute:
     with self.assertRaises(ValueError):m.execute(base,token,True)
     execute.assert_not_called()
 def test_terminal_reviews_preserved_but_active_blocks(self):
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp)
   with closing(sqlite3.connect(base/'holds.sqlite3',isolation_level=None)) as db:
    db.execute('CREATE TABLE firewall_holds(state TEXT)');db.execute("INSERT INTO firewall_holds VALUES('review_required')")
    s.assert_idle(base,allow_review=True)
    self.assertEqual(db.execute('SELECT COUNT(*) FROM firewall_holds').fetchone()[0],1)
    for state in ('active',None,'unknown'):
     db.execute('UPDATE firewall_holds SET state=?',(state,))
     with self.assertRaises(RuntimeError):s.assert_idle(base,allow_review=True)
if __name__=='__main__':unittest.main()
