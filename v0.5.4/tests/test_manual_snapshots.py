import json,tempfile,unittest,uuid
from pathlib import Path
from datetime import datetime,timezone,timedelta
from ransomguard.snapshots import HourlySnapshotCoordinator
from ransomguard.recovery import Snapshot
from test_snapshot_retention import RetentionTests,database,VOLUME

class ManualCreationTests(unittest.TestCase):
 def test_manual_bypasses_interval_but_duplicate_does_not_create(self):
  with tempfile.TemporaryDirectory() as tmp:
   now=datetime.now(timezone.utc);made=[]
   def create(volume,**kw):
    s=Snapshot('{'+str(uuid.uuid4())+'}',volume,now,r'\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9');made.append(s);return s
   c=HourlySnapshotCoordinator(Path(tmp)/'s.db',clock=lambda:now,volume_resolver=lambda _:VOLUME,create_fn=create)
   self.assertTrue(c.run()['created']);self.assertFalse(c.run()['attempted'])
   rid=str(uuid.uuid4());self.assertTrue(c.run(trigger='manual',request_id=rid)['created'])
   self.assertTrue(c.run(trigger='manual',request_id=rid)['duplicate_request']);self.assertEqual(len(made),2)
   self.assertFalse(c.run()['attempted'])
 def test_manual_never_bypasses_unknown_attempt(self):
  with tempfile.TemporaryDirectory() as tmp:
   now=datetime.now(timezone.utc)
   c=HourlySnapshotCoordinator(Path(tmp)/'s.db',clock=lambda:now,volume_resolver=lambda _:VOLUME)
   c._claim('C:\\',VOLUME)
   result=c.run(trigger='manual',request_id=str(uuid.uuid4()))
   self.assertFalse(result['attempted']);self.assertTrue(result['requires_reconciliation'])

class UserPinRetentionTests(RetentionTests):
 def test_user_pin_excludes_oldest_under_count_pressure(self):
  ident=self.items[0].snapshot_id
  with database(self.db) as db:
   db.execute('CREATE TABLE snapshot_user_pins(snapshot_id TEXT PRIMARY KEY)');db.execute('INSERT INTO snapshot_user_pins VALUES(?)',(ident,))
  r=self.manager().run(VOLUME,apply=True)
  self.assertNotIn(ident,self.deleted);self.assertIn(ident,r['protected_ids'])
 def test_all_pinned_blocks_capacity_instead_of_deleting(self):
  with database(self.db) as db:
   db.execute('CREATE TABLE snapshot_user_pins(snapshot_id TEXT PRIMARY KEY)');db.executemany('INSERT INTO snapshot_user_pins VALUES(?)',[(x.snapshot_id,) for x in self.items])
  r=self.manager().run(VOLUME,apply=True,reserve_for_creation=True)
  self.assertFalse(r['creation_allowed']);self.assertFalse(self.deleted)
 def test_removing_user_pin_keeps_incident_pin(self):
  ident=self.items[0].snapshot_id;self.pins.add(ident)
  with database(self.db) as db:
   db.execute('CREATE TABLE snapshot_user_pins(snapshot_id TEXT PRIMARY KEY)');db.execute('INSERT INTO snapshot_user_pins VALUES(?)',(ident,));db.execute('DELETE FROM snapshot_user_pins WHERE snapshot_id=?',(ident,))
  r=self.manager().run(VOLUME,apply=True)
  self.assertNotIn(ident,self.deleted);self.assertIn(ident,r['protected_ids'])

if __name__=='__main__':unittest.main()
