import sqlite3,unittest
from ransomguard.delivery_pressure import DeliveryPressure

class PressureTests(unittest.TestCase):
 def test_waits_for_receipts_without_removing_any_record(self):
  db=sqlite3.connect(':memory:')
  self.addCleanup(db.close)
  db.executescript('CREATE TABLE events_capacity(singleton INTEGER,pending INTEGER); INSERT INTO events_capacity VALUES(1,8); CREATE TABLE ui_pending_capacity(singleton INTEGER,pending INTEGER); INSERT INTO ui_pending_capacity VALUES(1,8); CREATE TABLE evidence(id INTEGER); INSERT INTO evidence VALUES(1);')
  now=[0.];gate=DeliveryPressure(db,10,clock=lambda:now[0])
  self.assertTrue(gate.blocked());self.assertEqual(gate.waits,1)
  db.execute('UPDATE events_capacity SET pending=6');db.execute('UPDATE ui_pending_capacity SET pending=6');now[0]+=1
  self.assertTrue(gate.blocked())
  db.execute('UPDATE events_capacity SET pending=5');db.execute('UPDATE ui_pending_capacity SET pending=5');now[0]+=1
  self.assertFalse(gate.blocked());self.assertEqual(db.execute('SELECT * FROM evidence').fetchall(),[(1,)])
 def test_either_downstream_queue_can_hold_admission(self):
  db=sqlite3.connect(':memory:');self.addCleanup(db.close)
  db.executescript('CREATE TABLE events_capacity(singleton INTEGER,pending INTEGER); INSERT INTO events_capacity VALUES(1,1); CREATE TABLE ui_pending_capacity(singleton INTEGER,pending INTEGER); INSERT INTO ui_pending_capacity VALUES(1,9);')
  gate=DeliveryPressure(db,10);self.assertTrue(gate.blocked())
