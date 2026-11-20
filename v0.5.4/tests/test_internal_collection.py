import unittest,tempfile
from pathlib import Path
from types import SimpleNamespace
from ransomguard.internal_collection import InternalCollection
from ransomguard.observer_filter import ObserverOutboxFilter
class InternalTests(unittest.TestCase):
 def test_unrelated_events_never_query_ui_process_handle(self):
  from unittest.mock import Mock
  with tempfile.TemporaryDirectory() as d:
   gate=InternalCollection(d);gate.ui_filter=ObserverOutboxFilter(Path(d)/'db.sqlite',observer_pid=77)
   alive=Mock(return_value=True);gate.owner=SimpleNamespace(alive=alive,created=100)
   for pid,path in ((78,'db.sqlite'),(77,'protected.txt')):
    for _ in range(100):
     self.assertFalse(gate.exclude(SimpleNamespace(pid=pid,filetime=101,event_type=4,fields={'path':str(Path(d)/path)})))
   alive.assert_not_called()
   self.assertTrue(gate.exclude(SimpleNamespace(pid=77,filetime=101,event_type=4,fields={'path':str(Path(d)/'db.sqlite')})))
   alive.assert_called_once()
 def test_scope_and_generation(self):
  with tempfile.TemporaryDirectory() as d:
   gate=InternalCollection(d);gate.collect=False
   gate.ui_filter=ObserverOutboxFilter(Path(d)/'db.sqlite',observer_pid=77)
   gate.owner=SimpleNamespace(alive=lambda:True,created=100)
   def event(pid=77,path=None,t=101,kind=4):return SimpleNamespace(pid=pid,filetime=t,event_type=kind,fields={'path':str(path or Path(d)/'db.sqlite')})
   self.assertTrue(gate.exclude(event()))
   self.assertFalse(gate.exclude(event(pid=78)))
   self.assertFalse(gate.exclude(event(path=Path(d)/'protected.txt')))
   self.assertFalse(gate.exclude(event(t=99)))
   self.assertFalse(gate.exclude(event(kind=3)))
   gate.owner=SimpleNamespace(alive=lambda:False,created=100)
   self.assertFalse(gate.exclude(event()))
 def test_on_retains_and_off_only_exact_state_files(self):
  import os
  with tempfile.TemporaryDirectory() as d:
   gate=InternalCollection(d)
   e=SimpleNamespace(pid=os.getpid(),event_type=4,filetime=1,fields={'path':str(Path(d)/'observer-ready.json.tmp')})
   self.assertTrue(gate.exclude(e));gate.collect=True;self.assertFalse(gate.exclude(e))
   gate.collect=False;e.fields['path']=str(Path(d)/'protected-manifest.json');self.assertFalse(gate.exclude(e))
 def test_bad_config_retains_evidence(self):
  with tempfile.TemporaryDirectory() as d:
   (Path(d)/'console-display.json').write_text('{bad json')
   gate=InternalCollection(d);gate.tick();self.assertTrue(gate.collect);self.assertIsNotNone(gate.error)
 def test_missing_writer_does_not_turn_default_off_on(self):
  with tempfile.TemporaryDirectory() as d:
   gate=InternalCollection(d);gate.tick()
   self.assertFalse(gate.collect);self.assertIsNotNone(gate.error)
   event=SimpleNamespace(pid=77,filetime=101,event_type=4,fields={'path':str(Path(d)/'db.sqlite')})
   self.assertFalse(gate.exclude(event))
 def test_verified_retired_writer_excludes_only_its_lifetime_and_exact_path(self):
  with tempfile.TemporaryDirectory() as d:
   gate=InternalCollection(d)
   old=SimpleNamespace(includes=lambda t:100<=t<=200,close=lambda:None)
   gate.retired=[(old,ObserverOutboxFilter(Path(d)/'db.sqlite',observer_pid=77))]
   def event(pid=77,t=150,name='db.sqlite-journal'):
    return SimpleNamespace(pid=pid,filetime=t,event_type=4,fields={'path':str(Path(d)/name)})
   self.assertTrue(gate.exclude(event()))
   self.assertFalse(gate.exclude(event(t=99)))
   self.assertFalse(gate.exclude(event(t=201)))
   self.assertFalse(gate.exclude(event(pid=78)))
   self.assertFalse(gate.exclude(event(name='document.txt')))
   self.assertEqual(gate.diagnostics()['ui_excluded'],1)
   gate.collect=True;self.assertFalse(gate.exclude(event()))
 def test_writer_rotation_retains_verified_old_binding(self):
  import json,os
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d:
   base=Path(d);(base/'installation.json').write_text(json.dumps({'ui':'trusted.exe'}));(base/'ui.pid').write_text('77')
   a=SimpleNamespace(alive=lambda:True,includes=lambda t:100<=t<=200,close=lambda:None)
   b=SimpleNamespace(alive=lambda:True,includes=lambda t:t>=300,close=lambda:None)
   with patch.dict(os.environ,{'RANSOM0_UI_DATABASE':str(base/'db.sqlite')}),patch('ransomguard.internal_collection.LiveOwner',side_effect=[a,b]):
    gate=InternalCollection(base);gate.tick();(base/'ui.pid').write_text('88');gate.next=0;gate.tick()
   self.assertFalse(gate.collect);self.assertIsNone(gate.error)
   self.assertEqual(len(gate.retired),1)
   self.assertTrue(gate.exclude(SimpleNamespace(pid=77,filetime=150,event_type=4,fields={'path':str(base/'db.sqlite-wal')})))
   self.assertTrue(gate.exclude(SimpleNamespace(pid=88,filetime=350,event_type=4,fields={'path':str(base/'db.sqlite-wal')})))
