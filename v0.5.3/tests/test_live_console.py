import io,time,unittest
from types import SimpleNamespace
from ransomguard.live_console import LiveConsole
class ConsoleTests(unittest.TestCase):
 def test_bounded_offer_does_not_write_or_wait_for_display(self):
  sink=LiveConsole(io.StringIO(),capacity=2)
  event=SimpleNamespace(sequence=1,filetime=2,pid=3,kind='file_rename_attempted',fields={'path':'a.txt','new_extension':'locked','command_line':'SECRET'})
  for _ in range(100):sink.offer(event)
  self.assertEqual(sink.queue.qsize(),2);self.assertEqual(sink.omitted,98)
  self.assertNotIn('SECRET',str(list(sink.queue.queue)))
 def test_real_event_identity_is_displayed(self):
  stream=io.StringIO()
  with LiveConsole(stream) as sink:
   sink.offer(SimpleNamespace(sequence=42,filetime=2,pid=77,kind='process_created',fields={}))
   time.sleep(.3)
  self.assertIn('kernel_ioctl_live',stream.getvalue());self.assertIn('42',stream.getvalue())
 def test_toggle_keeps_other_process_and_other_path(self):
  import tempfile,json
  from pathlib import Path
  with tempfile.TemporaryDirectory() as d:
   control=Path(d)/'console-display.json';db=Path(d)/'db.sqlite'
   control.write_text(json.dumps({'visible':True,'showOwnDbEvents':False,'uiPid':77,'uiDbPath':str(db)}))
   sink=LiveConsole(io.StringIO(),control_path=control);sink._controls()
   def event(pid,path):return SimpleNamespace(event_type=4,sequence=1,filetime=2,pid=pid,kind='file_write_attempted',fields={'path':str(path)})
   sink.offer(event(77,db));self.assertEqual(sink.queue.qsize(),0)
   sink.offer(event(78,db));sink.offer(event(77,Path(d)/'other.txt'));self.assertEqual(sink.queue.qsize(),2)
   sink.show_own=True;sink.offer(event(77,db));self.assertEqual(sink.queue.qsize(),3)
 def test_control_survives_blocked_output(self):
  import tempfile,json,threading
  from pathlib import Path
  entered=threading.Event();release=threading.Event()
  class Blocked:
   def write(self,text):entered.set();release.wait(5)
   def flush(self):pass
  with tempfile.TemporaryDirectory() as d:
   control=Path(d)/'console-display.json'
   try:
    with LiveConsole(Blocked(),control_path=control) as sink:
     sink.offer(SimpleNamespace(sequence=1,filetime=2,pid=7,kind='process_created',fields={}))
     self.assertTrue(entered.wait(2))
     control.write_text(json.dumps({'visible':False,'showOwnDbEvents':True,'requestId':'blocked-writer-test'}))
     deadline=time.monotonic()+3;status=Path(d)/'console-display.status.json'
     while not status.exists() and time.monotonic()<deadline:time.sleep(.05)
     self.assertEqual(json.loads(status.read_text())['requestId'],'blocked-writer-test')
     self.assertTrue(sink.show_own)
     release.set()
   finally:release.set()
