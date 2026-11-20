import time,unittest
from ransomguard.buffered_reader import BufferedReader,RawQueue
import queue
class Reader:
 def __init__(self,n):self.n=n;self.i=0;self.closed=False
 def read(self,timeout_ms=100):
  if self.i>=self.n:time.sleep(.002);return None
  self.i+=1;return str(self.i).encode()
 def status(self):return {}
 def close(self):self.closed=True
class BufferedTests(unittest.TestCase):
 def test_byte_bound_preserves_fifo_without_evicting(self):
  q=RawQueue(100,byte_limit=8)
  q.put(b'123456')
  with self.assertRaises(queue.Full):q.put(b'789',timeout=.01)
  self.assertEqual(q.get_nowait(),b'123456')
  q.put(b'789');self.assertEqual(q.bytes,3)
  self.assertEqual(q.get_nowait(),b'789');self.assertEqual(q.bytes,0)
  self.assertEqual(q.peak_bytes,6)
 def test_record_count_and_invalid_size_are_bounded(self):
  q=RawQueue(1,byte_limit=8);q.put(b'a')
  with self.assertRaises(queue.Full):q.put_nowait(b'b')
  with self.assertRaises(ValueError):q.put(b'x'*9)
  self.assertEqual(q.get_nowait(),b'a')
 def test_backpressure_preserves_order_and_shutdown_tail(self):
  raw=Reader(100);b=BufferedReader(raw,2);b.__enter__();time.sleep(.12)
  first=b.read();pending=b.stop_and_drain()
  self.assertEqual([first]+pending,[str(i).encode() for i in range(1,raw.i+1)])
  self.assertGreater(b.full_waits,0);self.assertLessEqual(b.peak,2)
  b.__exit__();self.assertTrue(raw.closed)
 def test_reader_failure_is_not_silently_ignored(self):
  class Broken(Reader):
   def read(self,timeout_ms=100):raise OSError('driver failed')
  b=BufferedReader(Broken(0),2);b.__enter__()
  with self.assertRaises(OSError):b.read()
  self.assertEqual(b.stop_and_drain(),[]);b.__exit__()
