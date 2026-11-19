import struct,time,unittest
from ransomguard.protocol import MAGIC,VERSION,GET_EVENT,GET_EVENT_BATCH,EVENT_BATCH_BYTES,EVENT_BATCH_LIMIT,split_event_batch,ProtocolError
from ransomguard.windows_reader import WindowsDriverReader
from ransomguard.buffered_reader import BufferedReader

def record(seq,size=32):return struct.pack('<IIIIQQ',MAGIC,VERSION,4,size,0,seq)+bytes(size-32)
def packet(rows):
    body=b''.join(rows)
    return struct.pack('<IIII',MAGIC,VERSION,len(rows),len(body)+16)+body

class BatchTests(unittest.TestCase):
    def test_variable_records_remain_complete_ordered_and_without_padding(self):
        rows=[record(1,1616),record(2,2232),record(3,1616)]
        self.assertEqual(split_event_batch(packet(rows)),rows)
    def test_legacy_and_larger_batches_preserve_every_record(self):
        for size in (32,128):
            rows=[record(n,2232) for n in range(size)]
            self.assertEqual(split_event_batch(packet(rows)),rows)
    def test_invalid_packets_fail_before_returning_partial_records(self):
        good=packet([record(1),record(2)])
        bad=[b'',good[:-1],good+b'x',packet([]),packet([record(n) for n in range(EVENT_BATCH_LIMIT+1)]),
             struct.pack('<IIII',MAGIC,VERSION,3,len(good))+good[16:],
             packet([record(1)])[:-32]+struct.pack('<IIIIQQ',MAGIC,VERSION,4,4000,0,1)]
        for raw in bad:
            with self.subTest(length=len(raw)),self.assertRaises(ProtocolError):split_event_batch(raw)
    def test_optional_abi_falls_back_only_for_unsupported_driver(self):
        reader=object.__new__(WindowsDriverReader);reader.batch_supported=None;calls=[]
        def ioctl(code,data,size,timeout):
            calls.append(code)
            if code==GET_EVENT_BATCH:
                e=OSError('unsupported');e.winerror=1;raise e
            return record(1)
        reader._ioctl=ioctl
        self.assertEqual(reader.read_many(),[record(1)]);self.assertEqual(reader.read_many(),[record(1)])
        self.assertEqual(calls,[GET_EVENT_BATCH,GET_EVENT,GET_EVENT])
        reader.batch_supported=None
        def denied(*args):e=OSError('denied');e.winerror=5;raise e
        reader._ioctl=denied
        with self.assertRaises(OSError):reader.read_many()
    def test_batch_timeout_is_empty_and_does_not_disable_batch(self):
        reader=object.__new__(WindowsDriverReader);reader.batch_supported=None
        reader._ioctl=lambda *args:None
        self.assertEqual(reader.read_many(),[]);self.assertTrue(reader.batch_supported)
    def test_shutdown_preserves_entire_unqueued_batch_tail_exactly_once(self):
        class Reader:
            def __init__(self):self.sent=False
            def read_many(self,timeout_ms):
                if self.sent:time.sleep(.002);return []
                self.sent=True;return [record(n) for n in range(32)]
            def close(self):pass
        b=BufferedReader(Reader(),2);b.__enter__()
        deadline=time.monotonic()+2
        while b.full_waits==0 and time.monotonic()<deadline:time.sleep(.01)
        first=b.read();pending=b.stop_and_drain()
        self.assertEqual([first]+pending,[record(n) for n in range(32)])
        self.assertEqual(b.stop_and_drain(),[])
        self.assertEqual(b.diagnostics()['peak_batch'],32)
