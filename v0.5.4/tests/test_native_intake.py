import ctypes as C
import struct
import unittest
from ransomguard.windows_reader import WindowsDriverReader
from ransomguard.protocol import MAGIC, VERSION, EVENT_BATCH_BYTES

class NativeIntakeTests(unittest.TestCase):
    def reader(self, native):
        r=object.__new__(WindowsDriverReader)
        r.handle=123;r.batch_supported=None;r.native_read=native
        r.native_read_calls=0;r.native_read_seconds=0
        return r

    def test_native_packet_uses_the_existing_complete_packet_validation(self):
        record=struct.pack('<IIIIQQ',MAGIC,VERSION,1,32,1,2)
        packet=struct.pack('<IIII',MAGIC,VERSION,1,16+len(record))+record
        def native(handle,code,buffer,size,timeout,returned,elapsed):
            self.assertEqual(size,EVENT_BATCH_BYTES)
            C.memmove(buffer,packet,len(packet));returned._obj.value=len(packet)
            elapsed._obj.value=.125
            return 0
        r=self.reader(native)
        self.assertEqual(r.read_many(),[record])
        self.assertEqual(r.native_read_calls,1)
        self.assertEqual(r.native_read_seconds,.125)

    def test_drained_cancellation_is_an_empty_read_not_a_fabricated_record(self):
        self.assertEqual(self.reader(lambda *args:995).read_many(),[])

    def test_oversized_native_count_is_rejected(self):
        def native(*args):
            args[-2]._obj.value=EVENT_BATCH_BYTES+1
            return 0
        with self.assertRaises(RuntimeError): self.reader(native).read_many()

    def test_legacy_path_remains_available_without_dll(self):
        r=self.reader(None)
        r._ioctl=lambda *args:None
        self.assertEqual(r.read_many(),[])

    def test_reused_buffer_never_replays_old_bytes_after_short_read_or_cancel(self):
        first=struct.pack('<IIIIQQ',MAGIC,VERSION,1,32,1,2)
        second=struct.pack('<IIIIQQ',MAGIC,VERSION,1,32,2,3)
        packets=[struct.pack('<IIII',MAGIC,VERSION,2,80)+first+second,
                 None,struct.pack('<IIII',MAGIC,VERSION,1,48)+second]
        addresses=[]
        def native(handle,code,buffer,size,timeout,returned,elapsed):
            addresses.append(C.addressof(buffer));packet=packets.pop(0)
            if packet is None:return 995
            C.memmove(buffer,packet,len(packet));returned._obj.value=len(packet)
            return 0
        reader=self.reader(native)
        self.assertEqual(reader.read_many(),[first,second])
        self.assertEqual(reader.read_many(),[])
        self.assertEqual(reader.read_many(),[second])
        self.assertEqual(len(set(addresses)),1)
