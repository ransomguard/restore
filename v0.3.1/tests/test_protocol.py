import struct
import unittest
from ransomguard.protocol import *


def process_record(kind=1, sequence=1, pid=1234, created=999):
    raw = bytearray(PROCESS_SIZE)
    struct.pack_into("<IIIIQQ", raw, 0, MAGIC, VERSION, kind, PROCESS_SIZE, 133000000000000000, sequence)
    path = "C:\\lab\\sample.exe".encode("utf-16-le")
    command = "sample.exe --test".encode("utf-16-le")
    struct.pack_into("<IIIIqIIII", raw, 32, pid, 100, 100, 0, created, 0, len(path), len(command), 0)
    raw[72:72 + len(path)] = path
    raw[592:592 + len(command)] = command
    return bytes(raw)


def file_record(kind=4, sequence=2):
    raw = bytearray(FILE_SIZE)
    path = "\\Device\\HarddiskVolume3\\RansomGuardLab\\Protected\\문서.txt".encode("utf-16-le")
    ext = "locked".encode("utf-16-le") if kind == 5 else b""
    struct.pack_into("<IIIIQQ", raw, 0, MAGIC, VERSION, kind, FILE_SIZE, 133000000000000001, sequence)
    struct.pack_into("<IIIIII", raw, 32, 1234, kind - 3, len(path), len(ext), 16, 0)
    raw[56:56 + len(path)] = path
    raw[2104:2104 + len(ext)] = ext
    return bytes(raw)


class ProtocolTests(unittest.TestCase):
    def test_process_offsets_match_v1_windows_abi(self):
        event = decode_event(process_record())
        self.assertEqual(event.pid, 1234)
        self.assertEqual(event.fields["process_create_time"], 999)
        self.assertEqual(event.fields["image_path"], "C:\\lab\\sample.exe")
        self.assertEqual(event.fields["command_line"], "sample.exe --test")

    def test_file_utf16_and_rename_semantics(self):
        event = decode_event(file_record(5))
        self.assertIn("문서.txt", event.fields["path"])
        self.assertEqual(event.fields["new_extension"], "locked")
        self.assertEqual(event.fields["operation_result"], "unknown_pre_operation")

    def test_reject_bad_driver_buffers(self):
        for mutation in ("magic", "type", "length", "string_length", "truncated", "operation"):
            with self.subTest(mutation=mutation):
                raw = bytearray(file_record())
                if mutation == "magic": struct.pack_into("<I", raw, 0, 0)
                if mutation == "type": struct.pack_into("<I", raw, 8, 99)
                if mutation == "length": struct.pack_into("<I", raw, 12, PROCESS_SIZE)
                if mutation == "string_length": struct.pack_into("<I", raw, 40, 3)
                if mutation == "truncated": raw = raw[:-1]
                if mutation == "operation": struct.pack_into("<I", raw, 36, 2)
                with self.assertRaises(ProtocolError):
                    decode_event(bytes(raw))

    def test_pid_reuse_and_sequence_gap_invalidate_correlation(self):
        registry = ProcessRegistry()
        registry.update(decode_event(process_record(sequence=1)))
        self.assertEqual(registry.generation_for(1234), 999)
        registry.update(decode_event(process_record(kind=2, sequence=2)))
        self.assertIsNone(registry.generation_for(1234))
        registry.update(decode_event(process_record(sequence=3, created=1000)))
        self.assertEqual(registry.generation_for(1234), 1000)
        registry.update(decode_event(file_record(sequence=5)))
        self.assertIsNone(registry.generation_for(1234))
        self.assertTrue(registry.loss_detected)


if __name__ == "__main__":
    unittest.main()
