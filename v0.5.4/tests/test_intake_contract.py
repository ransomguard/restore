"""Exercise the storage-scope ABI and reject ambiguous status responses."""
import struct
import unittest
from pathlib import PureWindowsPath
from unittest.mock import Mock, patch

from ransomguard.protocol import MAGIC, VERSION, SET_INTERNAL_STORAGE
from ransomguard.windows_reader import WindowsDriverReader


class IntakeContractTests(unittest.TestCase):
    def reader(self):
        reader = object.__new__(WindowsDriverReader)
        reader._ioctl = Mock()
        return reader

    def test_exact_volume_path_and_fixed_abi(self):
        reader = self.reader()
        with patch('pathlib.Path.resolve', return_value=PureWindowsPath(r'C:\State\observe.sqlite3')), \
             patch('ransomguard.observer_filter._query_dos_device', return_value=r'\Device\HarddiskVolume3'):
            reader.configure_internal_storage('unused')
        code, payload, size, timeout = reader._ioctl.call_args.args
        self.assertEqual((code, len(payload), size, timeout), (SET_INTERNAL_STORAGE, 2060, 0, 5000))
        magic, version, length = struct.unpack('<III', payload[:12])
        self.assertEqual((magic, version), (MAGIC, VERSION))
        self.assertEqual(payload[12:12+length].decode('utf-16-le'), r'\Device\HarddiskVolume3\State\observe.sqlite3')
        self.assertEqual(set(payload[12+length:]), {0})

    def test_unknown_volume_does_not_guess_an_exclusion(self):
        reader = self.reader()
        with patch('ransomguard.observer_filter._query_dos_device', return_value=None):
            with self.assertRaises(ValueError):
                reader.configure_internal_storage('observe.sqlite3')
        reader._ioctl.assert_not_called()

    def test_separate_exclusion_counter_does_not_change_real_drops(self):
        reader = self.reader()
        reader._ioctl.side_effect = [struct.pack('<IIIIIIQQQQQQ', MAGIC, VERSION, 123, 1, 0, 0, 100, 7, 0, 0, 93, 0),
                                    struct.pack('<IIQQ', MAGIC, VERSION, 456, 3),
                                    struct.pack('<IIIIIIQQQQQ', MAGIC, VERSION, 0, 90, 1024, 32, 5, 2, 0, 30, 93)]
        result = reader.status()
        self.assertEqual((result['events_dropped'], result['internal_storage_excluded'], result['file_observations_omitted']), (7, 456, 3))
        self.assertEqual((result['queue_overflow_drops'],result['queue_allocation_failures']),(5,2))

    def test_invalid_extended_status_is_never_success(self):
        for response in (b'', struct.pack('<IIQQ', 0, VERSION, 1, 2)):
            reader = self.reader()
            reader._ioctl.side_effect = [struct.pack('<IIIIIIQQQQQQ', MAGIC, VERSION, 123, 1, 0, 0, 100, 7, 0, 0, 93, 0), response]
            with self.assertRaises(RuntimeError):
                reader.status()

    def test_only_explicit_unsupported_errors_are_compatible(self):
        for code in (1, 50, 5, 995):
            reader = self.reader()
            error = OSError('injected')
            error.winerror = code
            reader._ioctl.side_effect = [struct.pack('<IIIIIIQQQQQQ', MAGIC, VERSION, 123, 1, 0, 0, 100, 7, 0, 0, 93, 0), error, error]
            if code in (1, 50):
                self.assertEqual(reader.status()['events_dropped'], 7)
            else:
                with self.assertRaises(OSError):
                    reader.status()
