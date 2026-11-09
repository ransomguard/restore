"""Portable ABI tests only; a real Windows kernel test is still required."""

import struct
import unittest
from unittest.mock import Mock

from ransomguard.protocol import MAGIC, TERMINATE_PROCESS, VERSION
from ransomguard.windows_reader import WindowsDriverReader


class TerminationIoctlContractTests(unittest.TestCase):
    def reader(self, response):
        instance = object.__new__(WindowsDriverReader)
        instance._ioctl = Mock(return_value=response)
        return instance

    def test_explicit_generation_bound_request_and_response(self):
        reader = self.reader(struct.pack("<IIIi", MAGIC, VERSION, 3210, 0))
        result = reader.terminate_checked(pid=3210, expected_create_time=134000000000000001,
                                          reason=1001, explicit_authorization=True)
        reader._ioctl.assert_called_once_with(
            TERMINATE_PROCESS, struct.pack("<IIIIq", MAGIC, VERSION, 3210, 1001, 134000000000000001),
            16, 5000)
        self.assertTrue(result["request_accepted"])
        self.assertFalse(result["exit_confirmed"])

    def test_rejected_kernel_status_is_not_reported_as_accepted(self):
        reader = self.reader(struct.pack("<IIIi", MAGIC, VERSION, 3210, -1073741790))
        result = reader.terminate_checked(pid=3210, expected_create_time=134000000000000001,
                                          reason=1, explicit_authorization=True)
        self.assertFalse(result["request_accepted"])
        self.assertFalse(result["exit_confirmed"])
        self.assertTrue(result["kernel_ntstatus"].startswith("0xC"))

    def test_never_submit_without_explicit_permission_and_exact_generation(self):
        for params in (
            {"pid": 3210, "expected_create_time": 1, "reason": 1},
            {"pid": 4, "expected_create_time": 1, "reason": 1, "explicit_authorization": True},
            {"pid": 3210, "expected_create_time": 0, "reason": 1, "explicit_authorization": True},
            {"pid": 3210, "expected_create_time": 2**63, "reason": 1, "explicit_authorization": True},
            {"pid": 3210, "expected_create_time": 1, "reason": -1, "explicit_authorization": True},
        ):
            with self.subTest(params=params), self.assertRaises((PermissionError, ValueError)):
                self.reader(b"").terminate_checked(**params)

    def test_reject_truncated_or_mismatched_response(self):
        for response in (b"", struct.pack("<IIIi", MAGIC, VERSION, 9999, 0),
                         struct.pack("<IIIi", 0, VERSION, 3210, 0)):
            with self.subTest(response=response), self.assertRaises(RuntimeError):
                self.reader(response).terminate_checked(
                    pid=3210, expected_create_time=134000000000000001, reason=1,
                    explicit_authorization=True)


if __name__ == "__main__":
    unittest.main()
