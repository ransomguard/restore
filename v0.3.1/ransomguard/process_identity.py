"""Live, generation-bound process observation for safe kernel termination.

Kernel file events carry only a PID. Never authorize termination from a PID or
from a cached UI millisecond timestamp. The exact 64-bit Windows creation
FILETIME must be verified via an open process handle and rechecked by the
kernel's generation-bound IOCTL. Hold the same process handle while waiting
for exit so PID reuse cannot create a false confirmation.
"""

from __future__ import annotations

import ctypes as C
import os

from .incidents import ProcessInstance


class ProcessIdentityError(RuntimeError):
    pass


DWORD = C.c_uint32
BOOL = C.c_int32
HANDLE = C.c_void_p


class _Filetime(C.Structure):
    _fields_ = [("dwLowDateTime", DWORD), ("dwHighDateTime", DWORD)]


def _filetime_number(value: _Filetime) -> int:
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


class WindowsProcessSession:
    def __init__(self, process: ProcessInstance):
        if not isinstance(process, ProcessInstance):
            raise TypeError("Exact process PID and creation FILETIME are required")
        if os.name != "nt":
            raise OSError("Live process generation verification requires Windows")
        self.process = process
        self.k = C.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "OpenProcess": ([DWORD, BOOL, DWORD], HANDLE),
            "GetProcessTimes": ([HANDLE, C.POINTER(_Filetime), C.POINTER(_Filetime),
                                 C.POINTER(_Filetime), C.POINTER(_Filetime)], BOOL),
            "WaitForSingleObject": ([HANDLE, DWORD], DWORD),
            "CloseHandle": ([HANDLE], BOOL),
        }
        for name, (argtypes, restype) in signatures.items():
            fn = getattr(self.k, name)
            fn.argtypes, fn.restype = argtypes, restype
        # PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, not PROCESS_TERMINATE.
        self.handle = self.k.OpenProcess(0x100000 | 0x1000, False, process.pid)
        if not self.handle:
            raise ProcessIdentityError("Cannot open live process handle to verify identity")
        try:
            created = _Filetime()
            exited = _Filetime()
            kernel = _Filetime()
            user = _Filetime()
            if not self.k.GetProcessTimes(self.handle, C.byref(created), C.byref(exited),
                                          C.byref(kernel), C.byref(user)):
                raise ProcessIdentityError("Cannot query live process creation time")
            if _filetime_number(created) != process.create_time:
                raise ProcessIdentityError("Live process PID belongs to a different generation")
        except BaseException:
            self.close()
            raise

    def is_exited(self) -> bool:
        if self.handle is None:
            raise ProcessIdentityError("Process identity handle is closed")
        result = self.k.WaitForSingleObject(self.handle, 0)
        if result not in (0, 258):
            raise ProcessIdentityError("Cannot determine process exit state")
        return result == 0

    def wait_exit(self, timeout_ms: int = 5000) -> bool:
        if self.handle is None:
            raise ProcessIdentityError("Process identity handle is closed")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60_000:
            raise ValueError("Process exit timeout must be 1..60000 ms")
        result = self.k.WaitForSingleObject(self.handle, timeout_ms)
        if result not in (0, 258):
            raise ProcessIdentityError("Cannot determine process exit state")
        return result == 0

    def close(self) -> None:
        if self.handle is not None:
            self.k.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self) -> "WindowsProcessSession":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
