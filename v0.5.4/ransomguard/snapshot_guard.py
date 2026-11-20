"""One Windows process/thread gate shared by VSS maintenance and live recovery.

No filesystem/network policy changes. An abandoned mutex is reported as an
error; durable attempt journals decide whether a later operation may proceed.
"""
from contextlib import contextmanager
import ctypes
import sys
import threading

_offline_lock = threading.RLock()


@contextmanager
def snapshot_guard(timeout_ms=30000):
    if sys.platform != 'win32':
        with _offline_lock:
            yield
        return
    dll = ctypes.WinDLL('kernel32', use_last_error=True)
    dll.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    dll.CreateMutexW.restype = ctypes.c_void_p
    dll.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    dll.WaitForSingleObject.restype = ctypes.c_uint32
    dll.ReleaseMutex.argtypes = [ctypes.c_void_p]
    dll.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = dll.CreateMutexW(None, False, r'Global\RansomGuard.VssMaintenance.v1')
    if not handle:
        raise RuntimeError('Cannot open the VSS maintenance/recovery gate')
    owned = False
    try:
        outcome = dll.WaitForSingleObject(handle, timeout_ms)
        owned = outcome in (0, 0x80)
        if outcome != 0:
            raise RuntimeError('VSS maintenance gate busy or abandoned; retry after inspection')
        yield
    finally:
        if owned:
            dll.ReleaseMutex(handle)
        dll.CloseHandle(handle)
