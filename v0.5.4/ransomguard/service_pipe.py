"""The service never delegates its token to an interactive named-pipe server."""
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import sys


CLIENT_FLAGS = 0x40000000 | 0x00100000  # FILE_FLAG_OVERLAPPED | SQOS_PRESENT, SECURITY_ANONYMOUS


def verify_peer(handle, image):
    if os.environ.get("RANSOM0_SERVICE_STORAGE") != "1":
        return
    kernel = C.WinDLL("kernel32", use_last_error=True)
    kernel.GetNamedPipeServerProcessId.argtypes = [W.HANDLE, C.POINTER(W.ULONG)]
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
    kernel.CloseHandle.argtypes = [W.HANDLE]
    security = C.WinDLL("advapi32", use_last_error=True)
    security.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    security.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, W.LPVOID, W.DWORD, C.POINTER(W.DWORD)]
    pid = W.ULONG()
    if not kernel.GetNamedPipeServerProcessId(handle, C.byref(pid)):
        raise C.WinError(C.get_last_error())
    process = kernel.OpenProcess(0x1000, False, pid.value)
    if not process:
        raise C.WinError(C.get_last_error())
    try:
        buf = C.create_unicode_buffer(32768)
        size = W.DWORD(len(buf))
        if not kernel.QueryFullProcessImageNameW(process, 0, buf, C.byref(size)):
            raise C.WinError(C.get_last_error())
        expected = Path(sys.executable).resolve().parent.parent / image
        if Path(buf.value).resolve() != expected.resolve():
            raise PermissionError("Unexpected Ransom0 pipe server")
        # Any logged-on user can start a copy of the packaged Python or UI.
        # The installation launches its legitimate pipe owners elevated.
        token = W.HANDLE()
        if not security.OpenProcessToken(process, 8, C.byref(token)):
            raise C.WinError(C.get_last_error())
        try:
            elevated, used = W.DWORD(), W.DWORD()
            if not security.GetTokenInformation(token, 20, C.byref(elevated),
                                               C.sizeof(elevated), C.byref(used)):
                raise C.WinError(C.get_last_error())
            if not elevated.value:
                raise PermissionError("Unelevated service pipe server")
        finally:
            kernel.CloseHandle(token)
    finally:
        kernel.CloseHandle(process)


def console_client(address, *, family):
    import _winapi
    from multiprocessing.connection import PipeConnection
    if family != "AF_PIPE" or not address.startswith(r"\\.\pipe\RansomGuard-output-"):
        raise ValueError("Expected a local console pipe")
    handle = _winapi.CreateFile(address, 0xC0000000, 0, None, 3, CLIENT_FLAGS, 0)
    try:
        verify_peer(handle, "python/python.exe")
        _winapi.SetNamedPipeHandleState(handle, _winapi.PIPE_READMODE_MESSAGE, None, None)
        return PipeConnection(handle)
    except BaseException:
        _winapi.CloseHandle(handle)
        raise
