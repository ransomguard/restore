"""Validate the SCM service identity; no privileged fallback identity is accepted."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import struct


SERVICE = "Ransom0Storage"
SERVICE_SID = "S-1-5-80-" + "-".join(str(v) for v in struct.unpack(
    "<5I", hashlib.sha1(SERVICE.upper().encode("utf-16-le")).digest()))


def scm_pid():
    """Query SCM with read-only access. A stale heartbeat cannot authorize device attach."""
    api = C.WinDLL("advapi32", use_last_error=True)
    api.OpenSCManagerW.argtypes = [W.LPCWSTR, W.LPCWSTR, W.DWORD]
    api.OpenSCManagerW.restype = W.HANDLE
    api.OpenServiceW.argtypes = [W.HANDLE, W.LPCWSTR, W.DWORD]
    api.OpenServiceW.restype = W.HANDLE
    api.QueryServiceStatusEx.argtypes = [W.HANDLE, C.c_int, W.LPVOID, W.DWORD, C.POINTER(W.DWORD)]
    api.CloseServiceHandle.argtypes = [W.HANDLE]
    manager = api.OpenSCManagerW(None, None, 1)
    if not manager:
        raise C.WinError(C.get_last_error())
    try:
        service = api.OpenServiceW(manager, SERVICE, 4)
        if not service:
            raise C.WinError(C.get_last_error())
        try:
            status, length = (W.DWORD * 9)(), W.DWORD()
            if not api.QueryServiceStatusEx(service, 0, status, C.sizeof(status), C.byref(length)):
                raise C.WinError(C.get_last_error())
            return status[7] if status[1] == 4 else None
        finally:
            api.CloseServiceHandle(service)
    finally:
        api.CloseServiceHandle(manager)


def current_user_sid():
    kernel = C.WinDLL("kernel32", use_last_error=True)
    security = C.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.LocalFree.argtypes = [W.HLOCAL]
    security.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    security.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, W.LPVOID, W.DWORD, C.POINTER(W.DWORD)]
    security.ConvertSidToStringSidW.argtypes = [W.LPVOID, C.POINTER(W.LPWSTR)]
    token, length, text = W.HANDLE(), W.DWORD(), W.LPWSTR()
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, C.byref(token)):
        raise C.WinError(C.get_last_error())
    try:
        security.GetTokenInformation(token, 1, None, 0, C.byref(length))
        if not 0 < length.value <= 65536:
            raise C.WinError(C.get_last_error())
        buf = C.create_string_buffer(length.value)
        if not security.GetTokenInformation(token, 1, buf, length, C.byref(length)):
            raise C.WinError(C.get_last_error())
        sid = C.cast(buf, C.POINTER(W.LPVOID))[0]
        if not security.ConvertSidToStringSidW(sid, C.byref(text)):
            raise C.WinError(C.get_last_error())
        return text.value
    finally:
        if text:
            kernel.LocalFree(C.cast(text, W.HLOCAL))
        kernel.CloseHandle(token)


def require_service_account():
    if current_user_sid() != SERVICE_SID:
        raise PermissionError("Ransom0Storage requires its dedicated virtual service account")
