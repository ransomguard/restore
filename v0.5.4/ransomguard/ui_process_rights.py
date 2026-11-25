"""Allow the dedicated collector to verify only this dashboard's identity and lifetime."""
import ctypes as C
from ctypes import wintypes as W
import os
import time

def allow_storage_query(pid, expected):
    k=C.WinDLL("kernel32",use_last_error=True)
    a=C.WinDLL("advapi32",use_last_error=True)
    P=C.c_void_p
    PP=C.POINTER(P)
    class Trustee(C.Structure):
        _fields_=[("multiple",P),("operation",W.DWORD),("form",W.DWORD),("kind",W.DWORD),("name",P)]
    class Ace(C.Structure):
        _fields_=[("permissions",W.DWORD),("mode",W.DWORD),("inheritance",W.DWORD),("trustee",Trustee)]
    k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=P
    k.CloseHandle.argtypes=[P];k.LocalFree.argtypes=[P]
    k.QueryFullProcessImageNameW.argtypes=[P,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)]
    a.GetSecurityInfo.argtypes=[P,W.DWORD,W.DWORD,PP,PP,PP,PP,PP]
    a.SetSecurityInfo.argtypes=[P,W.DWORD,W.DWORD,P,P,P,P]
    a.SetEntriesInAclW.argtypes=[W.DWORD,C.POINTER(Ace),P,PP]
    a.ConvertStringSidToSidW.argtypes=[W.LPCWSTR,PP]
    def check(err):
        if err:raise C.WinError(err)
    handle=k.OpenProcess(0x61000,False,pid)
    if not handle:raise C.WinError(C.get_last_error())
    sd,old,new,sid=P(),P(),P(),P()
    try:
        name=C.create_unicode_buffer(32768);size=W.DWORD(len(name))
        if not k.QueryFullProcessImageNameW(handle,0,name,C.byref(size)):raise C.WinError(C.get_last_error())
        if os.path.normcase(name.value)!=os.path.normcase(str(expected)):raise ValueError("Dashboard image changed")
        if not a.ConvertStringSidToSidW("S-1-5-80-3755250574-3201999084-3738073789-2921536738-940384076",C.byref(sid)):
            raise C.WinError(C.get_last_error())
        def grant(obj, kind, mask):
            desc,acl,updated=P(),P(),P()
            try:
                check(a.GetSecurityInfo(obj,kind,4,None,None,C.byref(acl),None,C.byref(desc)))
                if not acl.value:raise ValueError("Expected a protected object DACL")
                entry=Ace(mask,1,0,Trustee(None,0,0,1,sid))
                check(a.SetEntriesInAclW(1,C.byref(entry),acl,C.byref(updated)))
                check(a.SetSecurityInfo(obj,kind,4,None,None,updated,None))
            finally:
                for alloc in (desc,updated):
                    if alloc.value:k.LocalFree(alloc)
        grant(handle,6,0x101000)
        token=P()
        a.OpenProcessToken.argtypes=[P,W.DWORD,PP]
        if not a.OpenProcessToken(handle,0x60008,C.byref(token)):raise C.WinError(C.get_last_error())
        try:
            level=W.DWORD();size=W.DWORD()
            a.GetTokenInformation.argtypes=[P,W.DWORD,P,W.DWORD,C.POINTER(W.DWORD)]
            if not a.GetTokenInformation(token,20,C.byref(level),4,C.byref(size)):raise C.WinError(C.get_last_error())
            if not level.value:raise ValueError("Expected elevated dashboard")
            grant(token,6,8)  # TOKEN_QUERY alone
        finally:k.CloseHandle(token)
        pipe_name=r"\\.\pipe\Ransom0_UI"
        k.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,P,W.DWORD,W.DWORD,P];k.CreateFileW.restype=P
        k.GetNamedPipeServerProcessId.argtypes=[P,C.POINTER(W.ULONG)]
        until=time.monotonic()+12
        while True:
            pipe=k.CreateFileW(pipe_name,0x60003,0,None,3,0x100000,None)
            if pipe!=P(-1).value:break
            err=C.get_last_error()
            if err not in (2,231) or time.monotonic()>=until:raise C.WinError(err)
            time.sleep(.15)
        try:
            server=W.ULONG()
            if not k.GetNamedPipeServerProcessId(pipe,C.byref(server)):raise C.WinError(C.get_last_error())
            if server.value!=pid:raise PermissionError("Dashboard pipe PID mismatch")
            grant(pipe,6,3)  # Only FILE_READ_DATA and FILE_WRITE_DATA
        finally:k.CloseHandle(pipe)
    finally:
        for allocation in (sd,new,sid):
            if allocation.value:k.LocalFree(allocation)
        k.CloseHandle(handle)
