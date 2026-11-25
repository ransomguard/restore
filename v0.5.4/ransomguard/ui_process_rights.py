"""Allow the dedicated collector to verify only this dashboard's identity and lifetime."""
import ctypes as C
from ctypes import wintypes as W
import os

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
        check(a.GetSecurityInfo(handle,6,4,None,None,C.byref(old),None,C.byref(sd)))
        if not old.value:raise ValueError("Unexpected process DACL")
        if not a.ConvertStringSidToSidW("S-1-5-80-3755250574-3201999084-3738073789-2921536738-940384076",C.byref(sid)):raise C.WinError(C.get_last_error())
        ace=Ace(0x101000,1,0,Trustee(None,0,0,1,sid))
        check(a.SetEntriesInAclW(1,C.byref(ace),old,C.byref(new)))
        check(a.SetSecurityInfo(handle,6,4,None,None,new,None))
    finally:
        for allocation in (sd,new,sid):
            if allocation.value:k.LocalFree(allocation)
        k.CloseHandle(handle)
