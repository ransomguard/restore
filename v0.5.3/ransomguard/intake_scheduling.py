"""Prioritize only the kernel intake thread over ordinary analysis/file writers.

ABOVE_NORMAL is bounded and is not real-time scheduling. No process-wide or
persistent priority, event admission, driver policy or queue size is changed.
"""
from contextlib import contextmanager
import ctypes as C
import os

def _boost(thread_id):
    k=C.WinDLL('kernel32',use_last_error=True)
    k.OpenThread.argtypes=[C.c_uint32,C.c_int,C.c_uint32];k.OpenThread.restype=C.c_void_p
    k.GetThreadPriority.argtypes=[C.c_void_p];k.GetThreadPriority.restype=C.c_int
    k.SetThreadPriority.argtypes=[C.c_void_p,C.c_int];k.SetThreadPriority.restype=C.c_int
    k.CloseHandle.argtypes=[C.c_void_p]
    h=k.OpenThread(0x60,False,thread_id)
    if not h:raise C.WinError(C.get_last_error())
    try:
        prior=k.GetThreadPriority(h)
        if prior==0x7fffffff:raise C.WinError(C.get_last_error())
        changed=prior<1
        if changed and not k.SetThreadPriority(h,1):raise C.WinError(C.get_last_error())
    except BaseException:k.CloseHandle(h);raise
    def restore():
        try:
            if changed:k.SetThreadPriority(h,prior)
        finally:k.CloseHandle(h)
    return restore

@contextmanager
def intake_priority(reader):
    restore=None
    native_id=getattr(getattr(reader,'thread',None),'native_id',None)
    if os.name=='nt' and native_id:
        try:
            restore=_boost(native_id);reader.intake_priority='above_normal'
        except OSError as error:
            reader.intake_priority='unchanged:'+str(getattr(error,'winerror','unavailable'))
    try:yield
    finally:
        if restore:restore()
