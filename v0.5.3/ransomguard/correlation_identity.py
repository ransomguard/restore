"""Recover correlation after gaps without reusing pre-gap evidence or PID-only identity."""
import ctypes as C
import os
import time
from collections import OrderedDict
from .protocol import ProcessRegistry, FILE_FLAG_HIGH_ENTROPY
from .process_identity import DWORD, BOOL, HANDLE, _Filetime, _filetime_number

class LiveIdentityHandle:
    def __init__(self,pid):
        k=self.k=C.WinDLL('kernel32',use_last_error=True)
        for name,args,result in (
            ('OpenProcess',[DWORD,BOOL,DWORD],HANDLE),
            ('GetProcessTimes',[HANDLE,C.POINTER(_Filetime),C.POINTER(_Filetime),C.POINTER(_Filetime),C.POINTER(_Filetime)],BOOL),
            ('WaitForSingleObject',[HANDLE,DWORD],DWORD),('CloseHandle',[HANDLE],BOOL)):
            fn=getattr(k,name);fn.argtypes=args;fn.restype=result
        self.handle=k.OpenProcess(0x1000|0x100000,False,pid)
        if not self.handle:raise C.WinError(C.get_last_error())
        try:
            times=[_Filetime() for _ in range(4)]
            if not k.GetProcessTimes(self.handle,*(C.byref(t) for t in times)):raise C.WinError(C.get_last_error())
            self.generation=_filetime_number(times[0])
            if not self.alive():raise OSError('process_exited')
        except BaseException:
            self.close();raise
    def alive(self):return bool(self.handle) and self.k.WaitForSingleObject(self.handle,0)==258
    def close(self):
        if self.handle:self.k.CloseHandle(self.handle);self.handle=None

class RecoverableProcessRegistry(ProcessRegistry):
    def __init__(self,opener=None,clock=time.monotonic,capacity=256):
        super().__init__();self.opener=opener or LiveIdentityHandle;self.clock=clock;self.capacity=capacity
        self.handles=OrderedDict();self.retry=OrderedDict();self.epoch=0;self.ever_loss_detected=False
        self.window=clock();self.lookups=0;self.stats={'queries':0,'resolved':0,'failed':0,'sequence_epochs':0}
        self.identity_source='unresolved';self.identity_resolution={'reason':'not_observed'}
    def invalidate(self):
        super().invalidate();self.epoch+=1;self.ever_loss_detected=True;self.stats['sequence_epochs']+=1
        self.close();self.retry.clear()
    def close(self):
        for handle in self.handles.values():handle.close()
        self.handles.clear()
    def update(self,event):
        gap=self._last_sequence is not None and event.sequence!=self._last_sequence+1
        if gap:self.invalidate()
        super().update(event)
        self.loss_detected=gap
        if event.event_type in (1,2,3):
            handle=self.handles.get(event.pid)
            generation=event.fields.get('process_create_time',0)
            if handle and (event.event_type==1 or generation==handle.generation or not handle.alive()):
                self.handles.pop(event.pid).close()
            self.retry.pop(event.pid,None)
    def generation_for(self,pid):
        generation=super().generation_for(pid)
        handle=self.handles.get(pid)
        return generation or (handle.generation if handle and handle.alive() else None)
    def generation_for_event(self,event):
        self.identity_source='unresolved';self.identity_resolution={'reason':'no_lifecycle_observed'}
        # Entries are always emptied on a gap. A newly observed lifecycle is usable;
        # historic loss remains in ever_loss_detected and durable driver counters.
        generation=self._entries.get(event.pid)
        if generation:
            if event.filetime>=generation:
                self.identity_source='observed_lifecycle_correlation';self.identity_resolution={'reason':'fresh_lifecycle'}
                return generation
            self.identity_resolution={'reason':'event_predates_process_creation'};return None
        if event.event_type not in (4,5):return None
        handle=self.handles.get(event.pid)
        if handle and not handle.alive():
            self.handles.pop(event.pid).close();handle=None
        if handle is None:
            # Query missing identities only for suspicious writes, not every file I/O.
            if not (event.event_type==4 and event.fields.get('flags',0)&FILE_FLAG_HIGH_ENTROPY):return None
            now=self.clock()
            if now-self.window>=1:self.window=now;self.lookups=0
            retry_at, previous_error = self.retry.get(event.pid, (0, {}))
            if now<retry_at:
                self.identity_resolution=dict(previous_error, retry_backoff=True)
                return None
            if self.lookups>=32:self.identity_resolution={'reason':'query_rate_limited'};return None
            self.lookups+=1;self.stats['queries']+=1
            try:
                if os.name!='nt' and self.opener is LiveIdentityHandle:raise OSError('Windows required')
                handle=self.opener(event.pid)
                self.handles[event.pid]=handle;self.stats['resolved']+=1
                while len(self.handles)>self.capacity:self.handles.popitem(last=False)[1].close()
            except OSError as error:
                self.stats['failed']+=1
                self.identity_resolution={'reason':'live_query_failed','winerror':getattr(error,'winerror',None),'detail':str(error)}
                self.retry[event.pid]=(now+2, dict(self.identity_resolution))
                while len(self.retry)>self.capacity:self.retry.popitem(last=False)
                return None
        self.handles.move_to_end(event.pid)
        if event.filetime<handle.generation:
            self.identity_resolution={'reason':'event_predates_process_creation'};return None
        self.identity_source='live_handle_query';self.identity_resolution={'reason':'live_handle_creation_time_verified'}
        return handle.generation
