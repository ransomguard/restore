"""Exact, generation-bound internal storage admission; not a process allowlist."""
import json,os,time,ctypes as C
from pathlib import Path
from .observer_filter import ObserverOutboxFilter

class LiveOwner:
 def __init__(self,pid,expected):
  from ctypes import wintypes as W
  self.k=C.WinDLL('kernel32',use_last_error=True);self.handle=None
  self.k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];self.k.OpenProcess.restype=W.HANDLE
  self.k.CloseHandle.argtypes=[W.HANDLE];self.k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD]
  self.k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)]
  self.k.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4
  h=self.k.OpenProcess(0x101000,False,pid)
  if not h:raise OSError('Cannot verify internal writer')
  self.handle=h
  try:
   text=C.create_unicode_buffer(32768);n=W.DWORD(32768)
   if not self.k.QueryFullProcessImageNameW(h,0,text,C.byref(n)) or os.path.normcase(text.value)!=os.path.normcase(str(expected)):raise OSError('Writer executable mismatch')
   values=[W.FILETIME() for _ in range(4)]
   if not self.k.GetProcessTimes(h,*[C.byref(v) for v in values]):raise OSError('Writer generation unavailable')
   self.created=(values[0].dwHighDateTime<<32)|values[0].dwLowDateTime
  except BaseException:self.close();raise
 def alive(self):return self.handle and self.k.WaitForSingleObject(self.handle,0)==258
 def close(self):
  if self.handle:self.k.CloseHandle(self.handle);self.handle=None

class InternalCollection:
 def __init__(self,runtime):
  self.base=Path(runtime);self.next=0;self.signature=None;self.collect=False;self.owner=None;self.ui_filter=None
  self.excluded=0;self.observed=0;self.request_id=None;self.error=None
  self.state_filters=[ObserverOutboxFilter(self.base/name) for name in ('observer-ready.json','observer-ready.json.tmp','observer-ready.counters.json','observer-ready.counters.json.tmp')]
 def tick(self):
  if time.monotonic()<self.next:return
  self.next=time.monotonic()+1
  try:
   f=self.base/'console-display.json';v=json.loads(f.read_text(encoding='utf-8-sig')) if f.exists() else {}
   collect=v.get('collectOwnDbEvents',False)
   if type(collect) is not bool:raise ValueError('Invalid collection setting')
   pid=int((self.base/'ui.pid').read_text().strip())
   signature=(collect,pid,v.get('requestId'))
   if signature!=self.signature or not self.owner or not self.owner.alive():
    if self.owner:self.owner.close()
    self.owner=None;self.ui_filter=None
    config=json.loads((self.base/'installation.json').read_text(encoding='utf-8-sig'))
    self.owner=LiveOwner(pid,config['ui'])
    # The launcher provides the trusted user's database path, not an arbitrary UI request path.
    db=os.environ.get('RANSOM0_UI_DATABASE')
    if db:self.ui_filter=ObserverOutboxFilter(db,observer_pid=pid)
    self.signature=signature
   self.collect=collect;self.request_id=v.get('requestId');self.error=None
  except (OSError,ValueError,KeyError,TypeError) as exc:
   self.collect=True;self.error=type(exc).__name__ # Fail open: retain evidence when identity/config cannot be verified.
  result={'requestId':self.request_id,'pid':os.getpid(),'collectOwnDbEvents':self.collect,'excluded':self.excluded,'observed':self.observed,'error':self.error}
  # Only write acknowledgement on policy change; counters are also exposed through observer health.
  encoded=json.dumps(result)
  policy=(self.request_id,self.collect,self.error)
  if getattr(self,'last_ack',None)!=policy:
   target=self.base/'internal-collection.status.json';temp=target.with_suffix('.tmp')
   temp.write_text(encoded,encoding='utf8');temp.replace(target);self.last_ack=policy
 def matches(self,event):
  if any(f.matches(event) for f in self.state_filters):return True
  # Reject unrelated PID/path before the Win32 handle wait. Calling alive()
  # for every system write needlessly crosses the OS/GIL boundary at burst rate.
  return bool(self.ui_filter and self.ui_filter.matches(event) and self.owner
              and event.filetime>=self.owner.created and self.owner.alive())
 def exclude(self,event):
  matched=self.matches(event)
  if matched:self.observed+=1
  if matched and not self.collect:self.excluded+=1;return True
  return False
 def close(self):
  if self.owner:self.owner.close()
