"""Read-only comparison of observed files with explicitly approved hashes.

Open Windows handles deny write/delete sharing while hashing. Final handle
paths must match the approved local path. No file content is sent to JEV, and
changed bytes alone do not prove which process caused the change.
"""
import ctypes as C
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import time

from .recovery import ManifestEntry
from .observer_filter import _query_dos_device


def locked_hash(path, *, max_bytes=4*1024*1024):
    import msvcrt
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateFileW.argtypes=[C.c_wchar_p,C.c_ulong,C.c_ulong,C.c_void_p,C.c_ulong,C.c_ulong,C.c_void_p]
    k.CreateFileW.restype=C.c_void_p
    k.CloseHandle.argtypes=[C.c_void_p]
    k.GetFinalPathNameByHandleW.argtypes=[C.c_void_p,C.c_wchar_p,C.c_ulong,C.c_ulong]
    handle=k.CreateFileW(str(path),0x80000000,1,None,3,0x08200000,None)
    if handle==C.c_void_p(-1).value:raise C.WinError(C.get_last_error())
    try:
        buf=C.create_unicode_buffer(32768)
        length=k.GetFinalPathNameByHandleW(handle,buf,len(buf),0)
        if not 0<length<len(buf):raise OSError('Cannot resolve file handle')
        final=buf.value
        if final.startswith('\\\\?\\'):final=final[4:]
        if ntpath.normcase(final)!=ntpath.normcase(str(path)):
            raise ValueError('Resolved file escaped approved path')
        fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY);handle=None
        with os.fdopen(fd,'rb') as stream:
            if os.fstat(stream.fileno()).st_size>max_bytes:raise ValueError('Evidence file exceeds byte limit')
            data=stream.read(max_bytes+1)
            if len(data)>max_bytes:raise ValueError('Evidence read exceeds byte limit')
            return hashlib.sha256(data).hexdigest(),len(data)
    finally:
        if handle is not None:k.CloseHandle(handle)


def measure_changes(template_path, evidence, *, approved_prefix):
    template=json.loads(Path(template_path).read_text(encoding='utf-8-sig'))
    root=template.get('protected_root','')
    if not re.fullmatch(r'[A-Za-z]:\\[^*?]+',root) or '..' in root.split('\\'):
        raise ValueError('Approved local protected root is required')
    device=_query_dos_device(root[:2])
    if not device or (device+root[2:]).rstrip('\\').casefold()!=approved_prefix.rstrip('\\').casefold():
        raise ValueError('Evidence manifest and live-response scope differ')
    observed={p.casefold() for p in evidence.get('evidence',{}).get('sample_source_paths',[]) if isinstance(p,str)}
    items=template.get('manifest')
    if not isinstance(items,list) or not 1<=len(items)<=5000:raise ValueError('Invalid evidence manifest')
    result={'files_changed_sha256':0,'files_checked':0,'files_unverified':0,
            'changed_relative_paths':[],'checked_before_jev':True,
            'comparison':'approved_baseline_hash_vs_locked_current_file',
            'process_causation_proven':False,'complete_affected_file_list':False}
    started=time.monotonic();total=0
    for item in items:
        entry=ManifestEntry(**item) if isinstance(item,dict) else ManifestEntry(item)
        path=ntpath.join(root,entry.relative_path)
        if (device+path[2:]).casefold() not in observed or not entry.expected_sha256:continue
        if result['files_checked']+result['files_unverified']>=32 or total>=16*1024*1024 or time.monotonic()-started>2:
            result['bounded_scan_incomplete']=True;break
        try:digest,size=locked_hash(path)
        except (OSError,ValueError):result['files_unverified']+=1;continue
        total+=size;result['files_checked']+=1
        if digest!=entry.expected_sha256:
            result['files_changed_sha256']+=1
            result['changed_relative_paths'].append(entry.relative_path)
    return result
