"""Constant-size status reads. No live DB integrity scan or forced checkpoint.

An integrity audit is a maintenance operation, not a health poll. Reader
transactions and WAL checkpoints compete with event intake. Never run them
implicitly during shutdown, startup, or dashboard refresh.
"""
import json
from pathlib import Path
import time

def report(runtime, *, now=None):
    now=time.time() if now is None else now
    base=Path(runtime)
    def read(name):
        try:
            path=base/name
            if path.stat().st_size>1024*1024:raise ValueError('Status file too large')
            return json.loads(path.read_text(encoding='utf-8-sig'))
        except (OSError,ValueError):return {}
    ready=read('observer-ready.json');protection=read('protection-status.json')
    protection_age=max(0,now-protection.get('at',0))
    protection['status_age_seconds']=protection_age
    if protection.get('ready') and protection_age>7200:
        protection.update(ready=False,reason='baseline_status_stale',
            detail='복구 목록 상태를 2시간 넘게 갱신하지 못했습니다. 스냅샷 작업 상태를 확인하세요.')
    observed=ready.get('observed_at')
    age=now-observed if type(observed) in (int,float) else None
    counters=ready.get('counter_totals',{})
    return {'at':now,'collector_ready':ready.get('worker_state')=='running' and
            ready.get('driver_registered') is True and age is not None and 0<=age<15,
            'worker_state':ready.get('worker_state'),'worker_error':ready.get('worker_error'),
            'worker_failed_at':ready.get('worker_failed_at'),
            'last_processed_sequence':ready.get('last_processed_sequence'),
            'heartbeat_age_seconds':age,'collector_pid':ready.get('pid'),
            'counters':counters,'queue':ready.get('driver_status',{}).get('intake_queue_depth'),
            'pending_intake':ready.get('pending_intake'),'recovery':protection,
            'runtime':read('runtime.json'),'supervisor':read('supervisor-status.json'),
            'database_integrity_checked':False,'wal_checkpoint_requested':False}
