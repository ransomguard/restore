"""Manual VSS requests and durable user pins, using the owned-only retention gate."""
from contextlib import closing
from datetime import datetime,timezone
import json
from pathlib import Path
import sqlite3

def user_pins(state):
    p=Path(state)
    if not p.exists():return set()
    from .recovery import _snapshot_id
    with closing(sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True,timeout=3)) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='snapshot_user_pins'").fetchone():return set()
        return {_snapshot_id(r[0]) for r in db.execute('SELECT snapshot_id FROM snapshot_user_pins')}

def owned_receipts(state):
    from .recovery import Snapshot
    with closing(sqlite3.connect(Path(state).absolute().as_uri()+'?mode=ro',uri=True,timeout=3)) as db:
        rows=db.execute("SELECT result_json FROM snapshot_attempts WHERE status='created'").fetchall()
    result={}
    for raw, in rows:
        v=json.loads(raw)
        if v.get('created') is not True or v.get('reason')!='vss_create_verified':raise ValueError('Invalid ownership receipt')
        snap=Snapshot(**v['snapshot'])
        if snap.snapshot_id in result:raise ValueError('Duplicate ownership receipt')
        result[snap.snapshot_id]=(snap,bool(v.get('manual_request_id')))
    return result

def list_owned(runtime):
    from .snapshots import default_state_db
    from .recovery import enumerate_snapshots
    from .snapshot_retention import load_config,protection_state,RetentionPolicy
    from .snapshot_guard import snapshot_guard
    state=default_state_db()
    if not state.exists():return {'snapshots':[],'errors':[]}
    with snapshot_guard():
        owned=owned_receipts(state);pins=user_pins(state);items=[];errors=[]
        cfg=load_config(state)
        for volume in sorted({s.volume_id for s,_ in owned.values()}):
            try:
                live=enumerate_snapshots(volume)
                protected,reasons=protection_state(cfg,live)
                with closing(sqlite3.connect(state.as_uri()+'?mode=ro',uri=True,timeout=3)) as db:
                    if db.execute("SELECT 1 FROM sqlite_master WHERE name='snapshot_recovery_pins'").fetchone():
                        protected.update(r[0] for r in db.execute("SELECT snapshot_id FROM snapshot_recovery_pins WHERE state!='released'"))
                ours=sorted((s for s in live if s.snapshot_id in owned),key=lambda s:s.created_at)
                newest={s.snapshot_id for s in ours[-RetentionPolicy(**cfg['policy']).min_keep:]}
                for s in ours:
                    receipt,manual=owned[s.snapshot_id]
                    if (receipt.volume_id,receipt.created_at)!=(s.volume_id,s.created_at):raise ValueError('Snapshot ownership mismatch')
                    items.append(s.to_dict()|{'manual':manual,'userProtected':s.snapshot_id in pins,
                        'systemProtected':s.snapshot_id in protected,'minimumKeep':s.snapshot_id in newest,
                        'protected':s.snapshot_id in pins|protected|newest})
            except Exception as e:errors.append({'volume':volume,'error':str(e)})
        return {'snapshots':sorted(items,key=lambda x:x['created_at'],reverse=True),'errors':errors}

def protect(runtime,snapshot_id,enabled):
    if type(enabled)!=bool:raise ValueError('Invalid protection value')
    from .snapshots import default_state_db,require_storage_operator
    from .recovery import _snapshot_id,enumerate_snapshots
    from .snapshot_guard import snapshot_guard
    require_storage_operator();ident=_snapshot_id(snapshot_id);state=default_state_db()
    with snapshot_guard():
        receipt=owned_receipts(state).get(ident)
        if not receipt:raise ValueError('Ransom0가 생성한 스냅샷만 보호할 수 있습니다.')
        snap,_=receipt
        live=next((s for s in enumerate_snapshots(snap.volume_id) if s.snapshot_id==ident),None)
        if live is None or live.created_at!=snap.created_at:raise ValueError('스냅샷이 없거나 생성 정보를 확인할 수 없습니다.')
        with closing(sqlite3.connect(state.as_uri()+'?mode=rw',uri=True,timeout=3)) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE IF NOT EXISTS snapshot_user_pins(snapshot_id TEXT PRIMARY KEY,volume_id TEXT NOT NULL,pinned_at TEXT NOT NULL)')
            if enabled:db.execute('INSERT OR REPLACE INTO snapshot_user_pins VALUES(?,?,?)',(ident,snap.volume_id,datetime.now(timezone.utc).isoformat()))
            else:db.execute('DELETE FROM snapshot_user_pins WHERE snapshot_id=?',(ident,))
            db.commit()
    return list_owned(runtime)

def manual(runtime,request_id):
    from .snapshots import default_state_db,require_storage_operator,HourlySnapshotCoordinator
    from .scope_settings import read,scope_lock
    from .protection_setup import validate_folder
    require_storage_operator()
    with scope_lock(runtime):
        cfg=read(runtime,'protection.json',{})
        if not cfg:raise ValueError('먼저 보호·복구 폴더를 설정해 주세요.')
        _,volume=validate_folder(cfg['protected_root'],forbidden=(str(runtime),))
        result=HourlySnapshotCoordinator(default_state_db()).run(volume,trigger='manual',request_id=request_id)
    # Manual creation does not replace an incident's approved recovery manifest.
    # Align the scheduled next attempt, without changing its configured interval.
    if result.get('created') and not result.get('duplicate_request'):
        from .snapshot_settings import change,interval_minutes
        try:result['schedule']=change(runtime,interval_minutes(default_state_db()))
        except Exception as e:result['schedule_warning']=str(e)
    return result
