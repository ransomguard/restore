"""Explicit user rollback of the selected folder, independent of malware verdicts."""
import hashlib,json,time,uuid
from datetime import datetime,timezone
from pathlib import Path
from .scope_settings import read,scope_lock,assert_idle
from .protection_setup import save_json,validate_folder

def scope_digest(base):return hashlib.sha256((Path(base)/'protection.json').read_bytes()).hexdigest()

def preview(runtime,ident):
    from .snapshots import default_state_db,require_admin
    from .snapshot_management import owned_receipts
    from .recovery import enumerate_snapshots,_snapshot_id,volume_id_for_root
    from .recovery_catalog import catalog_snapshot
    from .snapshot_guard import snapshot_guard
    require_admin();base=Path(runtime);ident=_snapshot_id(ident)
    with scope_lock(base),snapshot_guard():
        cfg=read(base,'protection.json',{})
        if not cfg:raise ValueError('먼저 복구 폴더를 설정해 주세요.')
        folder,volume=validate_folder(cfg['protected_root'],forbidden=(str(base),))
        receipt=owned_receipts(default_state_db()).get(ident)
        if not receipt:raise ValueError('Ransom0 소유 스냅샷이 아닙니다.')
        saved,_=receipt
        if volume_id_for_root(volume)!=saved.volume_id:raise ValueError('현재 복구 폴더와 스냅샷의 볼륨이 다릅니다.')
        snapshot=next((s for s in enumerate_snapshots(saved.volume_id) if s.snapshot_id==ident),None)
        if snapshot is None or snapshot.created_at!=saved.created_at:raise ValueError('선택한 스냅샷을 확인할 수 없습니다.')
        catalog=catalog_snapshot(snapshot,volume_root=volume,protected_root=folder,
            reference_at=datetime.now(timezone.utc),manual_selection=True,max_seconds=60)
        token=str(uuid.uuid4())
        record={'token':token,'state':'prepared','expires':time.time()+600,'scope_digest':scope_digest(base),
                'snapshot':snapshot.to_dict(),'catalog':catalog,'source':'user_manual_restore'}
        save_json(base/'manual-restores'/(token+'.json'),record)
        return {'token':token,'snapshotId':ident,'createdAt':snapshot.created_at.isoformat(),
                'folder':folder,'files':[i['relative_path'] for i in catalog['manifest']],
                'bytes':catalog['catalog_bytes'],'expires':record['expires']}

def execute(runtime,token,confirmed):
    if confirmed is not True:raise ValueError('파일 덮어쓰기와 관련 프로그램 종료를 확인해 주세요.')
    if str(uuid.UUID(token))!=token:raise ValueError('Invalid restore token')
    from .snapshots import require_admin
    from .recovery import Snapshot,build_plan,RecoveryEngine
    require_admin();base=Path(runtime);path=base/'manual-restores'/(token+'.json')
    with scope_lock(base),scope_lock(base,dispatch=True):
        assert_idle(base,allow_review=True)
        r=read(path.parent,path.name)
        if not r:raise ValueError('복구 미리보기를 다시 생성해 주세요.')
        if r['state']!='prepared':raise ValueError('이미 실행했거나 결과 확인 중인 요청입니다. 기록을 확인해 주세요.')
        if time.time()>r['expires'] or r['scope_digest']!=scope_digest(base):raise ValueError('복구 범위가 변경됐거나 미리보기가 만료됐습니다. 다시 확인해 주세요.')
        cfg=r['catalog'];snapshot=Snapshot(**r['snapshot'])
        plan=build_plan(snapshot,volume_root=cfg['volume_root'],protected_root=cfg['protected_root'],
            manifest=cfg['manifest'],incident_at=datetime.now(timezone.utc))
        r.update(state='running',started=time.time(),job_id=plan.job_id);save_json(path,r)
        try:
            result=RecoveryEngine().execute(plan,allow_live=True,manual_restore_confirmed=True)
            r.update(state='verified' if result['verified'] else 'review_required',result=result,finished=time.time())
            save_json(path,r)
        except BaseException as e:
            r.update(state='review_required',error=str(e));save_json(path,r);raise
        return {'verified':result['verified'],'filesVerified':result['files_verified'],
                'filesFailed':result['files_failed'],'jobId':result['job_id'],
                'snapshotId':snapshot.snapshot_id,'source':'user_manual_restore',
                'malwareContainmentClaimed':False}
