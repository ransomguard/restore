"""Local settings for one approved recovery folder; no network policy changes."""
from contextlib import contextmanager, closing
import argparse
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid

from .protection_setup import save_json, configure_scope, refresh, validate_folder

class ScopeBusy(RuntimeError):pass


@contextmanager
def scope_lock(runtime, *, dispatch=False):
    """Also held by response enqueue and scheduled scope maintenance."""
    import msvcrt
    path=Path(runtime)/('scope-dispatch.lock' if dispatch else 'scope-change.lock')
    with path.open('a+b') as f:
        f.seek(0,2)
        if f.tell()==0:f.write(b'0');f.flush()
        f.seek(0)
        try:msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
        except OSError:raise ScopeBusy('복구 범위를 적용 중이거나 다른 설정 작업이 실행 중입니다.')
        try:yield
        finally:f.seek(0);msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)


def read(base,name,default=None):
    f=Path(base)/name
    return json.loads(f.read_text(encoding='utf-8-sig')) if f.exists() else default


def assert_idle(base, *, allow_review=False):
    for journal in (Path(base)/'manual-restores').glob('*.json'):
        record=read(journal.parent,journal.name)
        if not isinstance(record,dict) or record.get('state') not in ('prepared','verified'):
            raise RuntimeError('결과를 확인하지 못한 수동 복구가 있습니다. 복구 기록을 확인해 주세요.')
    for filename,queries in (
        ('holds.sqlite3',["SELECT 1 FROM firewall_holds LIMIT 1"]),
        ('observe.sqlite3',["SELECT 1 FROM response_jobs WHERE state IN ('READY','RUNNING','REVIEW_REQUIRED') LIMIT 1",
                           "SELECT 1 FROM live_response_attempts WHERE state NOT IN ('RELEASED','EXEMPTED') LIMIT 1"])):
        f=Path(base)/filename
        if not f.exists():continue
        with closing(sqlite3.connect(f.absolute().as_uri()+'?mode=ro',uri=True,timeout=3)) as db:
            tables={x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for query in queries:
                if allow_review:
                    if 'firewall_holds' in query:query="SELECT 1 FROM firewall_holds WHERE state IS NULL OR state!='review_required' LIMIT 1"
                    elif 'response_jobs' in query:query="SELECT 1 FROM response_jobs WHERE state IS NULL OR state NOT IN ('RELEASED','REVIEW_REQUIRED','EXEMPTED') LIMIT 1"
                    else:query="SELECT 1 FROM live_response_attempts WHERE state IS NULL OR state NOT IN ('RELEASED','REVIEW_REQUIRED','EXEMPTED') LIMIT 1"
                table=query.split('FROM ')[1].split()[0]
                if table in tables and db.execute(query).fetchone():
                    raise RuntimeError('진행 중이거나 상태가 불확실한 대응·복구 작업이 있어 변경할 수 없습니다. 기존 범위를 유지합니다.')


def status(runtime):
    from .health_report import report
    base=Path(runtime);settings=read(base,'protection.json',{})
    state=report(base)['recovery']
    blocked=None
    try:assert_idle(base,allow_review=True)
    except (RuntimeError,sqlite3.Error) as e:blocked=str(e)
    return dict(protectedRoot=settings.get('protected_root',''),ready=state.get('ready',False),
                reason=state.get('reason','scope_not_configured'),detail=state.get('detail',''),
                snapshotBudgetGiB=settings.get('snapshot_budget_gib',8),files=state.get('files',0),
                blockedReason=blocked,automaticResponse=(base/'live-response-profile.json').exists())


def apply_observer_scope(args):
    base=Path(args.db).parent
    fields=('live_track_a','live_track_b','authorize_live','confirm_isolated_vm','confirm_internal_test','async_response',
            'response_no_recovery_required','config','response_state_db','response_path_prefix','response_manifest_template')
    if not hasattr(args,'_scope_original_args'):
        args._scope_original_args={k:getattr(args,k,None) for k in fields}
    if not (base/'scope-settings-enabled.json').exists():
        for k,v in args._scope_original_args.items():setattr(args,k,v)
        return
    from .live_profile import observer_options
    options,_=observer_options(base/'live-response-profile.json',state_db=base/'holds.sqlite3')
    for field in ('live_track_a','live_track_b','authorize_live','confirm_isolated_vm','confirm_internal_test','async_response'):
        setattr(args,field,False)
    args.response_no_recovery_required=False
    if (base/'response-config.json').exists():args.config=str(base/'response-config.json')
    i=0
    while i<len(options):
        field=options[i][2:].replace('-','_');i+=1
        value=True
        if i<len(options) and not options[i].startswith('--'):value=options[i];i+=1
        setattr(args,field,value)


def change(runtime, request):
    base=Path(runtime)
    if request.get('acknowledgeFolderRevert') is not True:
        raise ValueError('선택 폴더를 스냅샷 시점으로 복구하는 데 동의해 주세요.')
    installation=read(base,'installation.json',{})
    folder,volume=validate_folder(request.get('folder',''),forbidden=(str(base),installation.get('recovery_root',str(base))))
    budget=request.get('snapshotBudgetGiB',8)
    if type(budget)!=int or not 4<=budget<=32:raise ValueError('스냅샷 목표는 4~32 GiB입니다.')
    with scope_lock(base), scope_lock(base,dispatch=True):
        assert_idle(base,allow_review=True)
        # Preserve immutable old manifests so ownership retention never loses pins.
        names=('protection.json','protection-status.json','protected-manifest.json','response-config.json','live-response-profile.json','scope-settings-enabled.json')
        originals={n:(base/n).read_bytes() if (base/n).exists() else None for n in names}
        archive=base/'scope-history'/uuid.uuid4().hex;archive.mkdir(parents=True)
        for n,data in originals.items():
            if data is not None:(archive/n).write_bytes(data)
        oldmanifest=archive/'protected-manifest.json'
        if oldmanifest.exists():
            from .snapshot_guard import snapshot_guard
            from .snapshots import default_state_db
            from .snapshot_retention import policy_path
            with snapshot_guard():
                policy=policy_path(default_state_db());v=read(policy.parent,policy.name)
                if not v:raise RuntimeError('기존 스냅샷 보존 정책을 확인할 수 없습니다.')
                paths=v.setdefault('manifest_paths',[])
                if str(oldmanifest) not in paths:paths.append(str(oldmanifest))
                save_json(policy,v)
        try:
            configure_scope(base,folder,acknowledge_folder_revert=True,snapshot_budget_gib=budget)
            prepared=refresh(base,create_snapshot=True,initial=True,_scope_locked=True)
            if not prepared['ready']:raise RuntimeError('새 복구 기준 준비 실패: '+prepared.get('detail',prepared['reason']))
            config=read(base,'response-config.json')
            if not config:raise RuntimeError('설치된 대응 설정을 찾지 못했습니다.')
            config.setdefault('recovery',{}).update(protected_root=folder,volume_root=volume)
            save_json(base/'response-config.json',config)
            profile=read(base,'live-response-profile.json') or read(base,'scope-authorization.json')
            if not profile:raise RuntimeError('설치 시 자동 대응 승인 정보를 찾지 못했습니다.')
            from .observer_filter import _query_dos_device
            profile.update(nt_path_prefix=_query_dos_device(folder[:2])+folder[2:],config=str(base/'response-config.json'),manifest=str(base/'protected-manifest.json'))
            # Key absence must never claim automatic JEV response is ready.
            transport=read(base,'jev-transport.json')
            import subprocess
            key_ready=bool(transport and subprocess.run([transport['bridge'],'--check-key'],capture_output=True,timeout=20).returncode==0)
            if key_ready:save_json(base/'live-response-profile.json',profile)
            else:(base/'live-response-profile.json').unlink(missing_ok=True)
            from .live_profile import observer_options
            observer_options(base/'live-response-profile.json',state_db=base/'holds.sqlite3')
            save_json(base/'scope-settings-enabled.json',{'schema_version':1})
            from .resident import request_reload
            ready=base/'observer-ready.json'
            req=request_reload(ready,Path(installation['recovery_root'])/'ransomguard')
            until=time.monotonic()+40
            while time.monotonic()<until:
                h=read(base,ready.name,{})
                if h.get('reload_request_id')==req['id'] and h.get('worker_state')=='running':break
                time.sleep(.2)
            else:raise RuntimeError('수집기의 새 범위 적용을 확인하지 못했습니다.')
        except BaseException:
            for n,data in originals.items():
                if data is None:(base/n).unlink(missing_ok=True)
                else:
                    temp=base/(n+'.rollback');temp.write_bytes(data);os.replace(temp,base/n)
            # Restore the previous observer arguments if handover already started.
            try:
                from .resident import request_reload
                request_reload(base/'observer-ready.json',Path(installation['recovery_root'])/'ransomguard')
            except Exception:pass
            raise
    return status(base)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',required=True);parser.add_argument('action',choices=('status','change'));args=parser.parse_args()
    import sys
    try:
        result=status(args.runtime) if args.action=='status' else change(args.runtime,json.load(sys.stdin))
        print(json.dumps(result,ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'error':str(error)},ensure_ascii=False));sys.exit(1)

if __name__=='__main__':main()
