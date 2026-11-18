"""Selected-folder provisioning. No incident-triggered VSS or invented baseline.

The operator approves reverting baseline files in ONE folder, not an inferred
affected-file list. VSS catalogs remain bounded; an incomplete catalog never
enables automatic restore. Existing incident holds and snapshot pins persist.
"""
from contextlib import closing
from datetime import datetime, timezone
import json
import ntpath
import os
from pathlib import Path
import sqlite3
import time

from .recovery import _check_chain, enumerate_snapshots, select_snapshot, volume_id_for_root
from .recovery_catalog import create_manifest
from .snapshot_guard import snapshot_guard
from .snapshots import HourlySnapshotCoordinator, default_state_db


def save_json(path, value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.new')
    with tmp.open('w',encoding='utf-8') as f:
        json.dump(value,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)


def validate_folder(value, *, forbidden=()):
    folder=Path(value).absolute()
    if os.name!='nt' or not folder.is_dir() or str(folder).startswith('\\\\'):
        raise ValueError('Choose an existing local Windows folder')
    drive,tail=ntpath.splitdrive(str(folder))
    if len(drive)!=2 or not tail.strip('\\/'):
        raise ValueError('A whole volume cannot be selected')
    # Reject junctions/symlinks at every level, not just the last directory.
    _check_chain(Path(drive+'\\'),tuple(str(folder)[3:].replace('/','\\').split('\\')),final_directory=True)
    roots=[os.environ.get('SystemRoot',r'C:\Windows'),os.environ.get('ProgramFiles',r'C:\Program Files'),
           os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)'),
           str(Path(os.environ.get('ProgramData',r'C:\ProgramData'))/'RansomGuard')]+list(forbidden)
    for root in roots:
        a=ntpath.normcase(ntpath.normpath(str(folder)));b=ntpath.normcase(ntpath.normpath(str(root)))
        if a==b or a.startswith(b+'\\') or b.startswith(a+'\\'):
            raise ValueError('System, application, or evidence folders cannot be protected scopes')
    volume=drive.upper()+'\\'
    return str(folder),volume


def configure_scope(runtime, folder, *, acknowledge_folder_revert, snapshot_budget_gib=8):
    if acknowledge_folder_revert is not True:
        raise ValueError('Folder-wide snapshot restore must be acknowledged')
    base=Path(runtime)
    folder,volume=validate_folder(folder,forbidden=(str(base),))
    if type(snapshot_budget_gib)!=int or not 4<=snapshot_budget_gib<=32:
        raise ValueError('Snapshot target must be between 4 and 32 GiB')
    save_json(base/'protection.json',dict(schema_version=1,protected_root=folder,volume_root=volume,
        acknowledged_folder_revert=True,snapshot_budget_gib=snapshot_budget_gib,
        max_files=5000,max_total_bytes=2*1024**3,max_file_bytes=512*1024**2,
        restore_scope='baseline_regular_files_in_selected_folder',created_at=time.time()))


def ensure_response_database(base):
    path=Path(base)/'observe.sqlite3'
    if path.exists():
        # A periodic snapshot must never initialize a live outbox connection:
        # its default auto-checkpoint could block behind the collector WAL.
        with closing(sqlite3.connect(path.absolute().as_uri()+'?mode=ro',uri=True,timeout=3)) as db:
            names={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('events','response_jobs','live_response_attempts')")}
        if names!={'events','response_jobs','live_response_attempts'}:
            raise ValueError('Existing response database requires controlled schema migration')
        return
    from .outbox import Outbox
    from .response_ledger import ResponseLedger
    with Outbox(path) as outbox:
        ResponseLedger(outbox.db)
        outbox.db.execute('''CREATE TABLE IF NOT EXISTS response_jobs (
            id TEXT PRIMARY KEY,owner TEXT NOT NULL,pid INTEGER NOT NULL,generation INTEGER NOT NULL,
            track TEXT NOT NULL,created REAL NOT NULL,state TEXT NOT NULL,reason TEXT,payload TEXT NOT NULL,
            UNIQUE(pid,generation))''')
        outbox.db.commit()


def refresh(runtime, *, create_snapshot=False, initial=False):
    base=Path(runtime);settings=json.loads((base/'protection.json').read_text(encoding='utf-8-sig'))
    folder,volume=validate_folder(settings['protected_root'],forbidden=(str(base),))
    if settings.get('acknowledged_folder_revert') is not True:
        raise ValueError('Folder restore not approved')
    status=dict(at=time.time(),protected_root=folder,ready=False,reason='checking',
                restore_scope=settings['restore_scope'],initial=initial)
    save_json(base/'protection-status.json',status)
    from .snapshot_retention import policy_path,RetentionPolicy
    from .firewall_control import FirewallHoldManager,FirewallProfile
    # These are the same durable databases used by intake and response.
    ensure_response_database(base)
    with FirewallHoldManager(base/'holds.sqlite3',FirewallProfile('https://api.typesafe.ai')):pass
    state=default_state_db();coordinator=HourlySnapshotCoordinator(state)
    # Initialize ownership storage without creating/adopting any snapshot.
    with coordinator._database():pass
    with snapshot_guard():
        sidecar=policy_path(state)
        old=json.loads(sidecar.read_text(encoding='utf-8-sig')) if sidecar.exists() else {}
        manifests=list(old.get('manifest_paths',[]))
        target=base/'protected-manifest.json'
        # A newly chosen folder has no fabricated manifest; include it only
        # once a verified catalog exists. Existing pins never disappear.
        if target.is_file() and str(target) not in manifests:manifests.append(str(target))
        if not manifests:
            placeholder=base/'unprepared-manifest.json'
            save_json(placeholder,{'schema_version':1,'manifest':[]})
            manifests=[str(placeholder)]
        policy=old.get('policy',vars(RetentionPolicy()))
        policy['max_used_bytes']=settings['snapshot_budget_gib']*1024**3
        RetentionPolicy(**policy)
        save_json(sidecar,dict(schema_version=1,enabled=True,policy=policy,
            outbox_db=str(base/'observe.sqlite3'),holds_db=str(base/'holds.sqlite3'),manifest_paths=manifests))
        with closing(sqlite3.connect(state)) as db:
            db.execute('CREATE TABLE IF NOT EXISTS snapshot_retention_required(singleton INTEGER PRIMARY KEY CHECK(singleton=1),required INTEGER NOT NULL)')
            db.execute('INSERT OR REPLACE INTO snapshot_retention_required VALUES(1,1)');db.commit()
        try:
            if create_snapshot:
                status['creation']=coordinator.run(volume,trigger='initial_setup' if initial else 'hourly_schedule')
            catalog=create_manifest(volume_root=volume,protected_root=folder,
                max_files=settings['max_files'],max_file_bytes=settings['max_file_bytes'],
                max_total_bytes=settings['max_total_bytes'],max_seconds=60)
            catalog.update(operator_review_required=False,automatic_activation=True,
                approved_restore_scope=settings['restore_scope'])
            save_json(target,catalog)
            if str(target) not in manifests:
                manifests.append(str(target));old=json.loads(sidecar.read_text());old['manifest_paths']=manifests;save_json(sidecar,old)
            status.update(ready=True,reason='verified_preincident_baseline',snapshot_id=catalog['snapshot_id'],
                snapshot_created_at=catalog['snapshot_created_at'],files=len(catalog['manifest']),bytes=catalog['catalog_bytes'])
        except Exception as error:
            status.update(reason='recovery_not_ready',detail=str(error),error_type=type(error).__name__)
    save_json(base/'protection-status.json',status)
    return status
