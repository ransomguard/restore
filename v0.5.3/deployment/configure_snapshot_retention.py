"""Prepare the shared retention policy and task XML on the protected Windows VM.

Does not create/delete VSS, register tasks, or change account/network/UI settings.
The running collector must already have initialized its response databases.
"""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
import sys
from contextlib import closing

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ransomguard.snapshot_guard import snapshot_guard
from ransomguard.snapshot_retention import RetentionPolicy, policy_path, protection_state
from ransomguard.snapshots import default_state_db, HourlySnapshotCoordinator
from ransomguard.scheduling import build_retention_task_xml


def configure(*, python, config, outbox, holds, manifests, user_sid, output, check=False):
    state = default_state_db()  # Live recovery pins use this same machine-wide DB.
    paths = [Path(p).resolve(strict=True) for p in (python, config, outbox, holds, *manifests)]
    if any(not p.is_file() for p in paths):
        raise ValueError('All selected paths must identify existing files')
    value = {'schema_version':1, 'enabled':True, 'policy':asdict(RetentionPolicy()),
             'outbox_db':str(paths[2]), 'holds_db':str(paths[3]),
             'manifest_paths':[str(p) for p in paths[4:]]}
    protection_state(value, [])
    from ransomguard.cli import _hourly_volume, _load_config
    volume_root = _hourly_volume(_load_config(str(paths[1])))
    xml = build_retention_task_xml(python_executable=str(paths[0]), config_path=str(paths[1]),
        state_db=str(state), outbox_db=str(paths[2]), user_sid=user_sid, volume_root=volume_root)
    target = policy_path(state)
    if target.exists() and json.loads(target.read_text(encoding='utf-8-sig')) != value:
        raise ValueError('Existing retention policy differs; review rather than overwrite it')
    output = Path(output).absolute()
    if output.exists():
        raise ValueError('Choose a new XML output file')
    if not check:
        with snapshot_guard():
            # Initialize only the ownership schema, never a VSS creation attempt.
            with HourlySnapshotCoordinator(state)._database():
                pass
            with closing(sqlite3.connect(state)) as db:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('CREATE TABLE IF NOT EXISTS snapshot_retention_required(singleton INTEGER PRIMARY KEY CHECK(singleton=1),required INTEGER NOT NULL)')
                db.execute('INSERT OR REPLACE INTO snapshot_retention_required VALUES(1,1)');db.commit()
            temp = target.with_suffix('.pending.json')
            temp.write_text(json.dumps(value,indent=2),encoding='utf-8');temp.replace(target)
            output.write_text(xml,encoding='utf-8')
    return {'state_db':str(state),'policy_file':str(target),'task_xml':str(output),'configured':not check,
            'tasks_registered':False,'snapshots_changed':False}


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('python','config','outbox','holds','user-sid','output'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--manifest',action='append',required=True)
    p.add_argument('--check',action='store_true')
    a=p.parse_args()
    print(json.dumps(configure(python=a.python,config=a.config,outbox=a.outbox,holds=a.holds,
        manifests=a.manifest,user_sid=a.user_sid,output=a.output,check=a.check),indent=2))
