"""Snapshot schedule and read-only native console. No network changes."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from datetime import datetime,timedelta,timezone

MINUTES=(15,30,60,120)

def schedule_path(state_db):return Path(state_db).with_suffix('.schedule.json')

def interval_minutes(state_db):
    p=schedule_path(state_db)
    if not p.exists():return 60
    v=json.loads(p.read_text(encoding='utf-8-sig'))
    n=v.get('interval_minutes')
    if v.get('schema_version')!=1 or type(n)!=int or n not in MINUTES:raise ValueError('Invalid snapshot schedule; creation refused')
    return n

def task_status():
    return powershell("$t=Get-ScheduledTask -TaskName 'RansomGuard-HourlySnapshot' -ErrorAction Stop;$i=Get-ScheduledTaskInfo -InputObject $t;@{interval=$t.Triggers[0].Repetition.Interval;nextRun=$i.NextRunTime.ToString('o');lastResult=$i.LastTaskResult}|ConvertTo-Json -Compress")

def powershell(code,data=None):
    from .recovery import _powershell_executable
    result=subprocess.run([_powershell_executable(),'-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop';[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"+code],input=json.dumps(data or {}),text=True,encoding='utf-8',capture_output=True,timeout=30,creationflags=0x08000000)
    if result.returncode:raise RuntimeError(result.stderr.strip()[-1500:] or 'Snapshot schedule operation failed')
    return json.loads(result.stdout.lstrip('\ufeff'))

def status(runtime):
    from .snapshots import default_state_db
    n=interval_minutes(default_state_db())
    try:task=task_status();error=None
    except Exception as e:task={};error=str(e)
    return {'intervalMinutes':n,'task':task,'error':error}

def change(runtime,minutes):
    if type(minutes)!=int or minutes not in MINUTES:raise ValueError('15, 30, 60, 120분 중 선택해 주세요.')
    from .snapshots import default_state_db,require_admin
    from .snapshot_guard import snapshot_guard
    from .scope_settings import scope_lock
    from .protection_setup import save_json
    require_admin()
    with scope_lock(runtime,timeout=60),snapshot_guard():
        p=schedule_path(default_state_db());old=p.read_bytes() if p.exists() else None
        # Anchor the next run to the last attempt rather than postponing it
        # another full interval every time the user saves Settings.
        now=datetime.now(timezone.utc);next_at=now+timedelta(minutes=minutes)
        db_path=default_state_db()
        if db_path.exists():
            from .scope_settings import read
            from .recovery import volume_id_for_root
            scope=read(runtime,'protection.json',{})
            if scope:
                volume=volume_id_for_root(scope['volume_root'])
                with closing(sqlite3.connect(db_path.as_uri()+'?mode=ro',uri=True,timeout=3)) as db:
                    row=db.execute('SELECT attempted_at FROM snapshot_attempts WHERE volume_id=? ORDER BY sequence DESC LIMIT 1',(volume,)).fetchone()
                if row:next_at=max(now+timedelta(minutes=1),datetime.fromisoformat(row[0])+timedelta(minutes=minutes))
        # Change only this task's trigger; preserve action, account and settings.
        code="""$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
$t=Get-ScheduledTask -TaskName 'RansomGuard-HourlySnapshot';$old=Export-ScheduledTask -TaskName $t.TaskName
$trigger=New-ScheduledTaskTrigger -Once -At ([datetime]::Parse($i.next_at).ToLocalTime()) -RepetitionInterval (New-TimeSpan -Minutes ([int]$i.minutes))
Set-ScheduledTask -TaskName $t.TaskName -Trigger $trigger|Out-Null
$actual=(Get-ScheduledTask -TaskName $t.TaskName).Triggers[0].Repetition.Interval
@{xml=$old;interval=$actual}|ConvertTo-Json -Compress"""
        changed=powershell(code,{'minutes':minutes,'next_at':next_at.isoformat()})
        try:
            if changed['interval'] not in (f'PT{minutes}M',f'PT{minutes//60}H' if minutes%60==0 else ''):raise RuntimeError('Scheduled interval verification failed')
            save_json(p,{'schema_version':1,'interval_minutes':minutes})
        except BaseException:
            powershell("$i=[Console]::In.ReadToEnd()|ConvertFrom-Json;Register-ScheduledTask -TaskName 'RansomGuard-HourlySnapshot' -Xml $i.xml -Force|Out-Null;@{restored=$true}|ConvertTo-Json",{'xml':changed['xml']})
            if old is None:p.unlink(missing_ok=True)
            else:p.write_bytes(old)
            raise
    return status(runtime)

def inventory(runtime):
    from .scope_settings import read
    from .snapshots import default_state_db
    from .recovery import enumerate_snapshots,volume_id_for_root
    from .snapshot_retention import load_config,protection_state
    result={'schedule':status(runtime),'recovery':read(runtime,'protection-status.json',{})}
    config=read(runtime,'protection.json',{})
    if not config:return result|{'snapshots':[],'reason':'scope_not_configured'}
    state=default_state_db();copies=enumerate_snapshots(volume_id_for_root(config['volume_root']))
    owned=set();attempts=[]
    if state.exists():
        with closing(sqlite3.connect(state.as_uri()+'?mode=ro',uri=True,timeout=3)) as db:
            rows=db.execute('SELECT attempted_at,status,result_json FROM snapshot_attempts ORDER BY sequence DESC').fetchall()
            for at,st,raw in rows:
                v=json.loads(raw);snap=v.get('snapshot') or {}
                if st in ('created','reconciled_created') and snap.get('snapshot_id'):owned.add(snap['snapshot_id'].lower())
                if len(attempts)<10:attempts.append({'attempted_at':at,'status':st,'result':v})
    try:
        protected,reasons=protection_state(load_config(state),copies)
        result['protection_reasons']=reasons
    except Exception as e:
        protected=None;result['protection_error']=str(e)
    from .snapshot_management import user_pins
    pins=user_pins(state)
    result['snapshots']=[x.to_dict()|{'created_by_ransomguard':x.snapshot_id.lower() in owned,'user_protected':x.snapshot_id in pins,'protected':None if protected is None else x.snapshot_id in protected|pins} for x in copies]
    result['recent_attempts']=attempts
    return result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',required=True);parser.add_argument('action',choices=('status','change','inventory','launch','console','list','manual','protect','restore-preview','restore-execute'));args=parser.parse_args()
    if args.action=='launch':
        child=subprocess.Popen([sys.executable,'-u','-m','ransomguard.snapshot_settings','--runtime',args.runtime,'console'],cwd=str(Path(__file__).resolve().parent.parent),creationflags=subprocess.CREATE_NEW_CONSOLE|subprocess.CREATE_NEW_PROCESS_GROUP,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
        print(json.dumps({'viewer_pid':child.pid}));return
    if args.action=='console':
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW('RansomGuard VSS snapshot status - read only')
        sys.stdin=open('CONIN$','r');sys.stdout=open('CONOUT$','w',encoding='utf-8',buffering=1);sys.stderr=sys.stdout
        while True:
            try:print(json.dumps(inventory(args.runtime),ensure_ascii=False,indent=2,default=str))
            except Exception as e:print('ERROR:',str(e))
            if input('\nEnter: refresh VSS status / Q: close (collection continues) > ').lower()=='q':return
    else:
        try:
            from .snapshot_management import list_owned,manual,protect
            if args.action=='restore-preview':
                from .manual_restore import preview
                result=preview(args.runtime,json.load(sys.stdin)['snapshotId'])
            elif args.action=='restore-execute':
                from .manual_restore import execute
                v=json.load(sys.stdin);result=execute(args.runtime,v['token'],v.get('confirmed'))
            elif args.action=='manual':result=manual(args.runtime,json.load(sys.stdin)['requestId'])
            elif args.action=='protect':
                v=json.load(sys.stdin);result=protect(args.runtime,v['snapshotId'],v['enabled'])
            elif args.action=='list':result=list_owned(args.runtime)
            else:result=change(args.runtime,json.load(sys.stdin)['intervalMinutes']) if args.action=='change' else inventory(args.runtime) if args.action=='inventory' else status(args.runtime)
            print(json.dumps(result,ensure_ascii=False,default=str))
        except Exception as e:print(json.dumps({'error':str(e)},ensure_ascii=False));sys.exit(1)

if __name__=='__main__':main()
