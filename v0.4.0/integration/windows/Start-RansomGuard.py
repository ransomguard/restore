"""Local VM launcher. No listener, network setting, credential or startup-task changes."""
import ctypes as C
import json,os,subprocess,sys,time
from pathlib import Path

BASE=Path(r'C:\RG_Test\Dashboard_Integration_20261116')
ROOT=Path(r'C:\RG_Test\RansomGuard_RecoveryJEV_v0.4.0')
UI=Path(r'C:\RG_Test\Dashboard\ransom0-ui.exe')
PY=ROOT/'.venv'/'Scripts'/'python.exe'
DAEMON=Path(r'C:\RG_Test\firewall-manager-main\bin\r0-fw-daemon.exe')

def inventory():
    command="Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('python.exe','ransom0-ui.exe','r0-fw-daemon.exe') } | Select-Object ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
    result=subprocess.run(['powershell.exe','-NoProfile','-Command',command],capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise RuntimeError('Process inventory failed')
    value=json.loads(result.stdout.decode('utf-8-sig'))
    return value if isinstance(value,list) else [value]

def spawn(args,label,env):
    with (BASE/(label+'.stdout.log')).open('ab') as out,(BASE/(label+'.stderr.log')).open('ab') as err:
        return subprocess.Popen(args,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                                close_fds=True,creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | (subprocess.DETACHED_PROCESS if label!='ui' else 0)).pid

def main():
    if os.name!='nt' or not C.windll.shell32.IsUserAnAdmin():raise RuntimeError('Run in the guest as administrator')
    session=C.c_ulong()
    if not C.windll.kernel32.ProcessIdToSessionId(os.getpid(),C.byref(session)) or session.value==0:
        raise RuntimeError('Run RansomGuard-InteractiveStartup in the logged-on user session; do not launch the dashboard as SYSTEM')
    if not ROOT.is_dir() or not UI.is_file():raise RuntimeError('Expected guest installation missing')
    BASE.mkdir(exist_ok=True)
    for service in ('Anti_Ransom_Driver','Anti_Ransom_FsFilter'):
        result=subprocess.run(['sc.exe','start',service],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode not in (0,1056):raise RuntimeError('Could not start '+service)
    sys.path.insert(0,str(ROOT))
    from ransomguard.firewall_control import FirewallHoldManager,FirewallProfile,FirewallHoldError
    with FirewallHoldManager(BASE/'holds.sqlite3',FirewallProfile('https://api.typesafe.ai')):pass
    processes=inventory()
    def exact(path):
        return next((p['ProcessId'] for p in processes if str(p.get('ExecutablePath','')).casefold()==str(path).casefold()),None)
    env=os.environ.copy();env['RANSOM0_EVIDENCE_MODE']='test';env['RANSOM0_TEST_RUN_ID']='isolated-vm-validation';env['RANSOM0_FIREWALL_STATE_DB']=str(BASE/'holds.sqlite3')
    daemon=exact(DAEMON) or spawn([str(DAEMON)],'firewall',env)
    from ransomguard.firewall_ipc import FirewallIpcClient,FirewallIpcError
    ready=FirewallIpcClient(timeout_ms=500)
    for attempt in range(12):
        try:
            ready.request('get');break
        except (FirewallIpcError,OSError,TimeoutError):
            if attempt==11:raise
            time.sleep(.25)
    with FirewallHoldManager(BASE/'holds.sqlite3',FirewallProfile('https://api.typesafe.ai')) as owner:
        try:
            reconciliation=owner.reconcile_owned_holds()
        except FirewallHoldError as error:
            # Passive observation may continue while a review hold remains.
            # Never release/adopt unknown policy or enable live response here.
            reconciliation={"review_required":True,"reason":str(error),"active_holds":owner.status()["active_holds"],"reasserted":False}
    # Only reuse the UI started by this integration (known policy environment).
    saved_ui=int((BASE/'ui.pid').read_text().strip()) if (BASE/'ui.pid').exists() else None
    ui=next((p['ProcessId'] for p in processes if p['ProcessId']==saved_ui and
             str(p.get('ExecutablePath','')).casefold()==str(UI).casefold()),None)
    if not ui and exact(UI):raise RuntimeError('Close the separately launched dashboard before integrated startup')
    ui_restarted = ui is None
    ui=ui or spawn([str(UI)],'ui',env)
    (BASE/'ui.pid').write_text(str(ui))
    env['RANSOM0_UI_PROCESS_ID']=str(ui)
    env['RANSOM0_UI_DATABASE']=str(Path(os.environ['APPDATA'])/'ransom0-ui'/'db.sqlite')
    outbox=str(BASE/'observe.sqlite3')
    existing=next((p['ProcessId'] for p in processes if p.get('CommandLine') and
                   'ransomguard observe' in p['CommandLine'] and outbox.casefold() in p['CommandLine'].casefold()),None)
    ready_path=BASE/'observer-ready.json'
    try:ready=json.loads(ready_path.read_text())
    except (OSError,ValueError):ready={}
    ready_valid=any(p['ProcessId']==ready.get('pid') and p.get('CommandLine') and 'ransomguard observe' in p['CommandLine'] and outbox.casefold() in p['CommandLine'].casefold() for p in processes)
    if existing and (ui_restarted or not ready_valid):
        # Refresh the exact UI PID used by the SQLite feedback filter.
        subprocess.run(['taskkill','/PID',str(existing),'/T','/F'],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
        existing=None
    if not existing:
        ready_path.unlink(missing_ok=True)
        observer=spawn([str(PY),'-m','ransomguard','observe','--ui','--ui-durable','--quiet-events','--prefetch-events','8192','--ready-file',str(ready_path),'--status-every','50','--db',outbox],'observer',env)
        deadline=time.monotonic()+20
        while True:
            try:ready=json.loads(ready_path.read_text())
            except (OSError,ValueError):ready={}
            if ready.get('driver_registered') and str(ready.get('db','')).casefold()==outbox.casefold():break
            if time.monotonic()>deadline:raise RuntimeError('Observer did not report driver registration; inspect observer.stderr.log')
            time.sleep(.1)
    else:observer=existing
    report={'ui':ui,'observer':observer,'observer_engine_pid':ready['pid'],'daemon':daemon,'mode':'observe-only','firewall_reconciliation':reconciliation,'network_changed':False,'password_changed':False}
    (BASE/'runtime.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report))

if __name__=='__main__':main()
