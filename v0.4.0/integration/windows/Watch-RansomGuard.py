"""One bounded scheduled health check; never opens a listener or releases holds."""
import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import sys
import time

BASE = Path(r'C:\RG_Test\Dashboard_Integration_20261116')
ROOT = Path(r'C:\RG_Test\RansomGuard_RecoveryJEV_v0.4.0')
sys.path.insert(0, str(ROOT))
from ransomguard.supervision import assess, allow_restart, maintenance_active


def load(name):
    try:
        return json.loads((BASE / name).read_text(encoding='utf8'))
    except FileNotFoundError:
        return {}


def save(report):
    report['checked_at'] = time.time()
    target = BASE / 'supervisor-status.json'
    tmp = target.with_suffix('.tmp')
    tmp.write_text(json.dumps(report, indent=2), encoding='utf8')
    tmp.replace(target)


def check(launcher):
    return assess(launcher.inventory(), load('runtime.json'), load('observer-ready.json'),
                  db_path=BASE / 'observe.sqlite3', ui_path=launcher.UI, daemon_path=launcher.DAEMON)


def main():
    session = C.c_ulong()
    if (not C.windll.kernel32.ProcessIdToSessionId(os.getpid(), C.byref(session)) or session.value == 0):
        raise RuntimeError('Supervisor requires the existing interactive user session')
    # Scheduled task uses IgnoreNew; retain a mutex for manual/duplicate invocations too.
    kernel = C.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [C.c_void_p, C.c_int, C.c_wchar_p]
    kernel.CreateMutexW.restype = C.c_void_p
    kernel.CloseHandle.argtypes = [C.c_void_p]
    handle = kernel.CreateMutexW(None, False, 'Local\\RansomGuardPassiveSupervisor')
    if not handle:
        raise C.WinError(C.get_last_error())
    if C.get_last_error() == 183:
        kernel.CloseHandle(handle)
        return
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location('rg_launcher', BASE / 'Start-RansomGuard.py')
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        previous = load('supervisor-status.json')
        allowed, attempts = allow_restart(previous.get('restart_attempts', []), time.time())
        report = dict(restart_attempts=attempts, network_changed=False, password_changed=False)
        if maintenance_active(load('supervisor-maintenance.json'), time.time()):
            report.update(state='maintenance', reason='bounded_maintenance_window')
            save(report)
            return
        state, reason = check(launcher)
        report.update(state=state, reason=reason)
        if state == 'restart_collector':
            if not allowed:
                report.update(state='manual_attention', reason='restart_budget_exhausted')
            else:
                report['restart_attempts'].append(time.time())
                save(report)  # Record the attempt before invoking another process.
                with (BASE / 'supervisor.stdout.log').open('ab') as out, (BASE / 'supervisor.stderr.log').open('ab') as err:
                    result = subprocess.run([str(launcher.PY), str(BASE / 'Start-RansomGuard.py')],
                                            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                            timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
                state, reason = check(launcher)
                report.update(state=state, reason=reason, launch_exit=result.returncode)
                if result.returncode != 0 or state != 'observing':
                    report.update(state='manual_attention', reason='restart_not_confirmed')
        # Keep the unresolved firewall status visible; observing is not protection certification.
        report['firewall_reconciliation'] = load('runtime.json').get('firewall_reconciliation')
        save(report)
    finally:
        kernel.CloseHandle(handle)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Preserve restart budget even on inventory/launch failure. Never kill live processes.
        try:
            prior = load('supervisor-status.json')
            prior.update(state='manual_attention', reason='supervisor_error', error=type(error).__name__)
            save(prior)
        except Exception:
            pass
        raise
