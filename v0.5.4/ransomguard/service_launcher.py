"""Connect the interactive session to the registered storage owner."""
import os
from pathlib import Path
import subprocess
import time


def start_session(state, session_runtime, ui, daemon, inventory, spawn):
    from .supervision import _observer
    from .health_report import report
    from .firewall_ipc import FirewallIpcClient
    procs = inventory()
    if any(_observer(p, session_runtime / "observe.sqlite3") for p in procs):
        raise RuntimeError("The previous collector still owns intake. Finish its cooperative shutdown.")
    target = state / "private/stores"
    env = dict(os.environ, RANSOM0_STORAGE_OWNER="scm", RANSOMGUARD_RUNTIME_DIR=str(target),
               RANSOM0_FIREWALL_STATE_DB=str(target / "holds.sqlite3"))
    def exact(path):
        return next((p["ProcessId"] for p in procs if os.path.normcase(str(p.get("ExecutablePath", ""))) ==
                     os.path.normcase(str(path))), None)
    daemon_pid = exact(daemon) or spawn([str(daemon)], "firewall", env)
    ipc = FirewallIpcClient(timeout_ms=500)
    for i in range(20):
        try:
            ipc.request("get")
            break
        except (OSError, RuntimeError):
            if i == 19:
                raise
            time.sleep(.25)
    sc = str(Path(os.environ["SystemRoot"]) / "System32/sc.exe")
    def start(name):
        response = subprocess.run([sc, "start", name], capture_output=True, timeout=30,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        if response.returncode not in (0, 1056):
            raise RuntimeError(f"SCM could not start {name}: {response.returncode}")
    start("Ransom0Storage")
    from .service_identity import scm_pid
    deadline = time.monotonic() + 120
    while True:
        active = scm_pid()
        status = report(target)
        if active and status["collector_ready"] and status["collector_pid"] == active:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("No fresh heartbeat from the registered service. Inspect its status.")
        time.sleep(.25)
    candidates = [p for p in inventory() if os.path.normcase(str(p.get("ExecutablePath") or "")) == os.path.normcase(str(ui))
                  and " --type=" not in str(p.get("CommandLine") or "")]
    if len(candidates)>1:raise RuntimeError("Multiple dashboard owners")
    ui_pid = candidates[0]["ProcessId"] if candidates else None
    pid_path = session_runtime / "service-ui.pid"
    if ui_pid and (not pid_path.is_file() or pid_path.read_text().strip() != str(ui_pid)):
        raise RuntimeError("Close the dashboard launched against the previous database before switching")
    ui_pid = ui_pid or spawn([str(ui), "--disable-gpu"], "ui", env)
    pid_path.write_text(str(ui_pid))
    from .ui_process_rights import allow_storage_query
    allow_storage_query(ui_pid, ui)
    from .service_operations import submit
    submit(state, "ui.attach", {"uiPid": ui_pid, "uiDbPath": str(Path(env["APPDATA"]) / "ransom0-ui/db.sqlite")})
    start("Anti_Ransom_FsFilter")
    return {"collector_pid": active, "ui": ui_pid, "daemon": daemon_pid, "storage_owner": "Ransom0Storage"}
