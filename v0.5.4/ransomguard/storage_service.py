"""SCM entry point for the separate service build. No network or command listener."""
from pathlib import Path
import ctypes
from ctypes import wintypes
import json
import os
import sys
import threading
import time

from .resident import write_json
from .service_migration import ALLOWLIST, STORES, check_schema, migrate
from .service_identity import SERVICE as NAME, require_service_account


def serve_store(root, stop, on_ready, *, worker=None):
    """Only report SCM readiness after the registered collector acknowledges startup."""
    root = Path(root)
    target = root / "private" / "stores"
    if not target.exists():
        migrate(root / "incoming", root / "private")
    receipt = json.loads((target / "import.json").read_text(encoding="utf-8"))
    required = set(STORES)
    if "Runtime/" + ALLOWLIST in receipt.get("source_files", {}):
        required.add(ALLOWLIST)
    if receipt.get("schema") != 1 or set(receipt["imported_sha256"]) != required:
        raise ValueError("Incomplete storage migration receipt")
    import sqlite3
    from contextlib import ExitStack, closing
    # Never create a missing database on restart. Do not replay, unblock or reset an incident here.
    with ExitStack() as stack:
        for name in sorted(required):
            db = stack.enter_context(closing(sqlite3.connect((target / name).as_uri() + "?mode=rw", uri=True)))
            if db.execute("PRAGMA journal_mode").fetchone()[0] != "wal":
                raise ValueError("Unexpected SQLite journal mode")
            db.execute("PRAGMA synchronous=FULL")
            check_schema(db, name)
    if stop.is_set():
        return
    (worker or run_collector)(target, stop, on_ready)


def run_collector(target, stop, on_ready):
    from .cli import main as collector
    from .live_profile import observer_options
    from .firewall_control import FirewallHoldManager, FirewallProfile
    bundle = Path(sys.executable).resolve().parent.parent
    profile_path = target / "live-response-profile.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8-sig")) if profile_path.exists() else {}
    if profile and (Path(profile["config"]) != target / "response-config.json" or
                    Path(profile["manifest"]) != target / "protected-manifest.json"):
        raise ValueError("Service profile references a different runtime")
    write_json(target / "installation.json", {"schema": 1, "evidence_mode": "test",
        "python": str(bundle / "python/python.exe"), "recovery_root": str(bundle / "backend"),
        "ui": str(bundle / "ui/ransom0-ui.exe"), "firewall": str(bundle / "firewall/r0-fw-daemon.exe")})
    bridge = bundle / "bridge/RansomGuard.JevBridge.exe"
    if bridge.is_file():
        write_json(target / "jev-transport.json", {"endpoint": "https://api.typesafe.ai", "bridge": str(bridge)})
    opts, _ = observer_options(profile_path, state_db=target / "holds.sqlite3")
    if "--live-track-b" in opts:
        if not bridge.is_file():
            raise FileNotFoundError("Missing packaged JEV bridge")
        import subprocess
        key_check = subprocess.run([str(bridge), "--check-key"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        if key_check.returncode:
            raise PermissionError("Registered JEV key unavailable to the storage service")
        os.environ["RANSOMGUARD_JEV_BRIDGE"] = str(bridge)
    os.environ["RANSOM0_SERVICE_STORAGE"] = "1"
    os.environ["RANSOMGUARD_RUNTIME_DIR"] = str(target)
    os.environ["RANSOM0_FIREWALL_STATE_DB"] = str(target / "holds.sqlite3")
    os.environ["RANSOM0_EVIDENCE_MODE"] = "test"
    firewall_profile = FirewallProfile("https://api.typesafe.ai", tuple(profile.get("approved_extra_https_targets", [])))
    with FirewallHoldManager(target / "holds.sqlite3", firewall_profile) as owner:
        owner.reconcile_owned_holds()
    ready = target / "observer-ready.json"
    marker = ready.with_suffix(".stop")
    marker.unlink(missing_ok=True)  # This private tree has one SCM owner.
    start = time.time()
    finished = threading.Event()
    def supervise():
        announced = False
        while not finished.wait(.2):
            if stop.is_set():
                marker.touch(exist_ok=True)
                return
            if not announced:
                try:
                    h = json.loads(ready.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if (h.get("pid") == os.getpid() and h.get("driver_registered") is True
                        and h.get("worker_state") == "running" and h.get("observed_at", 0) >= start):
                    on_ready()
                    announced = True
    monitor = threading.Thread(target=supervise, name="SCM collector readiness")
    from .service_operations import operate
    operations = threading.Thread(target=operate, args=(target.parent.parent, finished), name="SCM operator requests")
    operations.start()
    monitor.start()
    try:
        status = collector(["observe","--resident","--ui","--ui-durable","--quiet-events",
                            "--prefetch-events","131072","--ready-file",str(ready),"--status-every","512",
                            "--db",str(target / "observe.sqlite3"), *opts])
        if status or not stop.is_set():
            raise RuntimeError(f"Service collector exited with status {status}")
    finally:
        finished.set()
        monitor.join()
        operations.join()


def main():
    if os.name != "nt":
        raise OSError("Windows SCM is required")
    require_service_account()
    # The packaged interpreter resides under <trusted installation>/python.
    # Neither SCM start arguments nor an interactive user's environment select executable code.
    root = Path(sys.executable).resolve().parent.parent / "service-state"
    if not (root / "private").is_dir():
        raise RuntimeError("Missing protected service state directory")
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    service_main = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
    handler_type = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.LPVOID)

    class Status(ctypes.Structure):
        _fields_ = [(key, wintypes.DWORD) for key in (
            "serviceType", "state", "accepts", "win32Exit", "serviceExit", "checkpoint", "waitHint")]

    class Entry(ctypes.Structure):
        _fields_ = [("name", wintypes.LPWSTR), ("main", service_main)]

    adv.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, handler_type, wintypes.LPVOID]
    adv.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    adv.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(Status)]
    adv.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(Entry)]
    stop = threading.Event()
    handle = None
    state_lock = threading.RLock()
    state = Status(0x10, 2, 0, 0, 0, 1, 30000)

    def publish(value, accepts=0, code=0):
        with state_lock:
            state.state, state.accepts, state.win32Exit = value, accepts, code
            state.checkpoint = state.checkpoint + 1 if value in (2, 3) else 0
            state.waitHint = 30000 if value in (2, 3) else 0
            if not adv.SetServiceStatus(handle, ctypes.byref(state)):
                raise ctypes.WinError(ctypes.get_last_error())

    @handler_type
    def handler(control, _kind, _data, _context):
        if control in (1, 5):
            stop.set()
            publish(3)
        elif control != 4:
            return 120
        return 0

    @service_main
    def run(argc, argv):
        nonlocal handle
        handle = adv.RegisterServiceCtrlHandlerExW(NAME, handler, None)
        if not handle:
            return
        code = 0
        startup_done = threading.Event()
        def checkpoint():
            while not startup_done.wait(5):
                with state_lock:
                    if state.state == 2:
                        publish(2)
        def ready():
            with state_lock:
                if not stop.is_set():
                    publish(4, 5)
            startup_done.set()
        monitor = threading.Thread(target=checkpoint, name="SCM startup checkpoint")
        try:
            publish(2)
            monitor.start()
            args = [argv[i] for i in range(1, argc)]
            marker_path = root / "incoming/service-owner.json"
            imported = root / "private/stores/import.json"
            if args == ["import-quiesced"]:
                if imported.exists() or marker_path.exists():
                    raise ValueError("Existing storage owner")
                gate = root.parent / "BenignStorageCheck/owner-switch-active.lock"
                import msvcrt
                # The installer holds a byte-range lock through quiescence and publication.
                with gate.open("rb") as lock:
                    try:
                        msvcrt.locking(lock.fileno(), msvcrt.LK_NBRLCK, 1)
                    except OSError as exc:
                        if exc.errno != 13: raise
                    else:
                        msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                        raise RuntimeError("No active handover")
                    migrate(Path(os.environ["ProgramData"]) / "RansomGuard", root / "private")
            elif not args and imported.is_file():
                serve_store(root, stop, ready)
            elif args == ["verify-storage"] and not imported.exists() and not marker_path.exists():
                from .storage_acceptance import verify_inactive_storage
                verify_inactive_storage(root, stop, ready)
            elif not args:
                marker = json.loads(marker_path.read_text(encoding="utf-8-sig"))
                if marker != {"owner": NAME, "schema": 1}:
                    raise RuntimeError("Storage registration has not completed")
                serve_store(root, stop, ready)
            else:
                raise ValueError("Unexpected service request or storage already active")
        except Exception as exc:
            code = 13
            write_json(root / "private/service-status.json", {"state": "failed", "error": str(exc), "at": time.time()})
        finally:
            startup_done.set()
            if monitor.is_alive():
                monitor.join()
            publish(1, code=code)

    services = (Entry * 2)(Entry(NAME, run), Entry())
    if not adv.StartServiceCtrlDispatcherW(services):
        raise ctypes.WinError(ctypes.get_last_error())


if __name__ == "__main__":
    main()
