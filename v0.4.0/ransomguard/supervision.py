"""Passive collector supervision decisions. Never terminate or alter firewall policy."""
from __future__ import annotations

import ntpath
import shlex


def _path(value):
    return ntpath.normcase(ntpath.normpath(str(value or "")))


def _observer(process, db_path):
    if ntpath.basename(_path(process.get("ExecutablePath"))) != "python.exe":
        return False
    try:
        lexer = shlex.shlex(process.get("CommandLine") or "", posix=True)
        lexer.whitespace_split = True
        lexer.escape = ""  # Windows path separators are literal backslashes.
        lexer.commenters = ""
        args = list(lexer)
    except ValueError:
        return False
    return (any(args[i:i + 3] == ["-m", "ransomguard", "observe"] for i in range(len(args)))
            and args.count("--db") == 1 and args.index("--db") + 1 < len(args)
            and _path(args[args.index("--db") + 1]) == _path(db_path))


def assess(processes, runtime, ready, *, db_path, ui_path, daemon_path):
    """Only restart an absent passive collector while its known UI/daemon survive.

    UI closure is intentionally not treated as a crash. A live but unready
    collector is reported, never forcibly terminated by this supervisor.
    """
    def known(pid, path):
        return any(p.get("ProcessId") == pid and _path(p.get("ExecutablePath")) == _path(path)
                   for p in processes)

    if runtime.get("mode") != "observe-only":
        return "manual_attention", "not_passive_runtime"
    if not known(runtime.get("ui"), ui_path):
        return "manual_attention", "ui_closed_or_missing"
    if not known(runtime.get("daemon"), daemon_path):
        return "manual_attention", "firewall_daemon_missing"
    observers = [p for p in processes if _observer(p, db_path)]
    if not observers:
        return "restart_collector", "collector_absent"
    if (ready.get("driver_registered") is True and _path(ready.get("db")) == _path(db_path)
            and any(p["ProcessId"] == ready.get("pid") for p in observers)):
        return "observing", "collector_ready"
    return "manual_attention", "collector_alive_but_not_ready"


def allow_restart(previous_attempts, now, *, limit=3, window=900):
    # A future timestamp (clock rollback) conservatively keeps the attempt.
    recent = [t for t in previous_attempts if isinstance(t, (int, float)) and t > now - window]
    return len(recent) < limit, recent


def maintenance_active(record, now):
    # Malformed maintenance metadata must not silently disable supervision.
    if not isinstance(record, dict):
        return False
    start, end = record.get("created_at"), record.get("until")
    return (type(start) in (int, float) and type(end) in (int, float)
            and bool(record.get("reason")) and 0 < end - start <= 3600
            and start <= now < end)
