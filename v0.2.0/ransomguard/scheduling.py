"""Build a reviewable Windows task definition without installing or running it.

The single timer starts at the next UTC hour and repeats every hour indefinitely.
It does not run at registration/logon/boot, catch up missed runs, wake the VM,
retry failures, or permit manual Task Scheduler starts. Snapshot creation itself
also uses the durable, per-volume hourly gate in snapshots.py.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import PureWindowsPath
import re
import subprocess
from xml.etree import ElementTree as ET


TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
ET.register_namespace("", TASK_NAMESPACE)


def next_hour(now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("The schedule time must include a timezone")
    return now.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)


def _local_path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or any(c in value for c in '\r\n\x00"<>|?*'):
        raise ValueError(f"{label} must be an absolute local Windows path")
    path = PureWindowsPath(value)
    if not path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", path.drive) or ".." in path.parts:
        raise ValueError(f"{label} must be an absolute local Windows path")
    if any(":" in part for part in path.parts[1:]):
        raise ValueError(f"{label} must not contain an alternate data stream")
    return str(path)


def build_hourly_task_xml(*, python_executable: str, config_path: str,
                          state_db: str, outbox_db: str, user_sid: str,
                          now: datetime | None = None) -> str:
    """Return XML for the current administrator's elevated interactive session.

    The task is deliberately not SYSTEM and stores no password. It runs while
    the registering user is logged on; the VM must be running and awake. The
    package must already be installed into this exact Python interpreter.
    """
    executable = _local_path(python_executable, "python_executable")
    config = _local_path(config_path, "config_path")
    state = _local_path(state_db, "state_db")
    outbox = _local_path(outbox_db, "outbox_db")
    if PureWindowsPath(executable).suffix.lower() != ".exe":
        raise ValueError("python_executable must identify a Python executable")
    if len({config.casefold(), state.casefold(), outbox.casefold()}) != 3:
        raise ValueError("Configuration, snapshot state, and event outbox must use different files")
    if not isinstance(user_sid, str) or re.fullmatch(r"S-1-[0-9]+(?:-[0-9]+)+", user_sid) is None:
        raise ValueError("A concrete Windows user SID is required")
    if user_sid in {"S-1-5-18", "S-1-5-19", "S-1-5-20"}:
        raise ValueError("Use the logged-on administrator's SID, not a service account")

    def add(parent: ET.Element, name: str, value: str | None = None, **attrs: str) -> ET.Element:
        item = ET.SubElement(parent, "{" + TASK_NAMESPACE + "}" + name, attrs)
        item.text = value
        return item

    task = ET.Element("{" + TASK_NAMESPACE + "}Task", {"version": "1.2"})
    registration = add(task, "RegistrationInfo")
    add(registration, "Description", "RansomGuard hourly VSS snapshot; no incident/startup snapshots; v0.6.1")
    triggers = add(task, "Triggers")
    timer = add(triggers, "TimeTrigger")
    repetition = add(timer, "Repetition")
    add(repetition, "Interval", "PT1H")
    add(repetition, "StopAtDurationEnd", "false")
    add(timer, "StartBoundary", next_hour(now).isoformat(timespec="seconds"))
    add(timer, "Enabled", "true")
    principals = add(task, "Principals")
    principal = add(principals, "Principal", id="SnapshotUser")
    add(principal, "UserId", user_sid)
    add(principal, "LogonType", "InteractiveToken")
    add(principal, "RunLevel", "HighestAvailable")
    settings = add(task, "Settings")
    for name, value in (
        ("MultipleInstancesPolicy", "IgnoreNew"),
        ("DisallowStartIfOnBatteries", "false"),
        ("StopIfGoingOnBatteries", "false"),
        ("AllowHardTerminate", "false"),
        ("StartWhenAvailable", "false"),
        ("RunOnlyIfNetworkAvailable", "false"),
        ("AllowStartOnDemand", "false"),
        ("Enabled", "true"),
        ("Hidden", "false"),
        ("RunOnlyIfIdle", "false"),
        ("WakeToRun", "false"),
        ("ExecutionTimeLimit", "PT10M"),
        ("Priority", "7"),
    ):
        add(settings, name, value)
    actions = add(task, "Actions", Context="SnapshotUser")
    execute = add(actions, "Exec")
    add(execute, "Command", executable)
    add(execute, "Arguments", subprocess.list2cmdline([
        "-I", "-m", "ransomguard", "snapshot-run", "--config", config,
        "--state-db", state, "--db", outbox,
    ]))
    add(execute, "WorkingDirectory", str(PureWindowsPath(config).parent))
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(task, encoding="unicode") + "\n"
