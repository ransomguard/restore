"""Suppress the observer's *own* SQLite I/O before persistence or triage.

The kernel still observes these operations. Filtering is intentionally limited
to the exact outbox database and SQLite sidecars, and to this observer's PID;
another process writing to the same path remains security-relevant evidence.
"""

from __future__ import annotations

import ntpath
import os
from pathlib import Path
import re
import sys
from typing import Callable

from .protocol import Event

_SQLITE_SIDECARS = ("", "-wal", "-shm", "-journal")


def _normalize_path(path: str) -> str:
    """Compare NT and DOS paths without treating a shared suffix as identity."""
    return ntpath.normcase(ntpath.normpath(path))


def _query_dos_device(drive: str) -> str | None:
    """Map a drive letter to its actual NT device on Windows, if available."""
    if sys.platform != "win32" or not re.fullmatch(r"[A-Za-z]:", drive):
        return None
    import ctypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.QueryDosDeviceW
    query.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
    query.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    if not query(drive, buffer, len(buffer)):
        return None  # Unknown mapping: keep observing, rather than guess a disk.
    return buffer.value


def _database_aliases(path: str, nt_device: str | None = None) -> frozenset[str]:
    """Build exact path identities, including NT volume and SQLite journal files."""
    names = {path}
    drive, suffix = ntpath.splitdrive(path)
    if re.fullmatch(r"[A-Za-z]:", drive):
        names.update(("\\??\\" + path, "\\\\?\\" + path))
        if nt_device and nt_device.startswith("\\"):
            names.add(nt_device.rstrip("\\") + suffix)
    return frozenset(_normalize_path(name + extra) for name in names for extra in _SQLITE_SIDECARS)


class ObserverOutboxFilter:
    """Match only file I/O by this process against its own outbox files."""

    def __init__(self, db_path: str | Path, *, observer_pid: int | None = None,
                 device_resolver: Callable[[str], str | None] = _query_dos_device):
        absolute_path = str(Path(db_path).resolve())
        drive = ntpath.splitdrive(absolute_path)[0]
        nt_device = device_resolver(drive) if re.fullmatch(r"[A-Za-z]:", drive) else None
        self.observer_pid = os.getpid() if observer_pid is None else observer_pid
        self._file_paths = _database_aliases(absolute_path, nt_device)

    def matches(self, event: Event) -> bool:
        if event.event_type not in (4, 5) or event.pid != self.observer_pid:
            return False
        path = event.fields.get("path")
        return isinstance(path, str) and bool(path) and _normalize_path(path) in self._file_paths
