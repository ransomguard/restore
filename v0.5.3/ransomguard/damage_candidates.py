"""Build a bounded, read-only recovery manifest *proposal* from the outbox.

Kernel ABI v1 reports PRE-OPERATION write attempts, not a confirmed result and
not the complete set of files damaged by a process. Therefore this component
NEVER restores files, authorizes kernel termination, or claims confirmed loss.
It requires a previously observed matching process-creation FILETIME and an
exact operator-approved NT test directory scope. Only eligible WRITE source
paths are included; RENAME source paths cannot identify the final destination.
"""

from __future__ import annotations

from collections import OrderedDict
import json
import re
import sqlite3
from typing import Any

from .protocol import FILE_FLAG_HIGH_ENTROPY, filetime_to_iso
from .recovery import ManifestEntry, RecoveryValidationError


_PREFIX = re.compile(r"^\\Device\\HarddiskVolume[0-9]+\\[^*?]+\\$", re.IGNORECASE)


def approved_nt_directory(raw: str) -> str:
    if not isinstance(raw, str):
        raise ValueError("An exact NT test-directory prefix is required")
    prefix = raw.replace("/", "\\").rstrip("\\") + "\\"
    if not _PREFIX.fullmatch(prefix):
        raise ValueError("Expected an exact \\Device\\HarddiskVolumeN\\directory prefix")
    # Apply the same component restrictions used for actual restoration.
    tail = prefix.split("\\", 3)[-1].rstrip("\\")
    try:
        ManifestEntry(tail)
    except (RecoveryValidationError, TypeError):
        raise ValueError("Unsafe NT directory prefix") from None
    return prefix


def _relative_path(raw_path: Any, prefix: str) -> str | None:
    if not isinstance(raw_path, str) or len(raw_path) > 30_000:
        return None
    path = raw_path.replace("/", "\\")
    if not path.casefold().startswith(prefix.casefold()):
        return None
    tail = path[len(prefix):]
    try:
        return ManifestEntry(tail).relative_path
    except (RecoveryValidationError, TypeError):
        return None


def propose_recovery_candidates(
    db: sqlite3.Connection, *, pid: int, process_create_time: int,
    approved_path_prefix: str, max_files: int = 500,
    scan_limit: int = 1_000_000,
) -> dict[str, Any]:
    """Return an explicit operator-review proposal; perform no Windows I/O."""
    if not isinstance(db, sqlite3.Connection):
        raise TypeError("A local outbox database is required")
    if type(pid) is not int or not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("PID must be a positive Windows PID")
    if type(process_create_time) is not int or not 0 < process_create_time < 1 << 63:
        raise ValueError("Process creation time must be an exact kernel FILETIME")
    if type(max_files) is not int or not 1 <= max_files <= 5000:
        raise ValueError("max_files must be 1..5000")
    if type(scan_limit) is not int or not 1 <= scan_limit <= 1_000_000:
        raise ValueError("scan_limit must be 1..1000000")
    prefix = approved_nt_directory(approved_path_prefix)
    states: dict[int, int] = {}
    candidates: OrderedDict[str, dict[str, Any]] = OrderedDict()
    ignored_uncorrelated = 0
    rename_attempts = 0
    inspected = 0
    first_filetime: int | None = None
    rows = db.execute(
        "SELECT payload FROM events WHERE kind='kernel_event' ORDER BY sequence LIMIT ?",
        (scan_limit + 1,))
    for (raw,) in rows:
        inspected += 1
        if inspected > scan_limit:
            raise ValueError("Scan limit reached; refusing an incomplete proposal")
        try:
            event = json.loads(raw)
        except (ValueError, TypeError):
            raise ValueError("Malformed stored kernel event") from None
        if not isinstance(event, dict):
            raise ValueError("Stored kernel event must be an object")
        kind = event.get("event_type")
        event_pid = event.get("pid")
        fields = event.get("fields")
        if type(event_pid) is not int or not isinstance(fields, dict):
            continue
        if kind == 1:
            stamp = fields.get("process_create_time")
            if type(stamp) is int and 0 < stamp < 1 << 63:
                states[event_pid] = stamp
            else:
                states.pop(event_pid, None)
            continue
        if kind in (2, 3):
            stamp = fields.get("process_create_time")
            if states.get(event_pid) == stamp:
                states.pop(event_pid, None)
            continue
        if kind not in (4, 5) or event_pid != pid:
            continue
        if (states.get(pid) != process_create_time or
                event.get("correlated_process_create_time") != process_create_time):
            ignored_uncorrelated += 1
            continue
        relative = _relative_path(fields.get("path"), prefix)
        if relative is None:
            continue
        if kind == 5:
            rename_attempts += 1
            continue
        flags = fields.get("flags")
        stamp = event.get("filetime")
        if (type(flags) is not int or not 0 <= flags <= 0xFFFFFFFF or
                type(stamp) is not int or stamp <= 0):
            continue
        if relative.casefold() not in candidates:
            if len(candidates) >= max_files:
                raise ValueError("Candidate capacity reached; explicit review is required")
            candidates[relative.casefold()] = {
                "relative_path": relative, "write_attempts": 0,
                "high_entropy_observations": 0, "first_sequence": event.get("sequence"),
                "last_sequence": event.get("sequence"),
            }
        item = candidates[relative.casefold()]
        item["write_attempts"] += 1
        item["high_entropy_observations"] += int(bool(flags & FILE_FLAG_HIGH_ENTROPY))
        item["last_sequence"] = event.get("sequence")
        first_filetime = stamp if first_filetime is None else min(first_filetime, stamp)

    return {
        "schema_version": 1, "proposal_type": "preop_write_evidence_only",
        "execution_mode": "read_only", "pid": pid,
        "process_create_time": process_create_time,
        "approved_nt_path_prefix": prefix,
        "suggested_incident_at": filetime_to_iso(first_filetime) if first_filetime else None,
        "manifest": [item["relative_path"] for item in candidates.values()],
        "evidence": list(candidates.values()),
        "rename_attempts_without_target_path": rename_attempts,
        "uncorrelated_attempts_excluded": ignored_uncorrelated,
        "stored_kernel_events_scanned": inspected,
        "complete_event_coverage": False,
        "file_damage_confirmed": False,
        "operator_review_required": True,
        "auto_restore_authorized": False,
        "next_step": "review_candidates_and_snapshot_before_explicit_recovery_plan",
    }
