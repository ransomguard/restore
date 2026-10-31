"""Real VSS creation, allowed only through a durable hourly scheduling gate.

Importing or constructing this module creates no snapshot.  A scheduled caller
must explicitly invoke ``HourlySnapshotCoordinator.run``.  One attempt per
volume consumes 3600 seconds even when it fails.  An interrupted/unknown attempt
blocks later attempts until an operator explicitly reconciles its outcome.

Use one protected, local state database for every entry point on a machine.
Deleting/replacing that database defeats the remembered scheduling boundary.
This module never prunes snapshots and never responds to detection/JEV events.
"""

from __future__ import annotations

import ctypes
import json
import math
import os
import re
import sqlite3
import subprocess
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .recovery import (
    Snapshot, RecoveryValidationError, _powershell_executable, _snapshot_id,
    _volume_id, enumerate_snapshots, volume_id_for_root,
)


INTERVAL_SECONDS = 3600


class SnapshotError(RuntimeError):
    """Base failure for scheduled snapshot operations."""


class SnapshotPolicyError(SnapshotError, ValueError):
    """A request does not meet the hourly-only policy or valid input contract."""


class SnapshotCreationFailed(SnapshotError):
    """A known creation failure; it still consumes the hourly attempt."""

    def __init__(self, reason: str, *, return_value: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.return_value = return_value


class SnapshotOutcomeUnknown(SnapshotError):
    """Creation may have happened.  Never retry without reconciliation."""

    def __init__(self, reason: str, *, snapshot_id: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.snapshot_id = snapshot_id


class SnapshotStateError(SnapshotError):
    """Durable scheduling state could not be read or committed safely."""


def normalize_volume_root(value: str) -> str:
    """Accept a legacy drive letter or a drive root, never a relative folder."""
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z]:(?:[\\/])?", value) is None:
        raise SnapshotPolicyError("volume_root must be a local drive root, such as C:\\")
    return value[0].upper() + ":\\"


def default_state_db() -> Path:
    """Stable machine-wide location shared by the compatibility entry points."""
    if sys.platform != "win32":
        raise SnapshotPolicyError("Set an explicit state_db for portable/offline use")
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RansomGuard" / "snapshots.sqlite3"


def require_admin() -> None:
    if sys.platform != "win32":
        raise SnapshotCreationFailed("windows_required")
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        function = shell32.IsUserAnAdmin
        function.argtypes = []
        function.restype = ctypes.c_int
        elevated = bool(function())
    except (OSError, AttributeError):
        raise SnapshotCreationFailed("administrator_check_failed") from None
    if not elevated:
        raise SnapshotCreationFailed("administrator_required")


def _timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SnapshotPolicyError("timeout_seconds must be a finite number from 1 to 300")
    try:
        valid = math.isfinite(value) and 1 <= value <= 300
    except (OverflowError, ValueError):
        valid = False
    if not valid:
        raise SnapshotPolicyError("timeout_seconds must be a finite number from 1 to 300")
    return float(value)


_CREATE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$inputData = [Console]::In.ReadToEnd() | ConvertFrom-Json
if ($inputData.schema_version -ne 1) { throw 'Unsupported input schema' }
$volume = [string]$inputData.volume_id
$result = Invoke-CimMethod -Namespace root/cimv2 -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{
    Volume = $volume
    Context = 'ClientAccessible'
} -ErrorAction Stop
$snapshot = $null
$metadataError = $false
if ([uint32]$result.ReturnValue -eq 0) {
    try {
        $matches = @(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_ShadowCopy -ErrorAction Stop |
            Where-Object { $_.ID -eq [string]$result.ShadowID })
        if ($matches.Count -ne 1 -or $null -eq $matches[0].InstallDate) { throw 'Metadata unavailable' }
        $item = $matches[0]
        $snapshot = [pscustomobject]@{
            snapshot_id = [string]$item.ID
            volume_id = [string]$item.VolumeName
            device_path = [string]$item.DeviceObject
            created_at = ([datetime]$item.InstallDate).ToUniversalTime().ToString('o')
        }
    } catch { $metadataError = $true }
}
[pscustomobject]@{
    schema_version = 1
    return_value = [uint32]$result.ReturnValue
    shadow_id = [string]$result.ShadowID
    metadata_error = $metadataError
    snapshot = $snapshot
} | ConvertTo-Json -Depth 5 -Compress
"""


def _create_vss_snapshot(volume_id: str, *, timeout_seconds: float = 180.0) -> Snapshot:
    """Private provider: call only after a durable coordinator reservation."""
    volume = _volume_id(volume_id)
    timeout = _timeout(timeout_seconds)
    require_admin()
    try:
        executable = _powershell_executable()
    except (OSError, RuntimeError):
        raise SnapshotCreationFailed("trusted_powershell_unavailable") from None
    try:
        result = subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _CREATE_SCRIPT],
            input=json.dumps({"schema_version": 1, "volume_id": volume}),
            capture_output=True, text=True, encoding="utf-8", errors="strict",
            timeout=timeout, check=False, shell=False,
        )
    except subprocess.TimeoutExpired:
        # Killing PowerShell does not prove that the provider stopped its work.
        raise SnapshotOutcomeUnknown("creation_timeout") from None
    except OSError:
        raise SnapshotCreationFailed("powershell_could_not_start") from None
    except (subprocess.SubprocessError, UnicodeError):
        raise SnapshotOutcomeUnknown("creation_transport_unknown") from None
    if result.returncode != 0:
        raise SnapshotOutcomeUnknown("powershell_failed_after_launch")
    shadow_id: str | None = None
    try:
        payload = json.loads(result.stdout.lstrip("\ufeff"))
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise ValueError
        code = payload["return_value"]
        if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 0xFFFFFFFF:
            raise ValueError
        if code != 0:
            raise SnapshotCreationFailed("vss_create_returned_failure", return_value=code)
        shadow_id = _snapshot_id(payload["shadow_id"])
        if payload.get("metadata_error") is not False or not isinstance(payload.get("snapshot"), dict):
            raise ValueError
        snapshot = Snapshot(**payload["snapshot"])
        if snapshot.snapshot_id != shadow_id or snapshot.volume_id != volume:
            raise ValueError
    except SnapshotCreationFailed:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RecoveryValidationError):
        raise SnapshotOutcomeUnknown("creation_response_unverified", snapshot_id=shadow_id) from None
    return snapshot


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class HourlySnapshotCoordinator:
    """Persistent per-volume at-most-once-per-3600s attempt coordinator.

    ``create_fn``, ``volume_resolver``, ``inventory_fn`` and ``clock`` are explicit
    offline-test seams; production callers should use their defaults.  The
    scheduler owns the first next-hour invocation and must not backfill misses.
    Unknown and crashed attempts require ``reconcile`` even after an hour.
    """

    def __init__(self, state_db: str | os.PathLike[str], *, timeout_seconds: float = 180.0,
                 create_fn: Callable[..., Snapshot] | None = None,
                 volume_resolver: Callable[[str], str] | None = None,
                 inventory_fn: Callable[[str], list[Snapshot]] | None = None,
                 clock: Callable[[], datetime] | None = None):
        raw = os.fspath(state_db)
        if not isinstance(raw, str) or not raw or raw == ":memory:" or "\x00" in raw:
            raise SnapshotPolicyError("A durable filesystem state_db path is required")
        self.state_db = Path(raw).absolute()
        self.timeout_seconds = _timeout(timeout_seconds)
        self._create = create_fn or _create_vss_snapshot
        self._resolve = volume_resolver or volume_id_for_root
        self._inventory = inventory_fn or enumerate_snapshots
        self._clock = clock or _utc_now

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise SnapshotPolicyError("Scheduling clock must return an aware UTC-compatible datetime")
        return now.astimezone(timezone.utc)

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            self.state_db.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(str(self.state_db), timeout=15, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA busy_timeout=15000")
            connection.execute("""CREATE TABLE IF NOT EXISTS snapshot_attempts (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_id TEXT NOT NULL UNIQUE,
                volume_id TEXT NOT NULL,
                attempted_at TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT NOT NULL
            )""")
            connection.execute("CREATE INDEX IF NOT EXISTS snapshot_attempts_volume ON snapshot_attempts(volume_id, sequence)")
            yield connection
        except (sqlite3.Error, OSError):
            raise SnapshotStateError("Durable snapshot state is unavailable; no unrecorded retry is allowed") from None
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _last(connection: sqlite3.Connection, volume: str) -> sqlite3.Row | None:
        return connection.execute("SELECT * FROM snapshot_attempts WHERE volume_id=? ORDER BY sequence DESC LIMIT 1", (volume,)).fetchone()

    def _claim(self, root: str, volume: str) -> dict[str, Any]:
        with self._database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = self._now()
            previous = self._last(connection, volume)
            if previous is not None:
                try:
                    attempted_at = datetime.fromisoformat(previous["attempted_at"])
                    if attempted_at.tzinfo is None:
                        raise ValueError
                    next_at = attempted_at + timedelta(seconds=INTERVAL_SECONDS)
                    unresolved = previous["status"] in ("in_progress", "unknown")
                    if previous["status"] not in ("in_progress", "unknown", "created", "failed", "reconciled_absent", "reconciled_created"):
                        raise ValueError
                except (ValueError, TypeError, KeyError):
                    raise SnapshotStateError("Stored snapshot state is invalid; refusing creation") from None
                if unresolved or now < next_at:
                    reason = "unresolved_previous_attempt" if unresolved else "clock_moved_backwards" if now < attempted_at else "hourly_cooldown"
                    result = {"status": "skipped", "created": False, "attempted": False,
                              "reason": reason, "volume_id": volume, "volume_root": root,
                              "attempted_at": previous["attempted_at"], "next_eligible_at": next_at.isoformat(),
                              "previous_status": previous["status"], "attempt_id": previous["attempt_id"],
                              "snapshot": None, "requires_reconciliation": unresolved}
                    connection.execute("COMMIT")
                    return result
            result = {"status": "in_progress", "created": False, "attempted": True,
                      "reason": "reserved_before_creation", "volume_id": volume, "volume_root": root,
                      "attempt_id": str(uuid.uuid4()), "attempted_at": now.isoformat(),
                      "next_eligible_at": (now + timedelta(seconds=INTERVAL_SECONDS)).isoformat(),
                      "snapshot": None, "requires_reconciliation": True}
            connection.execute("INSERT INTO snapshot_attempts(attempt_id,volume_id,attempted_at,status,result_json) VALUES(?,?,?,?,?)",
                               (result["attempt_id"], volume, result["attempted_at"], "in_progress", json.dumps(result)))
            connection.execute("COMMIT")
            return result

    def _finish(self, result: dict[str, Any]) -> None:
        with self._database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute("UPDATE snapshot_attempts SET status=?,result_json=? WHERE attempt_id=? AND status='in_progress'",
                                        (result["status"], json.dumps(result), result["attempt_id"]))
            if cursor.rowcount != 1:
                raise SnapshotStateError("Attempt changed before completion; inspect the persisted outcome")
            connection.execute("COMMIT")

    def run(self, volume_root: str = "C:\\", *, trigger: str = "hourly_schedule") -> dict[str, Any]:
        if trigger != "hourly_schedule":
            raise SnapshotPolicyError("Only the hourly_schedule trigger may create a snapshot")
        root = normalize_volume_root(volume_root)
        volume = _volume_id(self._resolve(root))
        result = self._claim(root, volume)
        if not result["attempted"]:
            return result
        try:
            snapshot = self._create(volume, timeout_seconds=self.timeout_seconds)
            if not isinstance(snapshot, Snapshot) or snapshot.volume_id != volume:
                raise SnapshotOutcomeUnknown("provider_returned_unverified_snapshot")
            attempted_at = datetime.fromisoformat(result["attempted_at"])
            if snapshot.created_at < attempted_at - timedelta(seconds=5) or snapshot.created_at > self._now() + timedelta(seconds=5):
                raise SnapshotOutcomeUnknown("snapshot_timestamp_unverified", snapshot_id=snapshot.snapshot_id)
            result.update(status="created", created=True, reason="vss_create_verified",
                          snapshot=snapshot.to_dict(), requires_reconciliation=False)
        except SnapshotCreationFailed as error:
            result.update(status="failed", reason=error.reason, return_value=error.return_value,
                          requires_reconciliation=False)
        except SnapshotOutcomeUnknown as error:
            result.update(status="unknown", reason=error.reason, returned_snapshot_id=error.snapshot_id,
                          requires_reconciliation=True)
        except Exception:
            # The provider may already have entered Create.  A programming or
            # transport exception must never authorize another blind attempt.
            result.update(status="unknown", reason="unexpected_provider_failure", requires_reconciliation=True)
        result["completed_at"] = self._now().isoformat()
        self._finish(result)
        return result

    def reconcile(self, volume_root: str = "C:\\", *, operation_finished: bool = False,
                  snapshot_id: str | None = None, confirm_no_snapshot: bool = False) -> dict[str, Any]:
        """Record an operator-verified outcome without creating/deleting anything.

        The operator must first verify that the old VSS operation is no longer
        running.  An exact existing ID is checked, or explicit absence is
        recorded.  Merely waiting an hour is never sufficient reconciliation.
        """
        if operation_finished is not True or type(confirm_no_snapshot) is not bool:
            raise SnapshotPolicyError("Reconciliation requires confirmation that the old operation finished")
        if (snapshot_id is None) == (confirm_no_snapshot is False):
            raise SnapshotPolicyError("Supply exactly one existing snapshot_id or confirm_no_snapshot=True")
        root = normalize_volume_root(volume_root)
        volume = _volume_id(self._resolve(root))
        selected = None
        if snapshot_id is not None:
            ident = _snapshot_id(snapshot_id)
            matches = [s for s in self._inventory(volume) if isinstance(s, Snapshot) and s.snapshot_id == ident and s.volume_id == volume]
            if len(matches) != 1:
                raise SnapshotPolicyError("Reconciliation requires one exact existing snapshot on the volume")
            selected = matches[0]
        with self._database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._last(connection, volume)
            if row is None or row["status"] not in ("unknown", "in_progress"):
                raise SnapshotPolicyError("There is no unresolved attempt to reconcile")
            try:
                result = json.loads(row["result_json"])
                attempted_at = datetime.fromisoformat(row["attempted_at"])
                if not isinstance(result, dict) or attempted_at.tzinfo is None:
                    raise ValueError
            except (ValueError, TypeError):
                raise SnapshotStateError("Stored reconciliation state is invalid") from None
            if selected is not None and result.get("returned_snapshot_id") not in (None, selected.snapshot_id):
                raise SnapshotPolicyError("Reconciliation must use the snapshot ID returned by the original operation")
            if selected is not None and (selected.created_at < attempted_at - timedelta(seconds=5) or selected.created_at > self._now() + timedelta(seconds=5)):
                raise SnapshotPolicyError("Selected snapshot does not match the unresolved attempt time range")
            result.update(status="reconciled_created" if selected else "reconciled_absent",
                          created=selected is not None, reason="operator_reconciled_existing_snapshot" if selected else "operator_confirmed_no_snapshot",
                          snapshot=selected.to_dict() if selected else None, requires_reconciliation=False,
                          reconciled_at=self._now().isoformat())
            connection.execute("UPDATE snapshot_attempts SET status=?,result_json=? WHERE attempt_id=?",
                               (result["status"], json.dumps(result), row["attempt_id"]))
            connection.execute("COMMIT")
            return result
