"""Explicit, manifest-based recovery from a pre-incident VSS snapshot.

Planning is portable and never writes.  Live execution requires Windows and two
explicit acknowledgements: live writes are allowed and the caller has contained
the threat.  This module does not terminate processes, infer that containment is
complete, create/delete snapshots, clear quarantine, or run a demonstration.

Recovery copies regular-file contents individually into same-directory staging
files, verifies their SHA-256 hashes, and atomically replaces each destination.
It is not an atomic transaction across a whole manifest.  ACL/ADS/EFS restoration
and recovery of reparse points are outside this module's contract.  The caller
must control concurrent writers and untrusted directory changes during recovery;
path checks are not a substitute for that enforcement.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable


class RecoveryError(RuntimeError):
    """Base class for recovery failures."""


class RecoveryValidationError(RecoveryError, ValueError):
    """Unsafe or incomplete recovery input."""


class SnapshotDiscoveryError(RecoveryError):
    """Snapshot metadata could not be obtained or validated."""


_VOLUME_RE = re.compile(r"^\\\\\?\\Volume\{([0-9a-fA-F-]{36})\}\\$", re.IGNORECASE)
_DEVICE_RE = re.compile(r"^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[0-9]+\\?$", re.IGNORECASE)
_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
             *(f"COM{i}" for i in "123456789¹²³"), *(f"LPT{i}" for i in "123456789¹²³")}
_REPARSE_POINT = 0x400
_ENCRYPTED = 0x4000


def _aware_utc(value: datetime | str, field: str) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise RecoveryValidationError(f"{field} must be an ISO-8601 timestamp") from None
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise RecoveryValidationError(f"{field} must include a timezone")
    return value.astimezone(timezone.utc)


def _volume_id(value: str) -> str:
    if not isinstance(value, str) or (match := _VOLUME_RE.fullmatch(value)) is None:
        raise RecoveryValidationError("volume_id must be a canonical Windows volume GUID path")
    try:
        ident = str(uuid.UUID(match.group(1)))
    except ValueError:
        raise RecoveryValidationError("volume_id contains an invalid GUID") from None
    return "\\\\?\\Volume{" + ident + "}\\"


def _snapshot_id(value: str) -> str:
    try:
        if not isinstance(value, str):
            raise ValueError
        return "{" + str(uuid.UUID(value.strip("{}"))) + "}"
    except ValueError:
        raise RecoveryValidationError("snapshot_id must be a GUID") from None


def _relative_parts(value: str, field: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > 30_000:
        raise RecoveryValidationError(f"{field} must be a nonempty relative path")
    path = PureWindowsPath(value)
    if path.drive or path.root or value.startswith(("/", "\\")):
        raise RecoveryValidationError(f"{field} must not be absolute or drive-relative")
    parts = value.replace("/", "\\").split("\\")
    for part in parts:
        if not part or part in (".", "..") or part.endswith((" ", ".")):
            raise RecoveryValidationError(f"{field} contains an unsafe path component")
        if any(ord(c) < 32 or c in '<>:"|?*' for c in part):
            raise RecoveryValidationError(f"{field} contains an unsupported path component")
        if part.split(".", 1)[0].upper() in _RESERVED:
            raise RecoveryValidationError(f"{field} contains a reserved Windows name")
    return tuple(parts)


@dataclass(frozen=True)
class Snapshot:
    snapshot_id: str
    volume_id: str
    created_at: datetime
    device_path: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _snapshot_id(self.snapshot_id))
        object.__setattr__(self, "volume_id", _volume_id(self.volume_id))
        object.__setattr__(self, "created_at", _aware_utc(self.created_at, "snapshot created_at"))
        if not isinstance(self.device_path, str) or _DEVICE_RE.fullmatch(self.device_path) is None:
            raise RecoveryValidationError("Snapshot device_path must identify a VSS GLOBALROOT device")
        object.__setattr__(self, "device_path", self.device_path.rstrip("\\"))

    def to_dict(self) -> dict[str, Any]:
        return {"snapshot_id": self.snapshot_id, "volume_id": self.volume_id,
                "created_at": self.created_at.isoformat(), "device_path": self.device_path}


@dataclass(frozen=True)
class ManifestEntry:
    relative_path: str
    expected_sha256: str | None = None
    expected_size: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "relative_path", "\\".join(_relative_parts(self.relative_path, "manifest path")))
        if self.expected_sha256 is not None:
            if not isinstance(self.expected_sha256, str) or re.fullmatch(r"[a-fA-F0-9]{64}", self.expected_sha256) is None:
                raise RecoveryValidationError("expected_sha256 must contain 64 hexadecimal characters")
            object.__setattr__(self, "expected_sha256", self.expected_sha256.lower())
        if self.expected_size is not None and (
            isinstance(self.expected_size, bool) or not isinstance(self.expected_size, int) or self.expected_size < 0
        ):
            raise RecoveryValidationError("expected_size must be a nonnegative integer")


@dataclass(frozen=True)
class RecoveryPlan:
    job_id: str
    snapshot: Snapshot
    incident_at: datetime
    volume_root: str
    protected_root: str
    protected_relative: tuple[str, ...]
    entries: tuple[ManifestEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id, "snapshot": self.snapshot.to_dict(),
            "incident_at": self.incident_at.isoformat(), "volume_root": self.volume_root,
            "protected_root": self.protected_root,
            "files": [{"relative_path": e.relative_path, "expected_sha256": e.expected_sha256,
                       "expected_size": e.expected_size} for e in self.entries],
        }


def select_snapshot(
    snapshots: Iterable[Snapshot], *, volume_id: str, incident_at: datetime | str,
    snapshot_id: str | None = None,
) -> Snapshot:
    """Select an exact volume's newest snapshot strictly before the incident.

    With snapshot_id specified, that exact snapshot must pass the same checks;
    there is no fallback to a different snapshot on mismatch.
    """
    volume = _volume_id(volume_id)
    cutoff = _aware_utc(incident_at, "incident_at")
    requested = _snapshot_id(snapshot_id) if snapshot_id is not None else None
    candidates = []
    seen: set[str] = set()
    for candidate in snapshots:
        if not isinstance(candidate, Snapshot):
            raise RecoveryValidationError("Snapshot inventory contains an invalid entry")
        if candidate.snapshot_id in seen:
            raise RecoveryValidationError("Snapshot inventory contains duplicate IDs")
        seen.add(candidate.snapshot_id)
        if candidate.volume_id == volume and candidate.created_at < cutoff:
            if requested is None or candidate.snapshot_id == requested:
                candidates.append(candidate)
    if not candidates:
        raise RecoveryValidationError("No matching pre-incident snapshot exists for the requested volume and ID")
    return max(candidates, key=lambda item: (item.created_at, item.snapshot_id))


def build_plan(
    snapshot: Snapshot, *, volume_root: str, protected_root: str,
    manifest: Iterable[str | ManifestEntry | dict[str, Any]], incident_at: datetime | str,
) -> RecoveryPlan:
    """Validate logical Windows paths without accessing the local filesystem."""
    if not isinstance(snapshot, Snapshot):
        raise RecoveryValidationError("An explicitly selected Snapshot is required")
    cutoff = _aware_utc(incident_at, "incident_at")
    if snapshot.created_at >= cutoff:
        raise RecoveryValidationError("Recovery snapshot must precede the incident")
    if not isinstance(volume_root, str) or re.fullmatch(r"[A-Za-z]:[\\/]", volume_root) is None:
        raise RecoveryValidationError("volume_root must be a local drive root, such as C:\\")
    base = PureWindowsPath(volume_root)
    if not isinstance(protected_root, str):
        raise RecoveryValidationError("protected_root must be an absolute Windows directory")
    protected = PureWindowsPath(protected_root)
    if not protected.is_absolute() or protected.drive.casefold() != base.drive.casefold():
        raise RecoveryValidationError("protected_root must belong to volume_root")
    # Validate original components too: PureWindowsPath normalizes lone dots.
    remainder = protected_root.replace("/", "\\")[3:].rstrip("\\")
    protected_parts = _relative_parts(remainder, "protected_root")
    if isinstance(manifest, (str, bytes)):
        raise RecoveryValidationError("manifest must contain explicit file entries")
    entries: list[ManifestEntry] = []
    seen: set[str] = set()
    for item in manifest:
        if isinstance(item, ManifestEntry):
            entry = item
        elif isinstance(item, str):
            entry = ManifestEntry(item)
        elif isinstance(item, dict):
            try:
                entry = ManifestEntry(**item)
            except TypeError:
                raise RecoveryValidationError("Manifest entry has unknown or missing fields") from None
        else:
            raise RecoveryValidationError("Manifest entries must be paths or ManifestEntry records")
        key = entry.relative_path.casefold()
        if key in seen:
            raise RecoveryValidationError("Manifest contains duplicate Windows paths")
        seen.add(key)
        entries.append(entry)
    if not entries:
        raise RecoveryValidationError("Empty manifests must be classified as recovery-not-needed by the coordinator")
    return RecoveryPlan(str(uuid.uuid4()), snapshot, cutoff, str(base), str(protected), protected_parts, tuple(entries))


_CIM_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$inputData = [Console]::In.ReadToEnd() | ConvertFrom-Json
if ($inputData.schema_version -ne 1) { throw 'Unsupported input schema' }
$volume = [string]$inputData.volume_id
$snapshots = @(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_ShadowCopy -ErrorAction Stop |
    Where-Object { $_.VolumeName -eq $volume } | ForEach-Object {
        [pscustomobject]@{
            snapshot_id = [string]$_.ID
            volume_id = [string]$_.VolumeName
            device_path = [string]$_.DeviceObject
            created_at = ([datetime]$_.InstallDate).ToUniversalTime().ToString('o')
        }
    })
[pscustomobject]@{ schema_version = 1; snapshots = $snapshots } | ConvertTo-Json -Depth 4 -Compress
"""


def _require_windows() -> None:
    if sys.platform != "win32":
        raise RecoveryValidationError("This operation requires Windows")


def _powershell_executable() -> str:
    _require_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_directory = kernel32.GetSystemDirectoryW
    get_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    get_directory.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_directory(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise SnapshotDiscoveryError("Cannot locate the trusted Windows system directory")
    return str(Path(buffer.value) / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def enumerate_snapshots(volume_id: str, *, timeout_seconds: float = 30.0) -> list[Snapshot]:
    """Read VSS metadata with fixed CIM code; never create or delete snapshots."""
    volume = _volume_id(volume_id)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 300:
        raise RecoveryValidationError("Snapshot discovery timeout must be between 0 and 300 seconds")
    executable = _powershell_executable()
    try:
        result = subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _CIM_SCRIPT],
            input=json.dumps({"schema_version": 1, "volume_id": volume}),
            capture_output=True, text=True, encoding="utf-8", errors="strict",
            timeout=timeout_seconds, check=False, shell=False,
        )
        if result.returncode != 0:
            raise SnapshotDiscoveryError("CIM snapshot discovery failed")
        payload = json.loads(result.stdout.lstrip("\ufeff"))
        if payload.get("schema_version") != 1 or not isinstance(payload.get("snapshots"), list):
            raise SnapshotDiscoveryError("CIM returned an unsupported snapshot schema")
        inventory = [Snapshot(**item) for item in payload["snapshots"]]
        if any(item.volume_id != volume for item in inventory):
            raise SnapshotDiscoveryError("CIM returned metadata for a different volume")
        if len({item.snapshot_id for item in inventory}) != len(inventory):
            raise SnapshotDiscoveryError("CIM returned duplicate snapshot IDs")
        return inventory
    except SnapshotDiscoveryError:
        raise
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError, TypeError, AttributeError):
        raise SnapshotDiscoveryError("Snapshot discovery failed or returned invalid metadata") from None


def _actual_volume_id(volume_root: str) -> str:
    _require_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel32.GetVolumeNameForVolumeMountPointW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    buffer = ctypes.create_unicode_buffer(1024)
    if not function(volume_root, buffer, len(buffer)):
        raise RecoveryValidationError("Cannot verify the destination volume GUID")
    return _volume_id(buffer.value)


def volume_id_for_root(volume_root: str) -> str:
    """Read the current GUID for a local drive root; never changes the volume."""
    if not isinstance(volume_root, str) or re.fullmatch(r"[A-Za-z]:[\\/]", volume_root) is None:
        raise RecoveryValidationError("volume_root must be a local drive root")
    return _actual_volume_id(str(PureWindowsPath(volume_root)))


def _assert_node(path: Path, *, directory: bool) -> os.stat_result:
    info = path.lstat()
    attrs = getattr(info, "st_file_attributes", 0)
    if stat.S_ISLNK(info.st_mode) or attrs & _REPARSE_POINT:
        raise RecoveryValidationError("Reparse points and symbolic links are not supported")
    if attrs & _ENCRYPTED:
        raise RecoveryValidationError("EFS files and directories require a separate recovery implementation")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise RecoveryValidationError("A recovery path component is not a directory")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise RecoveryValidationError("Recovery supports regular files only")
    return info


def _check_chain(base: Path, parts: tuple[str, ...], *, final_directory: bool = False) -> Path:
    _assert_node(base, directory=True)
    current = base
    for index, part in enumerate(parts):
        current = current / part
        _assert_node(current, directory=final_directory or index < len(parts) - 1)
    return current


def _ensure_directories(base: Path, parts: tuple[str, ...]) -> Path:
    _assert_node(base, directory=True)
    current = base
    for part in parts:
        current = current / part
        try:
            current.mkdir()
        except FileExistsError:
            pass
        _assert_node(current, directory=True)
    return current


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class LocalSnapshotBackend:
    """Offline-test adapter, explicitly selected by a caller.

    ``snapshot_root`` represents the whole snapshotted volume; ``volume_root``
    represents the live test volume.  Both must be existing real directories.
    No Windows/VSS/PowerShell operations are used.  Execution still requires
    ``allow_local_test=True`` and ``containment_confirmed=True``.
    """

    snapshot_root: Path
    volume_root: Path


class RecoveryEngine:
    def __init__(self, *, backend: LocalSnapshotBackend | None = None, max_file_bytes: int = 512 * 1024 * 1024) -> None:
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
            raise RecoveryValidationError("max_file_bytes must be a positive integer")
        self.backend = backend
        self.max_file_bytes = max_file_bytes

    @staticmethod
    def plan(snapshot: Snapshot, *, volume_root: str, protected_root: str,
             manifest: Iterable[str | ManifestEntry | dict[str, Any]], incident_at: datetime | str) -> RecoveryPlan:
        return build_plan(snapshot, volume_root=volume_root, protected_root=protected_root,
                          manifest=manifest, incident_at=incident_at)

    def execute(self, plan: RecoveryPlan, *, allow_live: bool = False,
                containment_confirmed: bool = False, allow_local_test: bool = False) -> dict[str, Any]:
        """Execute an explicitly authorized plan; never release quarantine.

        A ``verified`` result means every listed file matches the selected
        snapshot's bytes.  It does not establish that malware is absent, that
        unlisted files are healthy, or that the snapshot was application-consistent.
        """
        if not isinstance(plan, RecoveryPlan):
            raise RecoveryValidationError("A validated RecoveryPlan is required")
        # Revalidate to reject manually constructed or altered plan records.
        validated = build_plan(plan.snapshot, volume_root=plan.volume_root, protected_root=plan.protected_root,
                               manifest=plan.entries, incident_at=plan.incident_at)
        if validated.protected_relative != plan.protected_relative:
            raise RecoveryValidationError("Recovery plan path metadata is inconsistent")
        if containment_confirmed is not True:
            raise RecoveryValidationError("Caller must explicitly confirm containment before any recovery writes")
        if self.backend is None:
            if allow_live is not True:
                raise RecoveryValidationError("Live recovery writes require allow_live=True")
            _require_windows()
            if _actual_volume_id(plan.volume_root) != plan.snapshot.volume_id:
                raise RecoveryValidationError("Destination volume does not match the selected snapshot")
            # Re-enumerate by exact ID immediately before writing.  A stale or
            # deleted snapshot must not silently select a replacement.
            current = select_snapshot(enumerate_snapshots(plan.snapshot.volume_id),
                                      volume_id=plan.snapshot.volume_id, incident_at=plan.incident_at,
                                      snapshot_id=plan.snapshot.snapshot_id)
            if current != plan.snapshot:
                raise RecoveryValidationError("Selected snapshot metadata changed; create a new plan")
            source_base = Path(plan.snapshot.device_path + "\\")
            destination_base = Path(plan.volume_root)
        else:
            if allow_local_test is not True:
                raise RecoveryValidationError("Local test recovery requires allow_local_test=True")
            source_base = Path(self.backend.snapshot_root).absolute()
            destination_base = Path(self.backend.volume_root).absolute()
            # Roots must be disjoint, so a test cannot overwrite its own source.
            source_resolved = source_base.resolve()
            destination_resolved = destination_base.resolve()
            if source_resolved == destination_resolved or source_resolved in destination_resolved.parents or destination_resolved in source_resolved.parents:
                raise RecoveryValidationError("Snapshot and destination test roots must be disjoint")
        _assert_node(source_base, directory=True)
        _assert_node(destination_base, directory=True)
        results = [self._restore_file(plan, entry, source_base, destination_base) for entry in plan.entries]
        verified = sum(item["status"] == "verified" for item in results)
        status = "verified" if verified == len(results) else "partial" if verified else "failed"
        return {"job_id": plan.job_id, "snapshot_id": plan.snapshot.snapshot_id,
                "status": status, "verified": status == "verified", "files_total": len(results),
                "files_verified": verified, "files_failed": len(results) - verified, "files": results}

    def _restore_file(self, plan: RecoveryPlan, entry: ManifestEntry, source_base: Path,
                      destination_base: Path) -> dict[str, Any]:
        stage: Path | None = None
        replaced = False
        result: dict[str, Any] = {"relative_path": entry.relative_path, "status": "failed", "replaced": False}
        try:
            parts = plan.protected_relative + _relative_parts(entry.relative_path, "manifest path")
            source = _check_chain(source_base, parts)
            info = _assert_node(source, directory=False)
            if info.st_size > self.max_file_bytes:
                raise RecoveryValidationError("File exceeds the configured recovery size limit")
            if entry.expected_size is not None and info.st_size != entry.expected_size:
                raise RecoveryValidationError("Snapshot file size does not match the manifest")
            parent = _ensure_directories(destination_base, parts[:-1])
            destination = parent / parts[-1]
            if os.path.lexists(destination):
                _assert_node(destination, directory=False)
            fd, stage_name = tempfile.mkstemp(prefix=".ransomguard-", suffix=".tmp", dir=parent)
            stage = Path(stage_name)
            digest = hashlib.sha256()
            copied = 0
            with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
                for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
                    copied += len(chunk)
                    if copied > self.max_file_bytes:
                        raise RecoveryValidationError("File grew beyond the configured recovery size limit")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            source_hash = digest.hexdigest()
            if copied != info.st_size:
                raise RecoveryValidationError("Snapshot file changed during recovery")
            if entry.expected_sha256 is not None and source_hash != entry.expected_sha256:
                raise RecoveryValidationError("Snapshot file hash does not match the manifest")
            if _sha256(stage) != source_hash:
                raise RecoveryValidationError("Staging verification failed")
            # Recheck links immediately before replacement.  The documented
            # containment precondition remains necessary for directory races.
            _check_chain(destination_base, parts[:-1], final_directory=True)
            if os.path.lexists(destination):
                _assert_node(destination, directory=False)
            os.replace(stage, destination)
            stage = None
            replaced = True
            _check_chain(destination_base, parts)
            if _sha256(destination) != source_hash:
                raise RecoveryValidationError("Destination verification failed after replacement")
            result.update(status="verified", replaced=True, sha256=source_hash, bytes=copied)
        except (OSError, RecoveryError) as error:
            result.update(status="failed", replaced=replaced, error_type=type(error).__name__)
            if isinstance(error, OSError):
                result["error_code"] = getattr(error, "winerror", None) or error.errno
                result["message"] = "Filesystem operation failed; inspect the per-file result before retrying"
            else:
                result["message"] = str(error)
        finally:
            if stage is not None:
                try:
                    stage.unlink()
                except OSError:
                    result["staging_cleanup_failed"] = True
        return result
