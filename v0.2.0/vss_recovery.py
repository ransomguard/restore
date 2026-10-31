"""Legacy recovery methods backed by validated file recovery and hourly VSS.

Original names/positional arguments remain. No demo main, fabricated process-kill
message, shared mount, or snapshot-on-recovery. Writes require allow_live=True
and containment_confirmed=True. Incident recovery must supply its start time.
Without a manifest, folder recovery enumerates the selected snapshot's files;
this broad folder mode is for an explicitly requested manual lab restore.
"""
from __future__ import annotations

import json
import logging
import os
import stat
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Iterable

from create_snapshot import check_admin, create_vss_snapshot_result
from ransomguard.recovery import (
    ManifestEntry, RecoveryEngine, RecoveryError, RecoveryValidationError,
    Snapshot, _assert_node, _check_chain, _relative_parts, enumerate_snapshots,
    select_snapshot, volume_id_for_root,
)
from ransomguard.snapshots import normalize_volume_root

logger = logging.getLogger("VssRecoveryEngine")


class VssRecoveryEngine:
    def __init__(self, drive_letter: str = "C:", *, state_db: str | os.PathLike[str] | None = None,
                 incident_at: datetime | str | None = None,
                 recovery_engine: RecoveryEngine | None = None):
        self.volume_root = normalize_volume_root(drive_letter)
        self.drive_letter = self.volume_root[:2]
        self.state_db = state_db
        self.incident_at = incident_at
        self.last_snapshot_result: dict[str, Any] | None = None
        self.last_recovery_result: dict[str, Any] | None = None
        self._engine = recovery_engine or RecoveryEngine()
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="VssRecoveryWorker")

    def create_snapshot(self, *, trigger: str = "hourly_schedule", timeout_seconds: float = 180.0) -> str:
        """Keep the legacy string return, now containing an explicit JSON result."""
        result = create_vss_snapshot_result(self.volume_root, state_db=self.state_db,
                                            trigger=trigger, timeout_seconds=timeout_seconds)
        self.last_snapshot_result = result
        return json.dumps(result, ensure_ascii=False)

    def _select(self, incident_at: datetime | str | None, snapshot_id: str | None) -> tuple[Snapshot, datetime | str]:
        # Fallback preserves manual lab latest-existing behavior. Live adapters
        # must pass earliest incident time, rather than using this fallback.
        cutoff = incident_at if incident_at is not None else self.incident_at
        if cutoff is None:
            cutoff = datetime.now(timezone.utc)
        volume = volume_id_for_root(self.volume_root)
        snapshot = select_snapshot(enumerate_snapshots(volume), volume_id=volume,
                                   incident_at=cutoff, snapshot_id=snapshot_id)
        return snapshot, cutoff

    def get_latest_shadow_volume(self, *, incident_at: datetime | str | None = None,
                                 snapshot_id: str | None = None) -> str:
        snapshot, _ = self._select(incident_at, snapshot_id)
        return snapshot.device_path

    def _folder_manifest(self, snapshot: Snapshot, parts: tuple[str, ...]) -> list[str]:
        source_base = Path(snapshot.device_path + "\\")
        if self._engine.backend is not None:
            source_base = Path(self._engine.backend.snapshot_root).absolute()
        source = _check_chain(source_base, parts, final_directory=True)
        pending: list[tuple[Path, tuple[str, ...]]] = [(source, ())]
        files: list[str] = []
        while pending:
            directory, relative = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    is_directory = stat.S_ISDIR(path.lstat().st_mode)
                    _assert_node(path, directory=is_directory)
                    child = relative + (entry.name,)
                    if is_directory:
                        pending.append((path, child))
                    else:
                        files.append("\\".join(child))
                        if len(files) > 100_000:
                            raise RecoveryValidationError("Legacy folder restore exceeds the manifest limit")
        if not files:
            raise RecoveryValidationError("Snapshot folder contains no restorable regular files")
        return sorted(files, key=str.casefold)

    def recover(self, target_relative_path: str = "vss_test", mount_point: str = r"C:\vss_mount",
                destination_dir: str = r"C:\vss_test", *, incident_at: datetime | str | None = None,
                snapshot_id: str | None = None,
                manifest: Iterable[str | ManifestEntry | dict[str, Any]] | None = None,
                containment_confirmed: bool = False, allow_live: bool = False,
                allow_local_test: bool = False) -> None:
        """Legacy None-on-success; partial/failed writes raise RecoveryError.

        mount_point remains accepted, but is never used or deleted. Destination
        must be the selected subtree's original path. Partial results remain in
        last_recovery_result. No snapshot is created by this method.
        """
        if containment_confirmed is not True:
            raise RecoveryValidationError("Confirm containment before recovery writes")
        if self._engine.backend is None and allow_live is not True:
            raise RecoveryValidationError("Legacy live recovery requires allow_live=True")
        if self._engine.backend is not None and allow_local_test is not True:
            raise RecoveryValidationError("Offline legacy recovery requires allow_local_test=True")
        parts = _relative_parts(target_relative_path, "target_relative_path")
        expected_destination = PureWindowsPath(self.volume_root).joinpath(*parts)
        if not isinstance(destination_dir, str) or PureWindowsPath(destination_dir) != expected_destination:
            raise RecoveryValidationError("Destination must match the original snapshot subtree path")
        with self._lock:
            self.last_recovery_result = None
            snapshot, cutoff = self._select(incident_at, snapshot_id)
            entries = self._folder_manifest(snapshot, parts) if manifest is None else manifest
            plan = self._engine.plan(snapshot, volume_root=self.volume_root,
                                     protected_root=str(expected_destination), manifest=entries, incident_at=cutoff)
            result = self._engine.execute(plan, allow_live=allow_live,
                                          containment_confirmed=containment_confirmed,
                                          allow_local_test=allow_local_test)
            self.last_recovery_result = result
            if result.get("status") != "verified" or result.get("verified") is not True:
                raise RecoveryError("Recovery did not verify every listed file; inspect last_recovery_result")

    @staticmethod
    def _callback(callback: Callable[[bool, Exception | None], None] | None,
                  success: bool, error: Exception | None) -> None:
        if callback is not None:
            try:
                callback(success, error)
            except Exception:
                logger.error("Legacy recovery callback failed")

    def recover_async(self, target_relative_path: str = "vss_test", mount_point: str = r"C:\vss_mount",
                      destination_dir: str = r"C:\vss_test",
                      callback: Callable[[bool, Exception | None], None] | None = None,
                      **options: Any) -> threading.Thread:
        def worker() -> None:
            error = None
            try:
                self.recover(target_relative_path, mount_point, destination_dir, **options)
            except Exception as failure:
                error = failure
                logger.error("Asynchronous recovery failed (%s)", type(failure).__name__)
            self._callback(callback, error is None, error)
        thread = threading.Thread(target=worker, daemon=True, name="VssRecoveryDaemonWorker")
        thread.start()
        return thread

    def recover_executor(self, target_relative_path: str = "vss_test", mount_point: str = r"C:\vss_mount",
                         destination_dir: str = r"C:\vss_test",
                         callback: Callable[[bool, Exception | None], None] | None = None,
                         **options: Any) -> Future:
        def worker() -> bool:
            error = None
            try:
                self.recover(target_relative_path, mount_point, destination_dir, **options)
                return True
            except Exception as failure:
                error = failure
                raise
            finally:
                self._callback(callback, error is None, error)
        return self._executor.submit(worker)

    def close(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)

    def __enter__(self) -> "VssRecoveryEngine":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
