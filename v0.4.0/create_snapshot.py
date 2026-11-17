"""Compatibility entry point for real, hourly-gated VSS creation.

The original check_admin/create_vss_snapshot names remain. Explicit calls join
the SAME durable gate as the hourly task. Skipped/failed/unknown are never
successful creation. Import does nothing; script use requires --scheduled.
"""
from __future__ import annotations

import argparse
import json
import os

from ransomguard.recovery import RecoveryError
from ransomguard.snapshots import HourlySnapshotCoordinator, SnapshotError, default_state_db, require_admin


def check_admin() -> None:
    try:
        require_admin()
    except SnapshotError as error:
        print(f"Snapshot precondition failed: {error}")
        raise SystemExit(1) from None


def create_vss_snapshot_result(drive_letter: str = "C:", *, state_db: str | os.PathLike[str] | None = None,
                               trigger: str = "hourly_schedule", timeout_seconds: float = 180.0) -> dict:
    """Detailed explicit scheduled-call result; never bypasses the shared gate."""
    database = default_state_db() if state_db is None else state_db
    return HourlySnapshotCoordinator(database, timeout_seconds=timeout_seconds).run(drive_letter, trigger=trigger)


def create_vss_snapshot(drive_letter: str = "C:", *, state_db: str | os.PathLike[str] | None = None,
                        trigger: str = "hourly_schedule", timeout_seconds: float = 180.0) -> bool:
    """Legacy bool: True only for a newly created AND verified snapshot."""
    try:
        result = create_vss_snapshot_result(drive_letter, state_db=state_db, trigger=trigger,
                                            timeout_seconds=timeout_seconds)
    except (SnapshotError, RecoveryError) as error:
        print(json.dumps({"status": "failed", "created": False, "reason": str(error)}, ensure_ascii=False))
        return False
    print(json.dumps(result, ensure_ascii=False))
    return result["status"] == "created" and result["created"] is True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scheduled VSS creation through the durable hourly gate")
    parser.add_argument("--scheduled", action="store_true", help="Explicit hourly invocation; never use at boot/install/detection")
    parser.add_argument("--volume-root", default="C:\\")
    parser.add_argument("--state-db", help="The SAME database used by the installed task")
    args = parser.parse_args(argv)
    if not args.scheduled:
        parser.error("No snapshot was created: this entry point requires --scheduled")
    try:
        result = create_vss_snapshot_result(args.volume_root, state_db=args.state_db)
    except (SnapshotError, RecoveryError) as error:
        print(json.dumps({"status": "failed", "created": False, "reason": str(error)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["status"] == "unknown" or result.get("requires_reconciliation") is True:
        return 2
    return 0 if result["status"] in ("created", "skipped") else 1


if __name__ == "__main__":
    raise SystemExit(main())
