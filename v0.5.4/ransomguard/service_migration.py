"""Import a stopped installation's SQLite stores into a new service-owned directory."""
from contextlib import ExitStack, closing, contextmanager
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import sqlite3
import stat
import uuid


STORES = {
    "observe.sqlite3": "Runtime/observe.sqlite3",
    "holds.sqlite3": "Runtime/holds.sqlite3",
    "review-pauses.sqlite3": "Runtime/review-pauses.sqlite3",
    "snapshots.sqlite3": "snapshots.sqlite3",
}
TABLES = {"observe.sqlite3": "events", "holds.sqlite3": "firewall_holds",
          "review-pauses.sqlite3": "pauses", "snapshots.sqlite3": "snapshot_attempts",
          "program-policy/allowlist.sqlite3": "programs"}
ALLOWLIST = "program-policy/allowlist.sqlite3"

CONFIG_FILES = ("Runtime/live-response-profile.json", "Runtime/response-config.json",
                "Runtime/protected-manifest.json", "Runtime/unprepared-manifest.json", "Runtime/protection.json",
                "Runtime/scope-authorization.json", "Runtime/protection-status.json",
                "Runtime/observer-ready.counters.json", "Runtime/observer-ready.counters.loss-reset.json",
                "Runtime/console-display.json", "Runtime/live-console.enabled",
                "Runtime/scope-settings-enabled.json", "snapshots.retention.json", "snapshots.schedule.json")


def check_schema(connection, name):
    row = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                             (TABLES[name],)).fetchone()
    if not row:
        raise ValueError(f"Missing product table in {name}")


def databases(source):
    found = dict(STORES)
    parent = source / "Runtime/program-policy"
    if parent.exists() or parent.is_symlink():
        check_directory(parent)
        if (source / "Runtime" / ALLOWLIST).exists():
            found[ALLOWLIST] = "Runtime/" + ALLOWLIST
        elif any(parent.iterdir()):
            raise ValueError("Incomplete program allowlist")
    return found


def check_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError(f"Unexpected directory type: {path.name}")


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError(f"Unexpected file type: {path.name}")
    return info


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def inventory(source):
    result = {}
    for folder in (source, source / "Runtime"):
        check_directory(folder)
    for name, rel in databases(source).items():
        db = source / rel
        if not db.exists():
            raise ValueError(f"Missing source database: {name}")
        for suffix in ("", "-wal", "-journal"):
            file = Path(str(db) + suffix)
            if file.exists():
                regular(file)
                result[rel + suffix] = digest(file)
    for name in ("scope-history", "manual-restores", "counter-resets"):
        folder = source / "Runtime" / name
        if not folder.exists() and not folder.is_symlink():
            continue
        check_directory(folder)
        for parent, dirs, files in os.walk(folder):
            for sub in dirs:
                check_directory(Path(parent) / sub)
            for entry in files:
                path = Path(parent) / entry
                regular(path)
                result[path.relative_to(source).as_posix()] = digest(path)
    for rel in CONFIG_FILES:
        file = source / rel
        if file.exists():
            regular(file)
            result[rel] = digest(file)
    return result


def rebind_retention(value, output, target):
    old = PureWindowsPath(value["outbox_db"])
    if not old.is_absolute() or old.name.lower() != "observe.sqlite3" or (
            PureWindowsPath(value["holds_db"]) != old.with_name("holds.sqlite3")):
        raise ValueError("Unrecognized retention database paths")
    paths = []
    for previous in value["manifest_paths"]:
        rel = PureWindowsPath(previous).relative_to(old.parent)
        migrated = output.joinpath(*rel.parts)
        if rel == PureWindowsPath("unprepared-manifest.json"):
            # Kept by scope setup in the retention list even after a real baseline exists.
            if json.loads(migrated.read_text(encoding="utf-8-sig")) != {"schema_version": 1, "manifest": []}:
                raise ValueError("Unexpected unprepared recovery manifest")
        elif (".." in rel.parts or rel.name.lower() != "protected-manifest.json"
                or (len(rel.parts) > 1 and rel.parts[0].lower() != "scope-history")
                or not migrated.is_file()):
            raise ValueError("A referenced recovery manifest could not be migrated")
        paths.append(str(target.joinpath(*rel.parts)))
    return dict(value, outbox_db=str(target / old.name), holds_db=str(target / "holds.sqlite3"), manifest_paths=paths)


@contextmanager
def migration_directory(private_root):
    # Windows Python 3.13 gives mkdir(0o700) an explicit Administrators-full
    # ACL. On NTFS the renamed stores retain the staging ACL, so inherit the
    # service-owned parent's ACL from the instant we create the directory.
    stage = private_root / (".migration-" + uuid.uuid4().hex)
    stage.mkdir(mode=0o777 if os.name == "nt" else 0o700)
    try:
        yield stage
    finally:
        check_directory(stage)
        shutil.rmtree(stage)


def migrate(source, private_root):
    """Caller provides a quiescent source and an ACL-protected destination on local NTFS."""
    check_directory(Path(source))
    check_directory(Path(private_root))
    source, private_root = Path(source).resolve(strict=True), Path(private_root).resolve(strict=True)
    if source == private_root or source in private_root.parents or private_root in source.parents:
        raise ValueError("Source and service storage must be separate directories")
    target = private_root / "stores"
    if target.exists():
        raise FileExistsError("Service stores already exist; the active store was preserved")
    before = inventory(source)
    # A staging directory on the same volume keeps all four stores on one side of the handover.
    with migration_directory(private_root) as stage:
        snapshot, output = stage / "source", stage / "stores"
        output.mkdir()
        for rel, expected in before.items():
            clone = snapshot / rel
            clone.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / rel, clone)
            if digest(clone) != expected:
                raise RuntimeError("Source changed during import")
        stores = databases(snapshot)
        for name, rel in stores.items():
            # Rebuild SQLite shared memory only on the private copy. SQLite interprets committed
            # WAL frames and hot rollback journals before backing up the logical database.
            with ExitStack() as stack:
                old = stack.enter_context(closing(sqlite3.connect(snapshot / rel)))
                (output / name).parent.mkdir(exist_ok=True)
                new = stack.enter_context(closing(sqlite3.connect(output / name)))
                check_schema(old, name)
                if old.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise ValueError(f"Source integrity check failed: {name}")
                old.backup(new)
                if new.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                    raise RuntimeError(f"WAL unavailable: {name}")
                new.execute("PRAGMA synchronous=FULL")
                if new.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise ValueError(f"Imported database failed integrity check: {name}")
        for rel in CONFIG_FILES:
            if rel not in before:
                continue
            name = Path(rel).name
            if name == "live-response-profile.json":
                profile = json.loads((snapshot / rel).read_text(encoding="utf-8-sig"))
                # Scope, tracks and operator approvals remain exactly as supplied.
                profile["config"] = str(target / "response-config.json")
                profile["manifest"] = str(target / "protected-manifest.json")
                (output / name).write_text(json.dumps(profile, ensure_ascii=False), encoding="utf-8")
            else:
                shutil.copyfile(snapshot / rel, output / name)
        for rel in before:
            if rel.startswith(("Runtime/scope-history/", "Runtime/manual-restores/", "Runtime/counter-resets/")):
                dest = output / Path(rel).relative_to("Runtime")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(snapshot / rel, dest)
        retention = output / "snapshots.retention.json"
        if retention.is_file():
            policy = json.loads(retention.read_text(encoding="utf-8-sig"))
            retention.write_text(json.dumps(rebind_retention(policy, output, target), ensure_ascii=False), encoding="utf-8")
        if inventory(source) != before:
            raise RuntimeError("Source changed before handover")
        manifest = {"schema": 1, "source_files": before,
                    "imported_sha256": {name: digest(output / name) for name in stores}}
        with (output / "import.json").open("x", encoding="utf-8") as receipt:
            json.dump(manifest, receipt, sort_keys=True)
            receipt.flush()
            os.fsync(receipt.fileno())
        os.rename(output, target)
    return manifest


def stage_offline(source, destination):
    source = Path(source).resolve(strict=True)
    destination = Path(destination).resolve(strict=True)
    if (source == destination or source in destination.parents or destination in source.parents
            or any(destination.iterdir())):
        raise ValueError("Offline source and empty incoming directory must be separate")
    before = inventory(source)
    for rel in before:
        copy = destination / rel
        copy.parent.mkdir(parents=True, exist_ok=True)
        with (source / rel).open("rb") as reader, copy.open("xb") as writer:
            shutil.copyfileobj(reader, writer)
    if before != inventory(destination) or before != inventory(source):
        raise RuntimeError("Offline staging changed; service registration must stop")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline-source", required=True)
    parser.add_argument("--incoming", required=True)
    args = parser.parse_args()
    stage_offline(args.offline_source, args.incoming)
