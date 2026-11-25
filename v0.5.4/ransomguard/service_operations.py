"""Local administrator requests to the storage owner. No SQL or executable arguments."""
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

from .service_migration import regular


ARGUMENTS = {
    "scope.status": (), "scope.change": ("folder", "snapshotBudgetGiB", "acknowledgeFolderRevert"),
    "snapshot.status": (), "snapshot.change": ("intervalMinutes",), "snapshot.list": (),
    "snapshot.manual": ("requestId",), "snapshot.protect": ("snapshotId", "enabled"),
    "snapshot.restore-preview": ("snapshotId",), "snapshot.restore-execute": ("token", "confirmed"),
    "snapshot.inventory": (), "snapshot.scheduled": (), "snapshot.retention": (),
    "loss.reset": (), "program.list": (), "program.add": ("path",), "program.remove": ("id",),
    "firewall.policy": ("request",),
    "console.set": ("requestId", "uiPid", "uiDbPath", "visible", "collectOwnDbEvents"),
    "ui.attach": ("uiPid", "uiDbPath"),
}
UUID_TEXT = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"


def validate(op, args):
    if op not in ARGUMENTS or type(args) is not dict or set(args) != set(ARGUMENTS[op]):
        raise ValueError("Unrecognized service operation or arguments")
    for key, val in args.items():
        if key in ("token", "requestId", "id") and not (isinstance(val, str) and re.fullmatch(UUID_TEXT, val)):
            raise ValueError("Invalid request identifier")
        if key == "snapshotId" and not (isinstance(val, str) and re.fullmatch(r"\{" + UUID_TEXT + r"\}", val)):
            raise ValueError("Invalid snapshot identifier")
        if key in ("confirmed", "acknowledgeFolderRevert") and val is not True:
            raise ValueError("Operation requires explicit confirmation")
        if key == "enabled" and type(val) is not bool:
            raise ValueError("Expected boolean")
        if key in ("visible", "collectOwnDbEvents") and type(val) is not bool:
            raise ValueError("Invalid console selection")
        if key == "uiPid" and (type(val) is not int or not 0 < val < 2**32):
            raise ValueError("Invalid UI process")
        if key in ("path", "folder") and not (isinstance(val, str) and 0 < len(val) <= 32767):
            raise ValueError("Invalid local path")
        if key == "intervalMinutes" and (type(val) is not int or val not in (15, 30, 60, 120)):
            raise ValueError("Invalid interval")
        if key == "snapshotBudgetGiB" and (type(val) is not int or not 4 <= val <= 32):
            raise ValueError("Invalid snapshot budget")
        if key == "request":
            from .firewall_ipc import encode_firewall_request
            if type(val) is not dict or set(val) - {"action", "direction", "whitelist"} or "action" not in val:
                raise ValueError("Invalid firewall request")
            encode_firewall_request(**val)


def operator_policy(target, request):
    from contextlib import closing
    import sqlite3
    from .firewall_ipc import FirewallIpcClient
    uri = (target / "holds.sqlite3").as_uri() + "?mode=rw"
    with closing(sqlite3.connect(uri, uri=True, timeout=0)) as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM firewall_holds LIMIT 1").fetchone():
            raise ValueError("An incident holds the firewall policy")
        return FirewallIpcClient().request(**request)


def attach_ui(target, pid, database):
    from .internal_collection import LiveOwner
    from pathlib import PureWindowsPath
    db = PureWindowsPath(database)
    if (not db.is_absolute() or len(db.drive) != 2 or ".." in db.parts
            or tuple(part.lower() for part in db.parts[-4:]) != ("appdata", "roaming", "ransom0-ui", "db.sqlite")):
        raise ValueError("Unrecognized UI database path")
    owner = LiveOwner(pid, Path(sys.executable).resolve().parent.parent / "ui/ransom0-ui.exe")
    try:
        # Only an authenticated local operator supplies this path. It is used for
        # the existing exact PID/generation filter; this service never opens it.
        os.environ["RANSOM0_UI_DATABASE"] = str(db)
        os.environ["RANSOM0_UI_PROCESS_ID"] = str(pid)
        status = target / "ui.pid"
        temp = status.with_suffix(".new")
        temp.write_text(str(pid), encoding="ascii")
        temp.replace(status)
        return {"pid": pid, "uiDbPath": str(db)}
    finally:
        owner.close()


def dispatch(target, op, args):
    from . import scope_settings, snapshot_settings, snapshot_management, program_allowlist
    from . import loss_settings, manual_restore, protection_setup
    validate(op, args)
    if op in ("ui.attach", "console.set"):
        attached = attach_ui(target, args["uiPid"], args["uiDbPath"])
        if op == "console.set":
            commit(target / "console-display.json", dict(args, uiDbPath=attached["uiDbPath"],
                   showOwnDbEvents=args["collectOwnDbEvents"]))
        return {"pid": attached["pid"]}
    if op == "snapshot.retention":
        from .snapshot_retention import SnapshotRetention, load_config
        from .recovery import volume_id_for_root
        state = target / "snapshots.sqlite3"
        with scope_settings.scope_lock(target):
            scope = scope_settings.read(target, "protection.json", {})
            if not scope:
                return {"skipped": "scope_not_configured"}
            return SnapshotRetention(state, load_config(state)).run(volume_id_for_root(scope["volume_root"]), apply=True)
    actions = {
        "scope.status": lambda: scope_settings.status(target),
        "scope.change": lambda: scope_settings.change(target, args),
        "snapshot.status": lambda: snapshot_settings.status(target),
        "snapshot.change": lambda: snapshot_settings.change(target, args["intervalMinutes"]),
        "snapshot.inventory": lambda: snapshot_settings.inventory(target),
        "snapshot.list": lambda: snapshot_management.list_owned(target),
        "snapshot.protect": lambda: snapshot_management.protect(target, args["snapshotId"], args["enabled"]),
        "snapshot.manual": lambda: snapshot_management.manual(target, args["requestId"]),
        "snapshot.restore-preview": lambda: manual_restore.preview(target, args["snapshotId"]),
        "snapshot.restore-execute": lambda: manual_restore.execute(target, args["token"], args["confirmed"]),
        "snapshot.scheduled": lambda: protection_setup.refresh(target, create_snapshot=True),
        "loss.reset": lambda: loss_settings.reset(target),
        "program.list": lambda: {"entries": program_allowlist.entries(target)},
        "program.add": lambda: {"entries": program_allowlist.add(target, args["path"])},
        "program.remove": lambda: {"entries": program_allowlist.remove(target, args["id"])},
        "firewall.policy": lambda: operator_policy(target, args["request"]),
    }
    return actions[op]()


def bounded_json(path, limit):
    regular(path)
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Management message exceeds limit")
    return json.loads(data)


def commit(path, record):
    temp = path.with_suffix("." + uuid.uuid4().hex + ".tmp")
    try:
        with temp.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=True, allow_nan=False, default=str)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def process_request(state, request, *, act=dispatch):
    if not re.fullmatch("[0-9a-f]{32}[.]json", request.name):
        return
    result = state / "answers" / request.name
    claim = state / "private/claims" / request.name
    if result.exists():
        request.unlink(missing_ok=True)
        return
    if claim.exists():
        reply = {"error": "Prior action interrupted. Inspect the recorded outcome before any new request."}
    else:
        try:
            job = bounded_json(request, 262144)
            if set(job) != {"op", "args", "expires"} or type(job["expires"]) not in (int, float):
                raise ValueError("Invalid management request")
            if not time.time() <= job["expires"] <= time.time() + 120:
                raise ValueError("Request expired")
            validate(job["op"], job["args"])
            # A single SCM instance processes one job at a time. Record before effects.
            commit(claim, {"op": job["op"], "at": time.time()})
            reply = {"value": act(state / "private/stores", job["op"], job["args"])}
        except Exception as exc:
            reply = {"error": str(exc)[:2048] or type(exc).__name__}
    commit(result, reply)
    request.unlink(missing_ok=True)


def operate(state, finished):
    (state / "private/claims").mkdir(exist_ok=True)
    while not finished.wait(.5):
        for request in (state / "requests").glob("*.json"):
            if finished.is_set():
                return
            process_request(state, request)


def submit(state, op, args):
    validate(op, args)
    name = uuid.uuid4().hex + ".json"
    result = state / "answers" / name
    commit(state / "requests" / name, {"op": op, "args": args, "expires": time.time() + 90})
    until = time.monotonic() + 360
    while time.monotonic() < until:
        if result.is_file():
            reply = bounded_json(result, 16 * 1024 * 1024)
            if "error" in reply:
                raise RuntimeError(reply["error"])
            return reply["value"]
        time.sleep(.2)
    raise TimeoutError(f"Request {name} has no verified result; check its receipt before repeating")


def main():
    try:
        raw = sys.stdin.buffer.read(262145)
        if len(sys.argv) != 2 or len(raw) > 262144:
            raise ValueError("Invalid management request")
        result = submit(Path(sys.executable).resolve().parent.parent / "service-state",
                        sys.argv[1], json.loads(raw or b"{}"))
        print(json.dumps(result, ensure_ascii=True, default=str))
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
