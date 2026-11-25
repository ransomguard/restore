"""Check a newly installed storage identity without acquiring the kernel collector."""
from contextlib import ExitStack, closing
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid

from .service_identity import current_user_sid, require_service_account
from .service_migration import STORES, TABLES, check_directory, migrate, regular


def verify_inactive_storage(state, stop, ready):
    require_service_account()
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError("Storage service must be unprivileged")
    private=state/"private"
    check_directory(private)
    if (private/"stores").exists():
        raise RuntimeError("Production storage already exists")
    trial=private/("acceptance-"+uuid.uuid4().hex)
    trial.mkdir()
    incoming=trial/"incoming"
    (incoming/"Runtime").mkdir(parents=True)
    for name, rel in STORES.items():
        with closing(sqlite3.connect(incoming/rel)) as db:
            db.execute("CREATE TABLE "+TABLES[name]+"(seq INTEGER PRIMARY KEY)")
            db.execute("INSERT INTO "+TABLES[name]+" VALUES(1)")
            db.commit()
    dest=trial/"private"
    dest.mkdir()
    migrate(incoming,dest)
    with ExitStack() as handles:
        for name in STORES:
            db=handles.enter_context(closing(sqlite3.connect(dest/"stores"/name)))
            if db.execute("PRAGMA journal_mode").fetchone()!=("wal",):
                raise RuntimeError("Missing WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("INSERT INTO "+TABLES[name]+" VALUES (2)")
            db.commit()
            if (db.execute("PRAGMA synchronous").fetchone()!=(2,) or
                    db.execute("SELECT seq FROM "+TABLES[name]+" ORDER BY seq").fetchall()!=[(1,),(2,)]):
                raise RuntimeError("Storage commit check failed")
        receipt={"scope":"disposable data only","sid":current_user_sid(),"pid":os.getpid(),
                 "admin":False,"committed_databases":len(STORES),"started":time.time()}
        # The original protected files remain outside the trial. Report whether
        # the service identity can read the existing signed-off recovery manifest.
        base=Path(os.environ["ProgramData"])/"RansomGuard/Runtime"
        try:
            manifest_file=base/"protected-manifest.json"
            if regular(manifest_file).st_size>1024*1024:
                raise ValueError("Recovery manifest too large for preflight")
            manifest=json.loads(manifest_file.read_text(encoding="utf-8-sig"))
            scope=Path(manifest["protected_root"])
            if not scope.is_absolute() or scope.drive.upper()!=base.drive.upper() or ".." in scope.parts:
                raise ValueError("Expected a local protected directory")
            for ancestor in (scope,*scope.parents):
                check_directory(ancestor)
            if not 0<len(manifest["manifest"])<=12:
                raise ValueError("Scope exceeds bounded acceptance check")
            originals=[]
            for item in manifest["manifest"]:
                name=item["relative_path"]
                if Path(name).name!=name or name in (".","..") or ":" in name:
                    raise ValueError("Preflight only accepts direct child files")
                file=scope/name
                if regular(file).st_size>1024*1024:
                    raise ValueError("Preflight file limit exceeded")
                originals.append(hashlib.sha256(file.read_bytes()).hexdigest()==item["expected_sha256"])
            receipt["protected_files"]={"count":len(originals),"all_match":bool(originals) and all(originals)}
        except (OSError,ValueError,KeyError) as exc:
            receipt["protected_files"]={"error":type(exc).__name__,"win32":getattr(exc,"winerror",None)}
        temp=trial/"ready.part"
        with temp.open("x",encoding="ascii") as out:
            json.dump(receipt,out)
            out.flush()
            os.fsync(out.fileno())
        temp.rename(trial/"ready.json")
        ready()
        stop.wait(100)
