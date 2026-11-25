from contextlib import closing
from pathlib import Path
import json
import shutil
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from ransomguard.service_migration import ALLOWLIST, STORES, TABLES, migrate
from ransomguard.storage_service import serve_store


class ServiceMigrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.private = self.root / "private"
        self.private.mkdir()
        self.source = self.root / "incoming"
        (self.source / "Runtime").mkdir(parents=True)
        for name, rel in STORES.items():
            with closing(sqlite3.connect(self.source / rel)) as db:
                db.execute(f"CREATE TABLE {TABLES[name]}(id INTEGER PRIMARY KEY)")
                db.execute("CREATE TABLE history(seq INTEGER PRIMARY KEY, value TEXT)")
                db.execute("INSERT INTO history VALUES(1,?)", (name,))
                db.commit()

    def test_accepts_committed_wal_and_keeps_stores_on_service_restart(self):
        rel = STORES["observe.sqlite3"]
        # Copy a database with an uncheckpointed commit and an uncommitted writer.
        with closing(sqlite3.connect(self.root / "fixture")) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE events(id INTEGER PRIMARY KEY)")
            db.execute("CREATE TABLE history(seq INTEGER PRIMARY KEY, value TEXT)")
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            db.execute("INSERT INTO history VALUES(1,'kept')")
            db.commit()
            db.execute("INSERT INTO history VALUES(2,'not committed')")
            shutil.copyfile(self.root / "fixture", self.source / rel)
            shutil.copyfile(self.root / "fixture-wal", Path(str(self.source / rel) + "-wal"))
        manifest = migrate(self.source, self.private)
        self.assertEqual(set(manifest["imported_sha256"]), set(STORES))
        def writer(path, stop, ready):
            with closing(sqlite3.connect(path / "observe.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT * FROM history").fetchall(), [(1,"kept")])
                self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                db.execute("INSERT INTO history VALUES(3,'service write')")
                db.commit()
            ready()
        ready = threading.Event()
        serve_store(self.root, threading.Event(), ready.set, worker=writer)
        self.assertTrue(ready.is_set())
        with self.assertRaises(FileExistsError):
            migrate(self.source, self.private)
        with closing(sqlite3.connect(self.private / "stores/observe.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM history").fetchone()[0], 2)

    def test_corrupt_or_changing_source_never_activates_any_store(self):
        import ransomguard.service_migration as migration
        original = migration.inventory(self.source)
        with patch.object(migration, "inventory", side_effect=[original, {}]):
            with self.assertRaises(RuntimeError):
                migrate(self.source, self.private)
        self.assertEqual(list(self.private.iterdir()), [])
        (self.source / STORES["review-pauses.sqlite3"]).write_bytes(b"invalid fixture" * 100)
        with self.assertRaises((ValueError, sqlite3.DatabaseError)):
            migrate(self.source, self.private)
        self.assertEqual(list(self.private.iterdir()), [])

    def test_rejects_missing_database_on_restart_without_creating_empty_state(self):
        migrate(self.source, self.private)
        db = self.private / "stores/holds.sqlite3"
        db.unlink()
        with self.assertRaises(sqlite3.OperationalError):
            serve_store(self.root, threading.Event(), self.fail, worker=self.fail)
        self.assertFalse(db.exists())

    def test_empty_and_wrong_product_database_are_not_accepted(self):
        source = self.source / STORES["snapshots.sqlite3"]
        source.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "Missing product table"):
            migrate(self.source, self.private)
        shutil.copyfile(self.source / STORES["holds.sqlite3"], source)
        with self.assertRaisesRegex(ValueError, "Missing product table"):
            migrate(self.source, self.private)
        self.assertEqual(list(self.private.iterdir()), [])

    def test_preserves_setup_placeholder_beside_real_retention_manifest(self):
        runtime = self.source / "Runtime"
        old = Path(r"C:\ProgramData\RansomGuard\Runtime")
        blank = runtime / "unprepared-manifest.json"
        real = runtime / "protected-manifest.json"
        real.write_bytes(b'{"schema_version":1,"manifest":[{"relative_path":"original.txt"}]}')
        policy = dict(outbox_db=str(old / "observe.sqlite3"), holds_db=str(old / "holds.sqlite3"),
                      manifest_paths=[str(old / blank.name), str(old / real.name)])
        (self.source / "snapshots.retention.json").write_text(json.dumps(policy), encoding="utf-8")
        blank.write_bytes(b'{"schema_version":1,"manifest":["unexpected"]}')
        with self.assertRaisesRegex(ValueError, "Unexpected unprepared"):
            migrate(self.source, self.private)
        self.assertFalse((self.private / "stores").exists())
        blank.write_bytes(b'{"schema_version":1,"manifest":[]}')
        migrate(self.source, self.private)
        target = self.private / "stores"
        rebound = json.loads((target / "snapshots.retention.json").read_text(encoding="utf-8"))
        self.assertEqual(rebound["manifest_paths"], [str(target / blank.name), str(target / real.name)])
        self.assertEqual((target / blank.name).read_bytes(), blank.read_bytes())
        self.assertEqual((target / real.name).read_bytes(), real.read_bytes())

    def test_existing_allowlist_and_loss_history_survive_import(self):
        policy = self.source / "Runtime" / ALLOWLIST
        policy.parent.mkdir()
        with closing(sqlite3.connect(policy)) as db:
            db.execute("CREATE TABLE programs(id TEXT)")
            db.execute("INSERT INTO programs VALUES('trusted-entry')")
            db.commit()
        history = self.source / "Runtime/counter-resets/old/reset.json"
        history.parent.mkdir(parents=True)
        history.write_bytes(b'{"baseline":127}')
        migrate(self.source, self.private)
        target = self.private / "stores"
        self.assertEqual((target / "counter-resets/old/reset.json").read_bytes(), history.read_bytes())
        with closing(sqlite3.connect(target / ALLOWLIST)) as db:
            self.assertEqual(db.execute("SELECT id FROM programs").fetchone(), ("trusted-entry",))
        serve_store(self.root, threading.Event(), self.fail, worker=lambda *args: None)
