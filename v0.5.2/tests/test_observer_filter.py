"""Exact, PID-scoped suppression for the observer's own SQLite files."""

import unittest

from ransomguard.observer_filter import ObserverOutboxFilter, _database_aliases
from ransomguard.protocol import Event


class ObserverOutboxFilterTests(unittest.TestCase):
    def setUp(self):
        self.filter = ObserverOutboxFilter("unused.sqlite3", observer_pid=7010)
        self.filter._file_paths = _database_aliases(
            r"C:\RG_Test\v0.3.0\observe.sqlite3", r"\Device\HarddiskVolume3")

    def event(self, path, *, pid=7010, kind=4):
        return Event(kind, "file_write_attempted" if kind == 4 else "process_created",
                     1, 1, pid, {"path": path})

    def test_exact_nt_device_db_and_sqlite_sidecars_are_ignored(self):
        base = r"\DEVICE\HARDDISKVOLUME3\rg_test\v0.3.0\Observe.sqlite3"
        for suffix in ("", "-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                self.assertTrue(self.filter.matches(self.event(base + suffix)))

    def test_dos_paths_and_sqlite_sidecars_are_ignored(self):
        base = r"C:\RG_Test\v0.3.0\observe.sqlite3"
        for path in (base, "\\??\\" + base, "\\\\?\\" + base, base + "-wal"):
            with self.subTest(path=path):
                self.assertTrue(self.filter.matches(self.event(path)))

    def test_other_volumes_files_and_processes_remain_visible(self):
        own = r"\Device\HarddiskVolume3\RG_Test\v0.3.0\observe.sqlite3"
        for event in (
            self.event(own, pid=9999),  # Another process tampering with the DB.
            self.event(own, kind=1),
            self.event(own + ".txt"),
            self.event(own + "-wal-copy"),
            self.event(r"\Device\HarddiskVolume4\RG_Test\v0.3.0\observe.sqlite3"),
            self.event(r"\Device\HarddiskVolume3\RG_Test\v0.3.0\other.sqlite3"),
        ):
            with self.subTest(event=event):
                self.assertFalse(self.filter.matches(event))

    def test_opaque_path_or_missing_path_does_not_crash_or_match(self):
        for path in (None, "", 12):
            self.assertFalse(self.filter.matches(self.event(path)))

