from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from ransomguard.snapshot_retention import finish_recovery_pin


class PinContentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'snapshots.sqlite3'
        with closing(sqlite3.connect(self.db)) as db:
            db.execute('CREATE TABLE snapshot_recovery_pins(job_id TEXT PRIMARY KEY,state TEXT)')
            db.execute("INSERT INTO snapshot_recovery_pins VALUES('job','active')")
            db.commit()

    def state(self):
        with closing(sqlite3.connect(self.db)) as db:
            return db.execute('SELECT state FROM snapshot_recovery_pins').fetchone()[0]

    def lock_reader(self):
        ready, release = threading.Event(), threading.Event()
        def read():
            with closing(sqlite3.connect(self.db)) as db:
                db.execute('BEGIN')
                db.execute('SELECT * FROM snapshot_recovery_pins').fetchall()
                ready.set()
                release.wait(10)
                db.rollback()
        thread = threading.Thread(target=read)
        thread.start()
        self.assertTrue(ready.wait(2))
        self.addCleanup(thread.join, 11)
        self.addCleanup(release.set)
        return release

    def test_completion_survives_reader_longer_than_old_three_second_timeout(self):
        release = self.lock_reader()
        timer = threading.Timer(3.5, release.set)
        timer.start()
        try:
            finish_recovery_pin(self.db, 'job', verified=True)
        finally:
            release.set(); timer.join()
        self.assertEqual(self.state(), 'released')

    def test_busy_failure_preserves_active_pin(self):
        release = self.lock_reader()
        original = sqlite3.connect
        def short_wait(*args, **kwargs):
            kwargs['timeout'] = .03
            return original(*args, **kwargs)
        try:
            with patch('ransomguard.snapshot_retention.sqlite3.connect', side_effect=short_wait):
                with self.assertRaises(sqlite3.OperationalError):
                    finish_recovery_pin(self.db, 'job', verified=True)
        finally:
            release.set()
        self.assertEqual(self.state(), 'active')

    def test_missing_pin_does_not_report_success(self):
        with self.assertRaisesRegex(RuntimeError, 'missing'):
            finish_recovery_pin(self.db, 'unknown', verified=True)
        self.assertEqual(self.state(), 'active')

    def test_missing_database_is_not_recreated(self):
        missing = self.db.with_name('missing.sqlite3')
        with self.assertRaises(sqlite3.OperationalError):
            finish_recovery_pin(missing, 'job', verified=True)
        self.assertFalse(missing.exists())
