from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import uuid

from ransomguard.service_operations import commit, operator_policy, process_request, validate
from ransomguard.service_migration import rebind_retention


class OperatorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name)
        for name in ("requests", "answers", "private/stores", "private/claims"):
            (self.state / name).mkdir(parents=True)
        self.request = self.state / "requests" / (uuid.uuid4().hex + ".json")
        self.job = dict(op="scope.status", args={}, expires=time.time()+60)
        self.answer = self.state / "answers" / self.request.name

    def test_duplicate_delivery_does_not_repeat_action(self):
        act = Mock(return_value={"ready": False})
        for _ in range(2):
            commit(self.request, self.job)
            process_request(self.state, self.request, act=act)
        act.assert_called_once_with(self.state / "private/stores", "scope.status", {})
        self.assertEqual(json.loads(self.answer.read_text())["value"], {"ready": False})

    def test_stale_and_interrupted_jobs_never_repeat(self):
        act = Mock()
        commit(self.request, dict(self.job, expires=time.time()-1))
        process_request(self.state, self.request, act=act)
        self.assertIn("expired", self.answer.read_text())
        self.answer.unlink()
        commit(self.request, self.job)
        commit(self.state / "private/claims" / self.request.name, {"op": "scope.status"})
        process_request(self.state, self.request, act=act)
        self.assertIn("interrupted", self.answer.read_text())
        act.assert_not_called()

    def test_only_explicit_domain_operations_are_accepted(self):
        for op, args in (("sql", {}), ("scope.status", {"path": "other"}),
                         ("snapshot.restore-execute", {"token": "../file", "confirmed": True}),
                         ("snapshot.restore-execute", {"token": str(uuid.uuid4()), "confirmed": False}),
                         ("firewall.policy", {"request": {"action": "set", "path": "other"}})):
            with self.subTest(op=op), self.assertRaises(ValueError):
                validate(op, args)

    def test_firewall_change_checks_current_holds_before_contacting_daemon(self):
        target = self.state / "private/stores"
        with closing(sqlite3.connect(target / "holds.sqlite3")) as db:
            db.execute("CREATE TABLE firewall_holds(id TEXT)")
            db.execute("INSERT INTO firewall_holds VALUES('open')")
            db.commit()
            with patch("ransomguard.firewall_ipc.FirewallIpcClient") as client:
                with self.assertRaisesRegex(ValueError, "holds"):
                    operator_policy(target, {"action": "refresh"})
                client.assert_not_called()
                db.execute("DELETE FROM firewall_holds")
                db.commit()
                operator_policy(target, {"action": "refresh"})
                client.return_value.request.assert_called_once_with(action="refresh")

    def test_retention_keeps_links_to_archived_approved_manifests(self):
        folder = self.state / "private/stores"
        archive = folder / "scope-history/previous/protected-manifest.json"
        archive.parent.mkdir(parents=True)
        archive.write_text("{}")
        base = r"C:\ProgramData\RansomGuard\Runtime"
        policy = dict(outbox_db=base+r"\observe.sqlite3", holds_db=base+r"\holds.sqlite3",
                      manifest_paths=[base+r"\scope-history\previous\protected-manifest.json"])
        relinked = rebind_retention(policy, folder, folder)
        self.assertEqual(relinked["manifest_paths"], [str(archive)])
        policy["manifest_paths"] = [r"C:\outside\protected-manifest.json"]
        with self.assertRaises(ValueError):
            rebind_retention(policy, folder, folder)

    @unittest.skipUnless(os.name == "nt", "Windows identity")
    def test_interactive_account_cannot_enter_scm_service_main(self):
        from ransomguard.service_identity import require_service_account
        with self.assertRaises(PermissionError):
            require_service_account()
