"""Recovery tests operate only on explicit local temporary snapshot fixtures."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ransomguard.recovery import (
    LocalSnapshotBackend, ManifestEntry, RecoveryEngine, RecoveryValidationError,
    Snapshot, SnapshotDiscoveryError, build_plan, enumerate_snapshots, select_snapshot,
)


VOLUME = "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\"
OTHER_VOLUME = "\\\\?\\Volume{22222222-2222-2222-2222-222222222222}\\"
INCIDENT = datetime(2026, 1, 10, 12, tzinfo=timezone.utc)


def snapshot(number=1, age=timedelta(hours=1), volume=VOLUME):
    return Snapshot(f"{{00000000-0000-0000-0000-{number:012d}}}", volume,
                    INCIDENT - age, rf"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{number}")


def plan(files, selected=None):
    return build_plan(selected or snapshot(), volume_root="C:\\", protected_root="C:\\protected",
                      manifest=files, incident_at=INCIDENT)


class PlanningTests(unittest.TestCase):
    def test_selection_is_volume_and_time_bound_not_inventory_order(self):
        newest_safe = snapshot(2, timedelta(minutes=10))
        values = [snapshot(3, timedelta(minutes=-1)), newest_safe, snapshot(4, timedelta(minutes=1), OTHER_VOLUME), snapshot()]
        self.assertEqual(select_snapshot(values, volume_id=VOLUME, incident_at=INCIDENT), newest_safe)

    def test_explicit_id_never_falls_back(self):
        with self.assertRaises(RecoveryValidationError):
            select_snapshot([snapshot()], volume_id=VOLUME, incident_at=INCIDENT,
                            snapshot_id=snapshot(2).snapshot_id)

    def test_after_or_at_incident_snapshot_is_rejected(self):
        for age in (timedelta(0), timedelta(seconds=-1)):
            with self.subTest(age=age):
                with self.assertRaises(RecoveryValidationError):
                    plan(["a.txt"], snapshot(age=age))

    def test_timezone_is_required(self):
        with self.assertRaises(RecoveryValidationError):
            select_snapshot([snapshot()], volume_id=VOLUME, incident_at=INCIDENT.replace(tzinfo=None))

    def test_wrong_volume_and_duplicate_snapshot_ids_are_rejected(self):
        with self.assertRaises(RecoveryValidationError):
            select_snapshot([snapshot(volume=OTHER_VOLUME)], volume_id=VOLUME, incident_at=INCIDENT)
        with self.assertRaises(RecoveryValidationError):
            select_snapshot([snapshot(), snapshot()], volume_id=VOLUME, incident_at=INCIDENT)

    def test_rejects_unsafe_paths(self):
        for name in ("", "..\\a", "a\\..\\b", "a/./b", "C:\\a", "C:a", "/a", "\\\\server\\share\\a",
                     "a:stream", "NUL.txt", "folder\\CON", "a. ", "a\\", "a\\\\b", 'a"b', "a\x00b"):
            with self.subTest(name=name):
                with self.assertRaises(RecoveryValidationError):
                    plan([name])

    def test_rejects_wrong_roots_empty_and_duplicate_manifests(self):
        for root in ("D:\\protected", "C:\\", "C:\\protected\\..\\Windows", "C:protected"):
            with self.subTest(root=root):
                with self.assertRaises(RecoveryValidationError):
                    build_plan(snapshot(), volume_root="C:\\", protected_root=root, manifest=["a.txt"], incident_at=INCIDENT)
        for files in ([], ["a.txt", "A.TXT"], "a.txt"):
            with self.assertRaises(RecoveryValidationError):
                plan(files)

    def test_plan_has_explicit_snapshot_and_no_filesystem_side_effects(self):
        result = plan([{"relative_path": "sub/a.txt", "expected_size": 2}])
        self.assertEqual(result.entries[0].relative_path, "sub\\a.txt")
        self.assertEqual(result.protected_relative, ("protected",))
        self.assertEqual(result.to_dict()["snapshot"]["snapshot_id"], snapshot().snapshot_id)

    def test_protected_root_trailing_separator_is_supported(self):
        result = build_plan(snapshot(), volume_root="C:\\", protected_root="C:\\protected\\",
                            manifest=["a.txt"], incident_at=INCIDENT)
        self.assertEqual(result.protected_relative, ("protected",))

    def test_hash_and_size_manifest_fields_are_validated(self):
        for fields in ({"expected_sha256": "bad"}, {"expected_size": -1}, {"expected_size": True}, {"unexpected": 1}):
            with self.subTest(fields=fields):
                with self.assertRaises(RecoveryValidationError):
                    plan([{"relative_path": "a.txt", **fields}])


class LocalRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.source = root / "snapshot"
        self.live = root / "live"
        (self.source / "protected").mkdir(parents=True)
        (self.live / "protected").mkdir(parents=True)
        self.engine = RecoveryEngine(backend=LocalSnapshotBackend(self.source, self.live))

    def tearDown(self):
        self.temp.cleanup()

    def run_plan(self, value):
        return self.engine.execute(value, allow_local_test=True, containment_confirmed=True)

    def test_default_execution_never_writes(self):
        (self.source / "protected/a.txt").write_bytes(b"clean")
        target = self.live / "protected/a.txt"
        target.write_bytes(b"keep")
        with self.assertRaises(RecoveryValidationError):
            self.engine.execute(plan(["a.txt"]))
        with self.assertRaises(RecoveryValidationError):
            self.engine.execute(plan(["a.txt"]), containment_confirmed=True)
        self.assertEqual(target.read_bytes(), b"keep")

    def test_restores_only_manifest_files_and_verifies_hashes(self):
        (self.source / "protected/a.txt").write_bytes(b"clean")
        (self.source / "protected/unlisted.txt").write_bytes(b"old normal edit")
        (self.live / "protected/a.txt").write_bytes(b"damaged")
        (self.live / "protected/unlisted.txt").write_bytes(b"new normal edit")
        (self.live / "protected/ransom-note.txt").write_bytes(b"evidence")
        digest = hashlib.sha256(b"clean").hexdigest()
        result = self.run_plan(plan([ManifestEntry("a.txt", digest, 5)]))
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["verified"])
        self.assertEqual(result["files"][0]["sha256"], digest)
        self.assertEqual((self.live / "protected/a.txt").read_bytes(), b"clean")
        self.assertEqual((self.live / "protected/unlisted.txt").read_bytes(), b"new normal edit")
        self.assertEqual((self.live / "protected/ransom-note.txt").read_bytes(), b"evidence")
        self.assertEqual(list(self.live.rglob(".ransomguard-*")), [])

    def test_missing_source_is_partial_never_verified(self):
        (self.source / "protected/a.txt").write_bytes(b"clean")
        result = self.run_plan(plan(["a.txt", "missing.txt"]))
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["verified"])
        self.assertEqual((result["files_verified"], result["files_failed"]), (1, 1))

    def test_all_missing_is_failed(self):
        result = self.run_plan(plan(["missing.txt"]))
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["verified"])

    def test_hash_mismatch_does_not_replace_existing_file(self):
        (self.source / "protected/a.txt").write_bytes(b"unexpected")
        target = self.live / "protected/a.txt"
        target.write_bytes(b"original-live")
        result = self.run_plan(plan([ManifestEntry("a.txt", "0" * 64)]))
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["files"][0]["replaced"])
        self.assertEqual(target.read_bytes(), b"original-live")
        self.assertEqual(list(self.live.rglob(".ransomguard-*")), [])

    def test_creates_missing_parent_directories_for_listed_file(self):
        (self.source / "protected/sub").mkdir()
        (self.source / "protected/sub/a.txt").write_bytes(b"clean")
        result = self.run_plan(plan(["sub/a.txt"]))
        self.assertEqual(result["status"], "verified")
        self.assertEqual((self.live / "protected/sub/a.txt").read_bytes(), b"clean")

    def test_directory_manifest_entry_is_not_recursively_copied(self):
        (self.source / "protected/sub").mkdir()
        result = self.run_plan(plan(["sub"]))
        self.assertEqual(result["status"], "failed")
        self.assertFalse((self.live / "protected/sub").exists())

    def test_size_limit_is_enforced_before_replacement(self):
        (self.source / "protected/a.txt").write_bytes(b"12345")
        engine = RecoveryEngine(backend=self.engine.backend, max_file_bytes=4)
        result = engine.execute(plan(["a.txt"]), allow_local_test=True, containment_confirmed=True)
        self.assertEqual(result["status"], "failed")
        self.assertFalse((self.live / "protected/a.txt").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "OS does not expose symlink")
    def test_source_symlink_is_rejected(self):
        (self.source / "elsewhere.txt").write_bytes(b"outside")
        try:
            (self.source / "protected/a.txt").symlink_to(self.source / "elsewhere.txt")
        except OSError:
            self.skipTest("Creating symlinks requires unavailable platform permissions")
        result = self.run_plan(plan(["a.txt"]))
        self.assertEqual(result["status"], "failed")
        self.assertFalse((self.live / "protected/a.txt").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "OS does not expose symlink")
    def test_destination_directory_symlink_is_rejected(self):
        (self.source / "protected/sub").mkdir()
        (self.source / "protected/sub/a.txt").write_bytes(b"clean")
        elsewhere = Path(self.temp.name) / "elsewhere"
        elsewhere.mkdir()
        try:
            (self.live / "protected/sub").symlink_to(elsewhere, target_is_directory=True)
        except OSError:
            self.skipTest("Creating symlinks requires unavailable platform permissions")
        result = self.run_plan(plan(["sub/a.txt"]))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_replace_failure_preserves_existing_destination(self):
        (self.source / "protected/a.txt").write_bytes(b"clean")
        target = self.live / "protected/a.txt"
        target.write_bytes(b"original")
        with patch("ransomguard.recovery.os.replace", side_effect=PermissionError(13, "denied")):
            result = self.run_plan(plan(["a.txt"]))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(target.read_bytes(), b"original")
        self.assertEqual(list(self.live.rglob(".ransomguard-*")), [])

    def test_live_mode_requires_opt_in_and_windows(self):
        engine = RecoveryEngine()
        with self.assertRaises(RecoveryValidationError):
            engine.execute(plan(["a.txt"]), containment_confirmed=True)
        with patch("ransomguard.recovery.sys.platform", "linux"):
            with self.assertRaises(RecoveryValidationError):
                engine.execute(plan(["a.txt"]), containment_confirmed=True, allow_live=True)


class CimDiscoveryTests(unittest.TestCase):
    def test_fixed_script_uses_stdin_json_and_no_shell(self):
        selected = snapshot()
        output = json.dumps({"schema_version": 1, "snapshots": [selected.to_dict()]})
        with patch("ransomguard.recovery._powershell_executable", return_value="trusted-powershell.exe"), \
             patch("ransomguard.recovery.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=output)) as run:
            result = enumerate_snapshots(VOLUME)
        self.assertEqual(result, [selected])
        args, kwargs = run.call_args
        self.assertEqual(args[0][0], "trusted-powershell.exe")
        self.assertFalse(kwargs["shell"])
        self.assertEqual(json.loads(kwargs["input"])["volume_id"], VOLUME)
        self.assertNotIn(VOLUME, args[0][-1])
        self.assertIn("Get-CimInstance", args[0][-1])

    def test_discovery_rejects_wrong_volume_and_malformed_output(self):
        outputs = ["bad JSON", json.dumps({"schema_version": 1, "snapshots": [snapshot(volume=OTHER_VOLUME).to_dict()]}),
                   json.dumps({"schema_version": 1, "snapshots": {}})]
        for output in outputs:
            with self.subTest(output=output):
                with patch("ransomguard.recovery._powershell_executable", return_value="fake"), \
                     patch("ransomguard.recovery.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=output)):
                    with self.assertRaises(SnapshotDiscoveryError):
                        enumerate_snapshots(VOLUME)

    def test_discovery_timeout_is_a_typed_failure(self):
        with patch("ransomguard.recovery._powershell_executable", return_value="fake"), \
             patch("ransomguard.recovery.subprocess.run", side_effect=subprocess.TimeoutExpired("fake", 1)):
            with self.assertRaises(SnapshotDiscoveryError):
                enumerate_snapshots(VOLUME, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
