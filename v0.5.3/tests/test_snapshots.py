"""Offline tests: real SQLite/filesystem, mocked Windows/VSS provider calls."""
from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import subprocess
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import create_snapshot
import vss_recovery
from ransomguard.recovery import LocalSnapshotBackend, RecoveryEngine, RecoveryError, RecoveryValidationError, Snapshot
from ransomguard.snapshots import (
    HourlySnapshotCoordinator, SnapshotCreationFailed, SnapshotOutcomeUnknown,
    SnapshotPolicyError, SnapshotStateError, _CREATE_SCRIPT, _create_vss_snapshot,
    normalize_volume_root, require_admin,
)

VOLUME = "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\"
OTHER_VOLUME = "\\\\?\\Volume{22222222-2222-2222-2222-222222222222}\\"
START = datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc)


def snapshot(at=START, volume=VOLUME, ident=None):
    return Snapshot(ident or "{" + str(uuid.uuid4()) + "}", volume, at,
                    r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7")


def payload(value=None, **overrides):
    value = value or snapshot(datetime.now(timezone.utc))
    data = {"schema_version": 1, "return_value": 0, "shadow_id": value.snapshot_id,
            "metadata_error": False, "snapshot": value.to_dict()}
    data.update(overrides)
    return data


class ProviderTests(unittest.TestCase):
    def invoke(self, output, **kwargs):
        with patch("ransomguard.snapshots.require_admin"), \
             patch("ransomguard.snapshots._powershell_executable", return_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"), \
             patch("ransomguard.snapshots.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(output))) as run:
            result = _create_vss_snapshot(VOLUME, **kwargs)
        return result, run

    def test_real_provider_command_uses_fixed_script_stdin_json_and_checks_metadata(self):
        expected = snapshot(datetime.now(timezone.utc))
        result, run = self.invoke(payload(expected), timeout_seconds=45)
        self.assertEqual(result, expected)
        arguments, options = run.call_args
        self.assertEqual(arguments[0][-1], _CREATE_SCRIPT)
        self.assertNotIn(VOLUME, arguments[0][-1])
        self.assertIn("Invoke-CimMethod", arguments[0][-1])
        self.assertEqual(json.loads(options["input"]), {"schema_version": 1, "volume_id": VOLUME})
        self.assertIs(options["shell"], False)
        self.assertEqual(options["timeout"], 45.0)

    def test_nonzero_vss_return_values_are_definite_failures(self):
        for code in (1, 6, 9, 13):
            with self.subTest(code=code), self.assertRaises(SnapshotCreationFailed) as raised:
                self.invoke(payload(return_value=code, snapshot=None))
            self.assertEqual(raised.exception.return_value, code)

    def test_malformed_or_mismatched_success_is_unknown_never_success(self):
        good = snapshot(datetime.now(timezone.utc))
        bad_metadata = snapshot(datetime.now(timezone.utc), OTHER_VOLUME).to_dict()
        cases = [{}, [], payload(return_value=True), payload(return_value="0"),
                 payload(shadow_id="bad"), payload(metadata_error=True), payload(snapshot=None),
                 payload(good, snapshot=bad_metadata), payload(good, snapshot=snapshot().to_dict())]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(SnapshotOutcomeUnknown):
                self.invoke(value)

    def test_timeout_and_nonzero_process_exit_are_unknown(self):
        with patch("ransomguard.snapshots.require_admin"), patch("ransomguard.snapshots._powershell_executable", return_value="trusted"):
            with patch("ransomguard.snapshots.subprocess.run", side_effect=subprocess.TimeoutExpired("trusted", 2)):
                with self.assertRaises(SnapshotOutcomeUnknown):
                    _create_vss_snapshot(VOLUME)
            with patch("ransomguard.snapshots.subprocess.run", return_value=SimpleNamespace(returncode=1, stdout="")):
                with self.assertRaises(SnapshotOutcomeUnknown):
                    _create_vss_snapshot(VOLUME)

    def test_launch_and_admin_failures_do_not_claim_creation(self):
        with patch("ransomguard.snapshots.require_admin", side_effect=SnapshotCreationFailed("administrator_required")), \
             patch("ransomguard.snapshots.subprocess.run") as run:
            with self.assertRaises(SnapshotCreationFailed):
                _create_vss_snapshot(VOLUME)
            run.assert_not_called()
        with patch("ransomguard.snapshots.require_admin"), patch("ransomguard.snapshots._powershell_executable", return_value="trusted"), \
             patch("ransomguard.snapshots.subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(SnapshotCreationFailed):
                _create_vss_snapshot(VOLUME)
        with patch("ransomguard.snapshots.sys.platform", "linux"):
            with self.assertRaises(SnapshotCreationFailed):
                require_admin()


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Path(self.directory.name) / "state" / "snapshots.sqlite3"
        self.now = START
        self.creations = []

    def creator(self, volume, **_):
        value = snapshot(self.now, volume)
        self.creations.append(value)
        return value

    def coordinator(self, **overrides):
        options = dict(create_fn=self.creator, volume_resolver=lambda _: VOLUME,
                       inventory_fn=lambda _: self.creations, clock=lambda: self.now)
        options.update(overrides)
        return HourlySnapshotCoordinator(self.db, **options)

    def test_construct_and_disallowed_triggers_do_not_create_or_initialize_db(self):
        coordinator = self.coordinator()
        for trigger in ("startup", "install", "detection", "jev", "recovery", "manual"):
            with self.subTest(trigger=trigger), self.assertRaises(SnapshotPolicyError):
                coordinator.run(trigger=trigger)
        self.assertFalse(self.db.exists())
        self.assertEqual(self.creations, [])

    def test_first_explicit_tick_and_strict_3600_second_boundary(self):
        coordinator = self.coordinator()
        first = coordinator.run()
        self.assertEqual(first["status"], "created")
        self.assertTrue(first["created"])
        self.now += timedelta(seconds=3599)
        blocked = coordinator.run()
        self.assertEqual(blocked["reason"], "hourly_cooldown")
        self.assertFalse(blocked["attempted"])
        self.assertEqual(blocked["next_eligible_at"], (START + timedelta(hours=1)).isoformat())
        self.now += timedelta(seconds=1)
        self.assertEqual(coordinator.run()["status"], "created")
        self.assertEqual(len(self.creations), 2)

    def test_restart_and_drive_alias_preserve_volume_gate(self):
        self.coordinator().run("C:\\")
        self.now += timedelta(minutes=30)
        result = self.coordinator().run("D:\\")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(len(self.creations), 1)

    def test_independent_volumes_have_independent_hourly_gates(self):
        coordinator = self.coordinator(volume_resolver=lambda root: VOLUME if root == "C:\\" else OTHER_VOLUME)
        self.assertEqual(coordinator.run("C:\\")["status"], "created")
        self.assertEqual(coordinator.run("D:\\")["status"], "created")
        self.assertEqual(len(self.creations), 2)

    def test_concurrent_instances_reserve_only_once(self):
        barrier = threading.Barrier(8)
        def worker(_):
            coordinator = self.coordinator()
            barrier.wait(timeout=5)
            return coordinator.run()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        self.assertEqual(sum(item["status"] == "created" for item in results), 1)
        self.assertEqual(sum(item["status"] == "skipped" for item in results), 7)
        self.assertEqual(len(self.creations), 1)

    def test_failed_attempt_consumes_slot_but_allows_next_hour(self):
        provider = Mock(side_effect=SnapshotCreationFailed("storage_full", return_value=6))
        coordinator = self.coordinator(create_fn=provider)
        failed = coordinator.run()
        self.assertEqual((failed["status"], failed["return_value"]), ("failed", 6))
        self.assertFalse(failed["created"])
        self.assertEqual(coordinator.run()["reason"], "hourly_cooldown")
        self.now += timedelta(seconds=3600)
        coordinator.run()
        self.assertEqual(provider.call_count, 2)

    def test_unknown_blocks_even_after_hours_until_explicit_reconciliation(self):
        provider = Mock(side_effect=SnapshotOutcomeUnknown("creation_timeout"))
        result = self.coordinator(create_fn=provider).run()
        self.assertEqual(result["status"], "unknown")
        self.now += timedelta(hours=3)
        coordinator = self.coordinator(create_fn=provider)
        self.assertEqual(coordinator.run()["reason"], "unresolved_previous_attempt")
        self.assertEqual(provider.call_count, 1)
        with self.assertRaises(SnapshotPolicyError):
            coordinator.reconcile(confirm_no_snapshot=True)
        resolved = coordinator.reconcile(operation_finished=True, confirm_no_snapshot=True)
        self.assertEqual(resolved["status"], "reconciled_absent")
        self.assertEqual(self.coordinator().run()["status"], "created")

    def test_crash_after_claim_persists_in_progress_and_never_blindly_retries(self):
        provider = Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.coordinator(create_fn=provider).run()
        self.now += timedelta(hours=2)
        result = self.coordinator().run()
        self.assertEqual(result["previous_status"], "in_progress")
        self.assertEqual(result["reason"], "unresolved_previous_attempt")
        self.assertEqual(self.creations, [])

    def test_unexpected_provider_exception_is_persisted_unknown(self):
        coordinator = self.coordinator(create_fn=Mock(side_effect=ValueError("raw provider internals")))
        result = coordinator.run()
        self.assertEqual(result["status"], "unknown")
        self.assertNotIn("raw provider internals", json.dumps(result))

    def test_invalid_provider_snapshot_is_unknown(self):
        for value in (None, {}, snapshot(START, OTHER_VOLUME), snapshot(START - timedelta(minutes=1))):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                coordinator = HourlySnapshotCoordinator(Path(directory) / "state.db", volume_resolver=lambda _: VOLUME,
                                                        create_fn=Mock(return_value=value), clock=lambda: START)
                self.assertEqual(coordinator.run()["status"], "unknown")

    def test_state_failure_never_calls_provider(self):
        self.db.parent.mkdir()
        self.db.write_text("not a sqlite database", encoding="utf-8")
        with self.assertRaises(SnapshotStateError):
            self.coordinator().run()
        self.assertEqual(self.creations, [])

    def test_completion_commit_failure_keeps_unresolved_reservation(self):
        coordinator = self.coordinator()
        with patch.object(coordinator, "_finish", side_effect=SnapshotStateError("disk failed")):
            with self.assertRaises(SnapshotStateError):
                coordinator.run()
        self.now += timedelta(hours=2)
        self.assertEqual(self.coordinator().run()["reason"], "unresolved_previous_attempt")
        self.assertEqual(len(self.creations), 1)

    def test_clock_rollback_does_not_create(self):
        self.coordinator().run()
        self.now -= timedelta(minutes=5)
        self.assertEqual(self.coordinator().run()["reason"], "clock_moved_backwards")
        self.assertEqual(len(self.creations), 1)

    def test_reconcile_exact_existing_id_and_preserve_cooldown(self):
        created = snapshot(START)
        self.creations.append(created)
        coordinator = self.coordinator(create_fn=Mock(side_effect=SnapshotOutcomeUnknown("metadata_lost")))
        coordinator.run()
        self.now += timedelta(minutes=1)
        resolved = coordinator.reconcile(operation_finished=True, snapshot_id=created.snapshot_id)
        self.assertEqual(resolved["status"], "reconciled_created")
        self.assertEqual(resolved["snapshot"]["snapshot_id"], created.snapshot_id)
        self.assertEqual(coordinator.run()["reason"], "hourly_cooldown")

    def test_reconcile_requires_exact_choice_and_existing_same_volume_snapshot(self):
        coordinator = self.coordinator(create_fn=Mock(side_effect=SnapshotOutcomeUnknown("timeout")))
        coordinator.run()
        cases = [{}, {"confirm_no_snapshot": True, "snapshot_id": snapshot().snapshot_id},
                 {"snapshot_id": snapshot().snapshot_id}]
        for options in cases:
            with self.subTest(options=options), self.assertRaises(SnapshotPolicyError):
                coordinator.reconcile(operation_finished=True, **options)
        old = snapshot(START - timedelta(hours=1))
        self.creations.append(old)
        with self.assertRaises(SnapshotPolicyError):
            coordinator.reconcile(operation_finished=True, snapshot_id=old.snapshot_id)
        self.assertEqual(coordinator.run()["reason"], "unresolved_previous_attempt")

    def test_reconcile_does_not_substitute_another_id_for_known_creation_id(self):
        known, unrelated = snapshot(START), snapshot(START)
        self.creations.extend([known, unrelated])
        coordinator = self.coordinator(create_fn=Mock(side_effect=SnapshotOutcomeUnknown("metadata_lost", snapshot_id=known.snapshot_id)))
        coordinator.run()
        with self.assertRaises(SnapshotPolicyError):
            coordinator.reconcile(operation_finished=True, snapshot_id=unrelated.snapshot_id)
        self.assertEqual(coordinator.reconcile(operation_finished=True, snapshot_id=known.snapshot_id)["status"], "reconciled_created")

    def test_invalid_configuration_cannot_create(self):
        for timeout in (True, 0, -1, float("nan"), float("inf"), 301, "10"):
            with self.subTest(timeout=timeout), self.assertRaises(SnapshotPolicyError):
                self.coordinator(timeout_seconds=timeout)
        with self.assertRaises(SnapshotPolicyError):
            HourlySnapshotCoordinator(":memory:")
        for root in ("C:folder", "C:\\folder", "\\\\server\\share", "", "C:\\;x"):
            with self.subTest(root=root), self.assertRaises(SnapshotPolicyError):
                normalize_volume_root(root)
        self.assertEqual(normalize_volume_root("c:"), "C:\\")


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        base = Path(self.directory.name)
        self.source = base / "snapshot"
        self.live = base / "live"
        (self.source / "vss_test" / "sub").mkdir(parents=True)
        (self.live / "vss_test").mkdir(parents=True)
        (self.source / "vss_test" / "a.txt").write_text("original", encoding="utf-8")
        (self.source / "vss_test" / "sub" / "b.txt").write_text("nested", encoding="utf-8")
        (self.live / "vss_test" / "a.txt").write_text("changed", encoding="utf-8")
        (self.live / "vss_test" / "leftover.crypt").write_text("leftover", encoding="utf-8")
        engine = RecoveryEngine(backend=LocalSnapshotBackend(self.source, self.live))
        self.legacy = vss_recovery.VssRecoveryEngine(recovery_engine=engine)
        self.addCleanup(self.legacy.close)
        self.selection = patch.object(self.legacy, "_select", return_value=(snapshot(START), START + timedelta(minutes=10)))
        self.selection.start()
        self.addCleanup(self.selection.stop)
        self.options = {"containment_confirmed": True, "allow_local_test": True}

    def test_original_boolean_creation_api_reports_skips_and_unknown_as_false(self):
        for status in ("created", "skipped", "failed", "unknown"):
            result = {"status": status, "created": status == "created"}
            with self.subTest(status=status), patch("create_snapshot.create_vss_snapshot_result", return_value=result), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(create_snapshot.create_vss_snapshot(), status == "created")

    def test_legacy_string_creation_uses_shared_hourly_entrypoint(self):
        result = {"status": "skipped", "created": False, "reason": "hourly_cooldown"}
        with patch("vss_recovery.create_vss_snapshot_result", return_value=result) as create:
            self.assertEqual(json.loads(self.legacy.create_snapshot()), result)
        create.assert_called_once_with("C:\\", state_db=None, trigger="hourly_schedule", timeout_seconds=180.0)

    def test_plain_script_invocation_cannot_create(self):
        with patch("create_snapshot.create_vss_snapshot_result") as create, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                create_snapshot.main([])
            create.assert_not_called()

    def test_script_exit_codes_keep_unresolved_attempts_visible(self):
        cases = [("created", False, 0), ("skipped", False, 0), ("failed", False, 1),
                 ("unknown", True, 2), ("skipped", True, 2)]
        for status, unresolved, expected in cases:
            with self.subTest(status=status, unresolved=unresolved), \
                 patch("create_snapshot.create_vss_snapshot_result", return_value={"status": status, "requires_reconciliation": unresolved}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(create_snapshot.main(["--scheduled"]), expected)

    def test_actual_legacy_folder_restore_preserves_unlisted_leftovers_and_mount(self):
        mount = Path(self.directory.name) / "unrelated_mount"
        mount.write_text("keep", encoding="utf-8")
        with patch("vss_recovery.create_vss_snapshot_result") as create:
            self.assertIsNone(self.legacy.recover(mount_point=str(mount), **self.options))
            create.assert_not_called()
        self.assertEqual((self.live / "vss_test" / "a.txt").read_text(), "original")
        self.assertEqual((self.live / "vss_test" / "sub" / "b.txt").read_text(), "nested")
        self.assertTrue((self.live / "vss_test" / "leftover.crypt").exists())
        self.assertEqual(mount.read_text(), "keep")
        self.assertTrue(self.legacy.last_recovery_result["verified"])

    def test_recovery_without_opt_in_or_with_unsafe_mapping_fails_before_write(self):
        with self.assertRaises(RecoveryValidationError):
            self.legacy.recover()
        for options in ({"target_relative_path": "..\\vss_test"}, {"destination_dir": r"C:\another"}):
            with self.subTest(options=options), self.assertRaises(RecoveryValidationError):
                self.legacy.recover(**options, **self.options)
        self.assertEqual((self.live / "vss_test" / "a.txt").read_text(), "changed")

    def test_partial_result_is_an_error_not_legacy_success(self):
        with self.assertRaises(RecoveryError):
            self.legacy.recover(manifest=["a.txt", "missing.txt"], **self.options)
        self.assertEqual(self.legacy.last_recovery_result["status"], "partial")
        self.assertFalse(self.legacy.last_recovery_result["verified"])

    def test_async_and_pool_keep_original_thread_future_callback_contracts(self):
        callbacks = []
        thread = self.legacy.recover_async(callback=lambda ok, error: callbacks.append((ok, error)), **self.options)
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(callbacks, [(True, None)])
        callbacks.clear()
        future = self.legacy.recover_executor(callback=lambda ok, error: callbacks.append((ok, error)), **self.options)
        self.assertIs(future.result(timeout=5), True)
        self.assertEqual(callbacks, [(True, None)])

    def test_async_and_pool_report_missing_source_failure(self):
        callbacks = []
        options = {**self.options, "manifest": ["missing.txt"]}
        thread = self.legacy.recover_async(callback=lambda ok, error: callbacks.append((ok, error)), **options)
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(callbacks[0][0])
        self.assertIsInstance(callbacks[0][1], RecoveryError)
        future = self.legacy.recover_executor(**options)
        with self.assertRaises(RecoveryError):
            future.result(timeout=5)

    def test_legacy_folder_enumeration_refuses_symlinks(self):
        try:
            (self.source / "vss_test" / "link.txt").symlink_to(self.source / "vss_test" / "a.txt")
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable on this test host")
        with self.assertRaises(RecoveryValidationError):
            self.legacy.recover(**self.options)
        self.assertEqual((self.live / "vss_test" / "a.txt").read_text(), "changed")


if __name__ == "__main__":
    unittest.main()
