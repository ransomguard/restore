from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ransomguard.response_commands import (firewall_status, profile_from_config,
                                            recovery_plan_from_template,
                                            recovery_plan_from_file, respond_one)
from ransomguard.recovery import Snapshot


VOLUME = r"\\?\Volume{00000000-0000-0000-0000-000000000222}" + "\\"


def snapshot():
    return Snapshot(
        snapshot_id="{00000000-0000-0000-0000-000000000111}",
        volume_id=VOLUME,
        created_at=datetime(2026, 11, 4, tzinfo=timezone.utc),
        device_path=r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9",
    )


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.config = self.base / "config.json"
        self.config.write_text(json.dumps({"schema_version": 1, "network": {
            "scope": "host_outbound", "jev_url": "https://api.typesafe.ai",
            "extra_https_targets": []},
            "decision": {"thresholds_are_demo_only": True,
                         "benign_threshold": 0.2, "malicious_threshold": 0.8}}))

    def tearDown(self):
        self.temp.cleanup()

    def test_status_without_daemon_is_read_only_and_does_not_require_windows(self):
        status = firewall_status(config_path=str(self.config), state_db=str(self.base / "fw.sqlite3"))
        self.assertEqual(status["scope"], "host_outbound")
        self.assertEqual(status["active_holds"], 0)
        self.assertNotIn("daemon_active_reported", status)

    def test_profile_rejects_obsolete_pid_scoped_policy(self):
        self.assertEqual(profile_from_config({"network": {
            "scope": "host_outbound", "jev_url": "https://api.typesafe.ai"}}).allowlist,
            ["https://api.typesafe.ai"])
        with self.assertRaises(ValueError):
            profile_from_config({"network": {"scope": "process", "jev_url": "https://api.typesafe.ai"}})

    def test_live_command_does_not_even_read_config_without_two_confirmations(self):
        with self.assertRaises(PermissionError):
            respond_one(config_path="nonexistent.json", state_db="ignored.sqlite3", outbox_db="ignored.sqlite3",
                        track="A", pid=4321, create_time=133000000000000001,
                        jev_state_file=None, recovery_plan_file=None, no_recovery_required=True,
                        track_a_confirmed=True, authorize_live=False, confirm_isolated_vm=False)
        self.assertFalse((self.base / "ignored.sqlite3").exists())

    def test_operator_manifest_resolves_existing_preincident_vss_only(self):
        path = self.base / "manifest.json"
        path.write_text(json.dumps({"schema_version": 1, "volume_root": "C:\\",
                                    "protected_root": r"C:\RansomGuardLab\Protected",
                                    "manifest": ["file.txt"]}))
        with patch("ransomguard.response_commands.volume_id_for_root", return_value=VOLUME), \
             patch("ransomguard.response_commands.enumerate_snapshots", return_value=[snapshot()]):
            plan = recovery_plan_from_template(str(path), incident_at="2026-11-05T01:00:00Z")
        self.assertEqual(plan.snapshot.snapshot_id, snapshot().snapshot_id)
        self.assertEqual([e.relative_path for e in plan.entries], ["file.txt"])

    def test_explicit_plan_must_match_preincident_snapshot_id(self):
        path = self.base / "plan.json"
        path.write_text(json.dumps({"schema_version": 1, "volume_root": "C:\\",
                                    "protected_root": r"C:\RansomGuardLab\Protected",
                                    "incident_at": "2026-11-05T01:00:00Z",
                                    "snapshot_id": "{00000000-0000-0000-0000-000000000444}",
                                    "manifest": ["file.txt"]}))
        with patch("ransomguard.response_commands.volume_id_for_root", return_value=VOLUME), \
             patch("ransomguard.response_commands.enumerate_snapshots", return_value=[snapshot()]):
            with self.assertRaises(ValueError):
                recovery_plan_from_file(str(path))


if __name__ == "__main__":
    unittest.main()
