import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from ransomguard.cli import main
from ransomguard.outbox import Outbox
from ransomguard.protocol import MAGIC, VERSION, PROCESS_SIZE, FILE_SIZE, FILE_FLAG_HIGH_ENTROPY, FILE_FLAG_PREOP_OBSERVATION


def event_stream():
    process = bytearray(PROCESS_SIZE)
    struct.pack_into("<IIIIQQ", process, 0, MAGIC, VERSION, 1, PROCESS_SIZE, 133000000000000000, 1)
    struct.pack_into("<IIIIqIIII", process, 32, 4100, 10, 10, 0, 133000000000000001, 0, 0, 0, 0)
    data = [bytes(process)]
    for sequence in (2, 3):
        write = bytearray(FILE_SIZE)
        path = r"\Device\HarddiskVolume3\Lab\note.txt".encode("utf-16-le")
        struct.pack_into("<IIIIQQ", write, 0, MAGIC, VERSION, 4, FILE_SIZE, 133000000000000100, sequence)
        struct.pack_into("<IIIIII", write, 32, 4100, 1, len(path), 0,
                         FILE_FLAG_HIGH_ENTROPY | FILE_FLAG_PREOP_OBSERVATION, 0)
        write[56:56 + len(path)] = path
        data.append(bytes(write))
    return data


class FakeReader:
    def __init__(self):
        self.records = iter(event_stream())

    def read(self):
        return next(self.records)

    def status(self):
        return {"test_reader": True}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class CliIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.config = self.directory / "config.json"
        self.config.write_text(json.dumps({"schema_version": 1, "recovery": {
            "volume_root": "C:\\", "snapshot_policy": "hourly_only", "snapshot_interval_seconds": 3600,
            "snapshot_creation_triggers": ["hourly_schedule"],
        }}))

    def tearDown(self):
        self.temp.cleanup()

    def run_main(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(args)

    def test_real_decode_observer_intake_outbox_path_produces_one_candidate_without_actions(self):
        db = self.directory / "events.sqlite3"
        with patch("ransomguard.windows_reader.WindowsDriverReader", FakeReader):
            self.assertEqual(self.run_main(["observe", "--db", str(db), "--limit", "3"]), 0)
        with Outbox(db) as outbox:
            events = outbox.pending()
        self.assertEqual(sum(x["event_type"] == "kernel_event" for x in events), 3)
        candidates = [x["data"] for x in events if x["event_type"] == "track_b_candidate"]
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["track"], "B")
        self.assertEqual(candidate["pid"], 4100)
        self.assertFalse(candidate["identity_authorization"])
        self.assertFalse(candidate["containment_confirmed"])
        self.assertFalse(candidate["jev_requested"])
        self.assertFalse(any(x["event_type"] in ("quarantine_applied", "process_exit_confirmed", "jev_requested") for x in events))

    def test_snapshot_result_is_logged_with_honest_exit_status(self):
        for status, code in (("created", 0), ("skipped", 0), ("failed", 1), ("unknown", 2)):
            with self.subTest(status=status), patch("ransomguard.snapshots.HourlySnapshotCoordinator") as coordinator:
                coordinator.return_value.run.return_value = {"status": status, "created": status == "created"}
                db = self.directory / (status + ".sqlite3")
                result = self.run_main(["snapshot-run", "--config", str(self.config), "--state-db",
                                       str(self.directory / "state.sqlite3"), "--db", str(db)])
                self.assertEqual(result, code)
                coordinator.return_value.run.assert_called_once_with(volume_root="C:\\", trigger="hourly_schedule")
                with Outbox(db) as outbox:
                    self.assertEqual(outbox.pending()[-1]["event_type"], "snapshot_" + status)

    def test_nonhourly_configuration_never_invokes_provider(self):
        config = json.loads(self.config.read_text())
        config["recovery"]["snapshot_creation_triggers"].append("incident")
        self.config.write_text(json.dumps(config))
        with patch("ransomguard.snapshots.HourlySnapshotCoordinator") as coordinator:
            code = self.run_main(["snapshot-run", "--config", str(self.config), "--state-db",
                                  str(self.directory / "state.sqlite3"), "--db", str(self.directory / "events.sqlite3")])
            self.assertEqual(code, 1)
            coordinator.assert_not_called()

    def test_scheduler_jitter_rechecks_only_unattempted_cooldown_once(self):
        for seconds in (2, -2):
            with self.subTest(seconds=seconds), patch("ransomguard.snapshots.HourlySnapshotCoordinator") as coordinator, patch("time.sleep") as sleep:
                coordinator.return_value.run.side_effect = [
                    {"status": "skipped", "reason": "hourly_cooldown", "attempted": False,
                     "next_eligible_at": (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()},
                    {"status": "created", "created": True},
                ]
                code = self.run_main(["snapshot-run", "--config", str(self.config), "--state-db",
                                      str(self.directory / "state.sqlite3"), "--db", str(self.directory / (str(seconds) + ".sqlite3"))])
                self.assertEqual(code, 0)
                self.assertEqual(coordinator.return_value.run.call_count, 2)
                self.assertEqual(sleep.call_count, 1)
                self.assertLessEqual(sleep.call_args.args[0], 60.0)

    def test_uncertain_snapshot_result_is_never_retried_even_with_due_time(self):
        with patch("ransomguard.snapshots.HourlySnapshotCoordinator") as coordinator, patch("time.sleep") as sleep:
            coordinator.return_value.run.return_value = {
                "status": "unknown", "reason": "provider_timeout", "attempted": True,
                "next_eligible_at": datetime.now(timezone.utc).isoformat(),
            }
            code = self.run_main(["snapshot-run", "--config", str(self.config), "--state-db",
                                  str(self.directory / "state.sqlite3"), "--db", str(self.directory / "unknown.sqlite3")])
            self.assertEqual(code, 2)
            coordinator.return_value.run.assert_called_once()
            sleep.assert_not_called()

    def test_blocked_unknown_previous_attempt_is_not_reported_as_healthy_tick(self):
        with patch("ransomguard.snapshots.HourlySnapshotCoordinator") as coordinator, patch("time.sleep") as sleep:
            coordinator.return_value.run.return_value = {
                "status": "skipped", "reason": "unresolved_previous_attempt", "attempted": False,
                "requires_reconciliation": True, "next_eligible_at": datetime.now(timezone.utc).isoformat(),
            }
            code = self.run_main(["snapshot-run", "--config", str(self.config), "--state-db",
                                  str(self.directory / "state.sqlite3"), "--db", str(self.directory / "blocked.sqlite3")])
            self.assertEqual(code, 2)
            coordinator.return_value.run.assert_called_once()
            sleep.assert_not_called()

    def test_task_definition_generation_does_not_touch_snapshot_provider(self):
        config = json.loads(self.config.read_text())
        output = self.directory / "task.xml"
        with patch("ransomguard.cli._load_config", return_value=config), patch("ransomguard.snapshots.HourlySnapshotCoordinator") as coordinator:
            code = self.run_main(["snapshot-task", "--config", r"C:\Lab\config.json", "--state-db",
                                  r"C:\Lab\snapshots.sqlite3", "--db", r"C:\Lab\events.sqlite3",
                                  "--python-executable", r"C:\Lab\venv\Scripts\python.exe",
                                  "--user-sid", "S-1-5-21-111-222-333-1001", "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertTrue(output.is_file())
            coordinator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
