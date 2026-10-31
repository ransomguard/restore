from datetime import datetime, timezone
import unittest
from xml.etree import ElementTree as ET

from ransomguard.scheduling import build_hourly_task_xml, next_hour, TASK_NAMESPACE


class SchedulingTests(unittest.TestCase):
    def build(self, **overrides):
        values = dict(python_executable=r"C:\Lab folder\venv\Scripts\python.exe",
                      config_path=r"C:\Lab folder\config\example.json",
                      state_db=r"C:\ProgramData\RansomGuard\snapshots.sqlite3",
                      outbox_db=r"C:\ProgramData\RansomGuard\events.sqlite3",
                      user_sid="S-1-5-21-111-222-333-1001",
                      now=datetime(2026, 10, 31, 9, 14, 23, tzinfo=timezone.utc))
        values.update(overrides)
        return ET.fromstring(build_hourly_task_xml(**values))

    def test_only_one_future_hourly_trigger_without_catchup_or_retry(self):
        root = self.build()
        ns = {"t": TASK_NAMESPACE}
        triggers = root.find("t:Triggers", ns)
        self.assertEqual([x.tag.rsplit("}", 1)[-1] for x in triggers], ["TimeTrigger"])
        self.assertEqual(root.findtext("t:Triggers/t:TimeTrigger/t:StartBoundary", namespaces=ns),
                         "2026-10-31T10:00:00+00:00")
        self.assertEqual(root.findtext("t:Triggers/t:TimeTrigger/t:Repetition/t:Interval", namespaces=ns), "PT1H")
        self.assertIsNone(root.find(".//t:Duration", ns))
        for name in ("StartWhenAvailable", "WakeToRun", "AllowStartOnDemand"):
            self.assertEqual(root.findtext("t:Settings/t:" + name, namespaces=ns), "false")
        self.assertEqual(root.findtext("t:Settings/t:MultipleInstancesPolicy", namespaces=ns), "IgnoreNew")
        self.assertIsNone(root.find(".//t:RestartOnFailure", ns))

    def test_boundary_at_exact_hour_is_still_in_future(self):
        self.assertEqual(next_hour(datetime(2026, 10, 31, 23, tzinfo=timezone.utc)),
                         datetime(2026, 11, 1, 0, tzinfo=timezone.utc))
        with self.assertRaises(ValueError):
            next_hour(datetime(2026, 10, 31, 23))

    def test_elevated_interactive_user_and_literal_executable_not_shell(self):
        root = self.build(config_path=r"C:\Lab & test\config\example.json")
        ns = {"t": TASK_NAMESPACE}
        self.assertEqual(root.findtext("t:Principals/t:Principal/t:LogonType", namespaces=ns), "InteractiveToken")
        self.assertEqual(root.findtext("t:Principals/t:Principal/t:RunLevel", namespaces=ns), "HighestAvailable")
        self.assertEqual(root.findtext("t:Actions/t:Exec/t:Command", namespaces=ns), r"C:\Lab folder\venv\Scripts\python.exe")
        arguments = root.findtext("t:Actions/t:Exec/t:Arguments", namespaces=ns)
        self.assertTrue(arguments.startswith("-I -m ransomguard snapshot-run "))
        self.assertIn('"C:\\Lab & test\\config\\example.json"', arguments)
        self.assertNotIn("cmd.exe", arguments)

    def test_reject_relative_unc_control_char_service_account_and_file_collision(self):
        for overrides in (
            {"config_path": "relative.json"},
            {"python_executable": r"\\server\share\python.exe"},
            {"python_executable": r"C:\temp\..\python.exe"},
            {"config_path": "C:\\config.json\n--unexpected"},
            {"config_path": r"C:\config.json:stream"},
            {"user_sid": "S-1-5-18"},
            {"user_sid": "administrator"},
            {"state_db": r"C:\ProgramData\RansomGuard\events.sqlite3"},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.build(**overrides)


if __name__ == "__main__":
    unittest.main()
