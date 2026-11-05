from __future__ import annotations

import json
import unittest

from ransomguard.protocol import Event, FILE_FLAG_HIGH_ENTROPY, FILE_FLAG_PREOP_OBSERVATION
from ransomguard.incidents import ProcessInstance
from ransomguard.live_response import ResponseResult
from ransomguard.ui_bridge import (JS_MAX_SAFE_INT, UiBestEffortPublisher, UiMappingError,
                                    event_to_ui_message, snapshot_created_to_ui_message,
                                    status_to_ui_message, live_result_to_ui_messages)
from ransomguard.ui_pipe import encode_ui_jsonl


FILETIME = 134000000000000000


def process_event(kind: int = 1, sequence: int = 100) -> Event:
    return Event(kind, "process", sequence, FILETIME, 3256,
                 {"parent_pid": 777, "creator_pid": 777, "flags": 1,
                  "process_create_time": FILETIME + 12345, "matched_rule_id": 1001,
                  "image_path": r"C:\Lab\검증.exe", "command_line": "echo harmless"})


def file_event(kind: int = 4, sequence: int = 200, *, new_extension: str = "") -> Event:
    return Event(kind, "file", sequence, FILETIME + 23456, 3256,
                 {"operation": kind - 3, "flags": FILE_FLAG_HIGH_ENTROPY | FILE_FLAG_PREOP_OBSERVATION,
                  "path": r"\Device\HarddiskVolume3\Lab\보고서.txt", "new_extension": new_extension})


def status() -> dict[str, int]:
    return {"magic": 0x41525747, "version": 0x10000, "engine_pid": 500,
            "fastpath_mode": 1, "self_protect_enabled": 0, "queue_depth": 4,
            "events_generated": 123, "events_dropped": 2, "processes_blocked": 3,
            "termination_requests_succeeded": 1}


class MockSink:
    def __init__(self):
        self.messages = []
        self.offline = False

    def send(self, message):
        if self.offline:
            raise OSError("UI not listening")
        self.messages.append(message)


class UiBridgeTests(unittest.TestCase):
    def test_process_events_map_without_losing_generation_precision_in_outbox(self):
        for kind, expected in ((1, "PROCESS_CREATE"), (2, "PROCESS_TERMINATE"),
                               (3, "PROCESS_BLOCKED")):
            with self.subTest(kind=kind):
                event = process_event(kind)
                message = event_to_ui_message(event)
                self.assertEqual(message["type"], expected)
                self.assertEqual(message["timestamp"], (FILETIME - 116444736000000000) // 10000)
                self.assertEqual(message["data"]["processCreateTime"],
                                 (FILETIME + 12345 - 116444736000000000) // 10000)
                self.assertEqual(message["data"]["imagePath"], r"C:\Lab\검증.exe")
                self.assertEqual(message["data"].get("matchedRuleId"), 1001 if kind == 3 else None)
                self.assertEqual(event.fields["process_create_time"], FILETIME + 12345)

    def test_blocked_before_process_creation_allows_unknown_create_time(self):
        event = process_event(3)
        event.fields["process_create_time"] = 0
        message = event_to_ui_message(event)
        self.assertEqual(message["data"]["processCreateTime"], 0)

    def test_file_event_rename_empty_extension_is_not_silently_omitted(self):
        rename = event_to_ui_message(file_event(5, new_extension=""))
        self.assertEqual(rename["type"], "FILE_RENAME")
        self.assertIn("newExtension", rename["data"])
        self.assertEqual(rename["data"]["newExtension"], "")
        write = event_to_ui_message(file_event(4))
        self.assertEqual(write["type"], "FILE_WRITE")
        self.assertNotIn("newExtension", write["data"])
        self.assertEqual(write["data"]["operationType"], 1)

    def test_preserves_unicode_with_ascii_jsonl_framing(self):
        message = event_to_ui_message(file_event())
        data = encode_ui_jsonl(message)
        self.assertEqual(data.count(b"\n"), 1)
        self.assertEqual(data[-1:], b"\n")
        self.assertTrue(data.isascii())
        self.assertEqual(json.loads(data.decode("utf-8")), message)
        self.assertEqual(json.loads(data)["data"]["filePath"], r"\Device\HarddiskVolume3\Lab\보고서.txt")

    def test_rejects_unsafe_sequence_and_malformed_filetime(self):
        with self.assertRaises(UiMappingError):
            event_to_ui_message(process_event(sequence=JS_MAX_SAFE_INT + 1))
        with self.assertRaises(UiMappingError):
            event_to_ui_message(Event(1, "process", 1, 0, 3256, process_event().fields))
        with self.assertRaises(UiMappingError):
            event_to_ui_message(Event(1, "process", 1, FILETIME, 3256,
                                      {**process_event().fields, "process_create_time": 123456}))

    def test_real_status_mapping_and_exact_snapshot_verified_only(self):
        msg = status_to_ui_message(status(), sequence=42, now_seconds=1700000000)
        self.assertEqual(msg["type"], "SYSTEM_STATUS")
        self.assertEqual(msg["sequenceNumber"], 42)
        self.assertEqual(msg["data"]["processesTerminated"], 1)
        self.assertEqual(msg["timestamp"], 1700000000000)
        result = {"status": "created", "created": True, "reason": "vss_create_verified",
                  "volume_root": "C:\\", "snapshot": {"snapshot_id": "{aa-bb}"}}
        created = snapshot_created_to_ui_message(result, now_seconds=1700000000)
        self.assertEqual(created["type"], "VSS_STATUS")
        self.assertEqual(created["data"]["action"], "BACKUP_CREATED")
        for invalid in ({**result, "status": "skipped"}, {**result, "reason": "unknown"},
                        {**result, "snapshot": None}):
            with self.assertRaises(UiMappingError):
                snapshot_created_to_ui_message(invalid)

    def test_bounded_file_rate_and_offline_backoff_preserve_process_priority(self):
        sink = MockSink()
        now = [10.0]
        ui = UiBestEffortPublisher(sink, file_rate=2, retry_seconds=2.0, clock=lambda: now[0])
        self.assertEqual(ui.publish_event(file_event(sequence=1)), "sent")
        self.assertEqual(ui.publish_event(file_event(sequence=2)), "sent")
        self.assertEqual(ui.publish_event(file_event(sequence=3)), "rate_limited")
        self.assertEqual(ui.publish_event(process_event(sequence=4)), "sent")
        sink.offline = True
        self.assertEqual(ui.publish_event(process_event(sequence=5)), "send_failed")
        self.assertEqual(ui.publish_event(process_event(sequence=6)), "offline_skipped")
        now[0] = 13.0
        sink.offline = False
        self.assertEqual(ui.publish_event(file_event(sequence=7)), "sent")
        self.assertEqual(ui.diagnostics()["sent"], 4)
        self.assertEqual(ui.diagnostics()["rate_limited"], 1)
        self.assertEqual(ui.diagnostics()["send_failed"], 1)

    def test_invalid_or_oversized_sink_frame_does_not_interrupt_observation(self):
        class TooLargeSink:
            def send(self, message):
                raise ValueError("message too large")

        publisher = UiBestEffortPublisher(TooLargeSink())
        self.assertEqual(publisher.publish_event(process_event()), "invalid_message")
        self.assertEqual(publisher.diagnostics()["invalid_message"], 1)

    def test_live_jev_and_verified_recovery_generate_receiver_compatible_messages(self):
        item = ResponseResult("test-incident-id", "B", ProcessInstance(4004, FILETIME))
        item.jev_score = 0.92
        item.jev_classification = "malicious"
        item.exit_confirmed = True
        item.kernel_termination_accepted = True
        item.recovery_verified = True
        item.recovery_snapshot_id = "{00000000-0000-0000-0000-000000000001}"
        item.state = "RELEASED"
        messages = live_result_to_ui_messages(item, protected_root=r"C:\Protected", now_seconds=1700000000)
        self.assertEqual([x["type"] for x in messages], ["ALERT", "VSS_STATUS"])
        self.assertEqual(messages[0]["data"]["action"], "BLOCKED")
        self.assertEqual(messages[0]["data"]["threatScore"], 92)
        self.assertEqual(messages[1]["data"]["action"], "RESTORE_COMPLETED")
        sink = MockSink()
        self.assertEqual(UiBestEffortPublisher(sink).publish_live_result(
            item, protected_root=r"C:\Protected"), ["sent", "sent"])

    def test_firewall_ack_alone_never_emits_false_quarantine_alert(self):
        item = ResponseResult("test-id", "B", ProcessInstance(4004, FILETIME))
        item.firewall_policy_acknowledged = True
        item.firewall_hold_retained = True
        item.state = "REVIEW_REQUIRED"
        self.assertEqual(live_result_to_ui_messages(item, protected_root=r"C:\Protected"), [])
        item.jev_score = 0.5
        item.jev_classification = "ambiguous"
        self.assertEqual(live_result_to_ui_messages(item, protected_root=r"C:\Protected"), [])

    def test_track_a_alert_requires_kernel_accepted_termination_and_confirmed_exit(self):
        item = ResponseResult("track-a-id", "A", ProcessInstance(4004, FILETIME))
        item.state = "RELEASED"
        self.assertEqual(live_result_to_ui_messages(item, protected_root=r"C:\Protected"), [])
        item.exit_confirmed = True
        self.assertEqual(live_result_to_ui_messages(item, protected_root=r"C:\Protected"), [])
        item.kernel_termination_accepted = True
        messages = live_result_to_ui_messages(item, protected_root=r"C:\Protected")
        self.assertEqual(messages[0]["data"]["action"], "BLOCKED")
        self.assertEqual(messages[0]["data"]["ruleName"], "TRACK_A_OPERATOR_CONFIRMED")


if __name__ == "__main__":
    unittest.main()
