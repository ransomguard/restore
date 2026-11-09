"""Loss-aware, best-effort mapping from kernel observations to local UI IPC.

The SQLite outbox remains the record of truth. The UI pipe has no acknowledgement,
so a successful send means only that Windows accepted the write. File events are
pre-operation *attempts*, not evidence that an encryption/write completed.
"""

from __future__ import annotations

from collections import deque
import math
import time
from typing import Any, Callable, Protocol

from .protocol import Event

JS_MAX_SAFE_INT = (1 << 53) - 1
FILETIME_UNIX_EPOCH = 116444736000000000


class UiMappingError(ValueError):
    pass


def _safe_unsigned(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= JS_MAX_SAFE_INT:
        raise UiMappingError(f"{label} cannot be represented safely in the UI")
    return value


def _filetime_as_unix_ms(value: Any, label: str, *, allow_unknown: bool = False) -> int:
    if allow_unknown and value == 0 and type(value) is int:
        return 0
    if type(value) is not int or value < FILETIME_UNIX_EPOCH:
        raise UiMappingError(f"{label} is not a valid post-1970 Windows FILETIME")
    return _safe_unsigned((value - FILETIME_UNIX_EPOCH) // 10_000, label)


def event_to_ui_message(event: Event) -> dict[str, Any]:
    """Convert v1 ABI fields to the receiver's documented JSONL schema.

    FILETIME fields become display-only Unix milliseconds, both safely within
    JavaScript's integer range. Exact kernel process generations are retained
    ONLY in the durable outbox, never reconstructed from these display values.
    """
    sequence = _safe_unsigned(event.sequence, "sequence", minimum=1)
    timestamp = _filetime_as_unix_ms(event.filetime, "event timestamp")
    pid = _safe_unsigned(event.pid, "pid")
    if event.event_type in (1, 2, 3):
        f = event.fields
        payload: dict[str, Any] = {
            "processId": pid,
            "parentProcessId": _safe_unsigned(f["parent_pid"], "parent pid"),
            "creatorProcessId": _safe_unsigned(f["creator_pid"], "creator pid"),
            "flags": _safe_unsigned(f["flags"], "process flags"),
            "processCreateTime": _filetime_as_unix_ms(
                f["process_create_time"], "process create time", allow_unknown=True),
        }
        if event.event_type == 3 and f["matched_rule_id"]:
            payload["matchedRuleId"] = _safe_unsigned(f["matched_rule_id"], "rule id")
        for source, target in (("image_path", "imagePath"), ("command_line", "commandLine")):
            if f[source]:
                payload[target] = f[source]
        name = {1: "PROCESS_CREATE", 2: "PROCESS_TERMINATE", 3: "PROCESS_BLOCKED"}[event.event_type]
    elif event.event_type in (4, 5):
        f = event.fields
        payload = {"processId": pid,
                   "operationType": _safe_unsigned(f["operation"], "file operation"),
                   "flags": _safe_unsigned(f["flags"], "file flags")}
        if f["path"]:
            payload["filePath"] = f["path"]
        if event.event_type == 5:
            # The empty string is meaningful: a rename removing the extension.
            payload["newExtension"] = f["new_extension"]
        name = "FILE_WRITE" if event.event_type == 4 else "FILE_RENAME"
    else:
        raise UiMappingError(f"Unsupported kernel event type {event.event_type}")
    return {"type": name, "timestamp": timestamp, "sequenceNumber": sequence, "data": payload}


def status_to_ui_message(status: dict[str, int], *, sequence: int = 0,
                         now_seconds: float | None = None) -> dict[str, Any]:
    """Map the real driver status; seq=0 signifies no corresponding event."""
    if not isinstance(status, dict) or status.get("magic") != 0x41525747 or status.get("version") != 0x10000:
        raise UiMappingError("Cannot forward status from an unknown driver protocol")
    if now_seconds is None:
        now_seconds = time.time()
    if isinstance(now_seconds, bool) or not isinstance(now_seconds, (float, int)) or not math.isfinite(now_seconds):
        raise UiMappingError("Invalid status timestamp")
    stamp = _safe_unsigned(int(now_seconds * 1000), "status timestamp")
    fields = {
        "engineProcessId": _safe_unsigned(status["engine_pid"], "engine pid"),
        "engineVersion": f"0x{status['version']:08X}",
        "fastPathMode": _safe_unsigned(status["fastpath_mode"], "fast path"),
        "selfProtectEnabled": bool(_safe_unsigned(status["self_protect_enabled"], "self-protect flag")),
        "queueDepth": _safe_unsigned(status["queue_depth"], "queue depth"),
        "eventsGenerated": _safe_unsigned(status["events_generated"], "events generated"),
        "eventsDropped": _safe_unsigned(status["events_dropped"], "events dropped"),
        "processesBlocked": _safe_unsigned(status["processes_blocked"], "processes blocked"),
        "processesTerminated": _safe_unsigned(status["termination_requests_succeeded"], "termination requests"),
    }
    return {"type": "SYSTEM_STATUS", "timestamp": stamp,
            "sequenceNumber": _safe_unsigned(sequence, "status sequence"), "data": fields}


def snapshot_created_to_ui_message(result: dict[str, Any], *, now_seconds: float | None = None) -> dict[str, Any]:
    """Only a verified hourly VSS creation may be displayed as BACKUP_CREATED."""
    if (not isinstance(result, dict) or result.get("status") != "created"
            or result.get("created") is not True or result.get("reason") != "vss_create_verified"):
        raise UiMappingError("Snapshot was not verified as newly created")
    snapshot = result.get("snapshot")
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("snapshot_id"), str) or not snapshot["snapshot_id"]:
        raise UiMappingError("Created snapshot identity is missing")
    root = result.get("volume_root")
    if not isinstance(root, str) or not root:
        raise UiMappingError("Created snapshot volume is missing")
    if now_seconds is None:
        now_seconds = time.time()
    if isinstance(now_seconds, bool) or not isinstance(now_seconds, (float, int)) or not math.isfinite(now_seconds):
        raise UiMappingError("Invalid snapshot event time")
    return {"type": "VSS_STATUS", "timestamp": _safe_unsigned(int(now_seconds * 1000), "snapshot timestamp"),
            "data": {"action": "BACKUP_CREATED", "targetPath": root,
                     "snapshotId": snapshot["snapshot_id"],
                     "message": "Verified hourly VSS snapshot created"}}


def live_result_to_ui_messages(result: Any, *, protected_root: str,
                               observed_path: str = "", now_seconds: float | None = None) -> list[dict[str, Any]]:
    """Only map validated JEV/exit/recovery results, not speculative alerts.

    No QUARANTINED alert is sent merely because the firewall daemon reported
    active: that acknowledgement is NOT proof of packet-level enforcement.
    """
    if now_seconds is None:
        now_seconds = time.time()
    if not isinstance(now_seconds, (int, float)) or isinstance(now_seconds, bool) or not math.isfinite(now_seconds):
        raise UiMappingError("Invalid response timestamp")
    stamp = _safe_unsigned(int(now_seconds * 1000), "response timestamp")
    messages = []
    blocked = (result.jev_classification == "malicious" and
               result.kernel_termination_accepted and result.exit_confirmed)
    track_a_blocked = (result.track == "A" and result.kernel_termination_accepted and
                       result.exit_confirmed)
    allowed = result.jev_classification == "benign" and result.state == "RELEASED"
    if track_a_blocked or (result.track == "B" and result.jev_score is not None and (blocked or allowed)):
        score = 1.0 if track_a_blocked else result.jev_score
        if not isinstance(score, (int, float)) or isinstance(score, bool) or not math.isfinite(score) or not 0 <= score <= 1:
            raise UiMappingError("Invalid JEV score for UI")
        data = {"processId": _safe_unsigned(result.process.pid, "response pid"),
                "processName": f"PID_{result.process.pid}",
                "action": "BLOCKED" if blocked or track_a_blocked else "ALLOWED",
                "eventId": result.incident_id, "threatScore": round(score * 100, 2),
                "ruleName": ("TRACK_A_OPERATOR_CONFIRMED" if track_a_blocked else
                             "TRACK_B_JEV_DEMO_UNCALIBRATED")}
        if observed_path:
            data["filePath"] = observed_path[:1024]
        messages.append({"type": "ALERT", "timestamp": stamp, "data": data})
    if result.recovery_snapshot_id:
        if result.recovery_verified:
            action, message = "RESTORE_COMPLETED", "Explicit VSS manifest files verified; full-system health unverified"
        elif result.reason in ("restore_operation_failed", "restore_not_verified"):
            action, message = "RESTORE_FAILED", "VSS manifest restore incomplete; operator review required"
        else:
            action = message = None
        if action:
            messages.append({"type": "VSS_STATUS", "timestamp": stamp,
                             "data": {"action": action, "targetPath": protected_root,
                                      "snapshotId": result.recovery_snapshot_id, "message": message}})
    return messages


class MessageSink(Protocol):
    def send(self, message: dict[str, Any]) -> None: ...


class UiBestEffortPublisher:
    """Bounded-rate UI fanout. Never queues messages or triggers an OS action.

    A missing/busy UI disables writes temporarily; all original events are
    already persisted by the caller. Process events bypass file rate limits.
    """

    def __init__(self, sink: MessageSink, *, file_rate: int = 10, retry_seconds: float = 3.0,
                 clock: Callable[[], float] = time.monotonic):
        if type(file_rate) is not int or not 1 <= file_rate <= 100:
            raise ValueError("file_rate must be an integer between 1 and 100")
        if isinstance(retry_seconds, bool) or not isinstance(retry_seconds, (int, float)) or not math.isfinite(retry_seconds) or retry_seconds <= 0:
            raise ValueError("retry_seconds must be positive and finite")
        self.sink = sink
        self.file_rate = file_rate
        self.retry_seconds = float(retry_seconds)
        self.clock = clock
        self._file_sent_at: deque[float] = deque()
        self._offline_until = -math.inf
        self.counters = {"sent": 0, "rate_limited": 0, "offline_skipped": 0,
                         "send_failed": 0, "invalid_message": 0}

    def _send(self, message: dict[str, Any], *, is_file: bool) -> str:
        now = self.clock()
        if is_file:
            while self._file_sent_at and self._file_sent_at[0] <= now - 1.0:
                self._file_sent_at.popleft()
            if len(self._file_sent_at) >= self.file_rate:
                self.counters["rate_limited"] += 1
                return "rate_limited"
        if now < self._offline_until:
            self.counters["offline_skipped"] += 1
            return "offline_skipped"
        try:
            self.sink.send(message)
        except ValueError:
            # A malformed or oversized UI frame must not end kernel intake.
            self.counters["invalid_message"] += 1
            return "invalid_message"
        except (OSError, TimeoutError):
            self._offline_until = now + self.retry_seconds
            self.counters["send_failed"] += 1
            return "send_failed"
        self.counters["sent"] += 1
        if is_file:
            self._file_sent_at.append(now)
        return "sent"

    def publish_event(self, event: Event) -> str:
        try:
            message = event_to_ui_message(event)
        except (UiMappingError, KeyError, TypeError):
            self.counters["invalid_message"] += 1
            return "invalid_message"
        return self._send(message, is_file=event.event_type in (4, 5))

    def publish_status(self, status: dict[str, int], *, sequence: int = 0) -> str:
        try:
            message = status_to_ui_message(status, sequence=sequence)
        except (UiMappingError, KeyError, TypeError):
            self.counters["invalid_message"] += 1
            return "invalid_message"
        return self._send(message, is_file=False)

    def publish_snapshot_created(self, result: dict[str, Any]) -> str:
        try:
            message = snapshot_created_to_ui_message(result)
        except (UiMappingError, KeyError, TypeError):
            self.counters["invalid_message"] += 1
            return "invalid_message"
        return self._send(message, is_file=False)

    def publish_live_result(self, result: Any, *, protected_root: str, observed_path: str = "") -> list[str]:
        try:
            messages = live_result_to_ui_messages(result, protected_root=protected_root,
                                                  observed_path=observed_path)
        except (UiMappingError, AttributeError, TypeError, ValueError):
            self.counters["invalid_message"] += 1
            return ["invalid_message"]
        return [self._send(message, is_file=False) for message in messages]

    def diagnostics(self) -> dict[str, int]:
        return dict(self.counters)
