"""Decode the Windows ABI in knel/Shared/Common.h, independent of host wchar size.

All strings are UTF-16LE and all length fields count bytes. File records describe
attempted pre-operation I/O, not confirmed completed writes/renames.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import struct
from typing import Any

MAGIC = 0x41525747
VERSION = 0x00010000
HEADER_SIZE = 32
PROCESS_SIZE = 1616
FILE_SIZE = 2232
MAX_EVENT_SIZE = FILE_SIZE
DEVICE_PATH = r"\\.\RansomGuard"

EVENT_NAMES = {1: "process_created", 2: "process_exited", 3: "process_creation_blocked",
               4: "file_write_attempted", 5: "file_rename_attempted"}
FILE_FLAG_HIGH_ENTROPY = 1 << 3
FILE_FLAG_PREOP_OBSERVATION = 1 << 4
FILE_FLAG_EXT_UNAVAILABLE = 1 << 5
FILE_FLAG_FAST_IO = 1 << 6


def ctl_code(function: int, access: int) -> int:
    return (0x8123 << 16) | (access << 14) | (function << 2)


REGISTER_ENGINE = ctl_code(0x800, 2)
UNREGISTER_ENGINE = ctl_code(0x801, 2)
TERMINATE_PROCESS = ctl_code(0x802, 2)
UPDATE_POLICY = ctl_code(0x803, 2)
SET_INTERNAL_STORAGE = ctl_code(0x807, 2)
GET_INTAKE_STATUS = ctl_code(0x808, 1)
GET_STATUS = ctl_code(0x804, 1)
GET_EVENT = ctl_code(0x805, 1)
GET_EVENT_BATCH = ctl_code(0x809, 1)
GET_QUEUE_STATS = ctl_code(0x80A, 1)
EVENT_BATCH_LIMIT = 32
EVENT_BATCH_BYTES = 16 + EVENT_BATCH_LIMIT * MAX_EVENT_SIZE


class ProtocolError(ValueError):
    pass


def split_event_batch(raw: bytes) -> list[bytes]:
    """Validate the complete bounded packet before exposing any record."""
    if len(raw) < 16 or len(raw) > EVENT_BATCH_BYTES:
        raise ProtocolError('Invalid event batch length')
    magic, version, count, length = struct.unpack_from('<IIII', raw)
    if (magic, version) != (MAGIC, VERSION) or length != len(raw) or not 1 <= count <= EVENT_BATCH_LIMIT:
        raise ProtocolError('Invalid event batch header')
    records = []
    offset = 16
    for _ in range(count):
        if offset + HEADER_SIZE > len(raw):
            raise ProtocolError('Truncated event batch record')
        event_magic, event_version, _, size = struct.unpack_from('<IIII', raw, offset)
        if (event_magic, event_version) != (MAGIC, VERSION) or not HEADER_SIZE <= size <= MAX_EVENT_SIZE or offset + size > len(raw):
            raise ProtocolError('Invalid event batch record')
        records.append(raw[offset:offset + size]);offset += size
    if offset != len(raw):
        raise ProtocolError('Trailing event batch bytes')
    return records


@dataclass(frozen=True)
class Event:
    event_type: int
    kind: str
    sequence: int
    filetime: int
    pid: int
    fields: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _text(raw: bytes, start: int, length: int, capacity: int) -> str:
    if length < 0 or length > capacity or length % 2:
        raise ProtocolError("Invalid UTF-16 byte length")
    try:
        value = raw[start:start + length].decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolError("Invalid UTF-16 content") from exc
    if "\0" in value:
        raise ProtocolError("Embedded NUL in a length-delimited field")
    return value


def decode_event(raw: bytes) -> Event:
    if len(raw) < HEADER_SIZE:
        raise ProtocolError("Truncated event header")
    magic, version, kind, size, timestamp, sequence = struct.unpack_from("<IIIIQQ", raw)
    if magic != MAGIC or version != VERSION:
        raise ProtocolError("Unknown driver magic or protocol version")
    expected = PROCESS_SIZE if kind in (1, 2, 3) else FILE_SIZE if kind in (4, 5) else None
    if expected is None:
        raise ProtocolError(f"Unknown event type: {kind}")
    if size != expected or len(raw) != size:
        raise ProtocolError("PayloadSize, event type and returned byte count disagree")
    if kind in (1, 2, 3):
        pid, parent, creator, flags, created, rule, path_len, cmd_len, reserved = struct.unpack_from(
            "<IIIIqIIII", raw, HEADER_SIZE)
        fields = {"parent_pid": parent, "creator_pid": creator, "flags": flags,
                  "process_create_time": created, "matched_rule_id": rule,
                  "image_path": _text(raw, 72, path_len, 520),
                  "command_line": _text(raw, 592, cmd_len, 1024)}
    else:
        pid, operation, path_len, ext_len, flags, reserved = struct.unpack_from("<IIIIII", raw, HEADER_SIZE)
        if operation != kind - 3:
            raise ProtocolError("File operation and event type disagree")
        if kind == 4 and ext_len:
            raise ProtocolError("Write event unexpectedly contains a rename extension")
        fields = {"operation": operation, "flags": flags,
                  "path": _text(raw, 56, path_len, 2048),
                  "new_extension": _text(raw, 2104, ext_len, 128),
                  "high_entropy_observed": bool(flags & FILE_FLAG_HIGH_ENTROPY),
                  "fast_io_attempt": bool(flags & FILE_FLAG_FAST_IO),
                  "extension_available": not bool(flags & FILE_FLAG_EXT_UNAVAILABLE),
                  "operation_result": "unknown_pre_operation"}
    return Event(kind, EVENT_NAMES[kind], sequence, timestamp, pid, fields)


def filetime_to_iso(value: int) -> str:
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)).isoformat()
    except (OverflowError, ValueError) as exc:
        raise ProtocolError("FILETIME outside supported date range") from exc


class ProcessRegistry:
    """Best-effort correlation; clears cached identities on sequence anomalies.

    A response executor must additionally validate a live process handle. A file
    event itself has no generation field in protocol v1, so registry correlation
    alone is not sufficient authorization for destructive action.
    A drop before sequence allocation is invisible here, and concurrent producers
    can deliver out of sequence. A false loss_detected value does not prove that
    all process lifetime events were received; consult driver counters as well.
    """

    def __init__(self) -> None:
        self._entries: dict[int, int] = {}
        self._last_sequence: int | None = None
        self.loss_detected = False

    def invalidate(self) -> None:
        """Discard all correlatable identities on malformed data or observed loss."""
        self._entries.clear()
        self._last_sequence = None
        self.loss_detected = True

    def update(self, event: Event) -> None:
        if self._last_sequence is not None and event.sequence != self._last_sequence + 1:
            self._entries.clear()
            self.loss_detected = True
        self._last_sequence = event.sequence
        generation = event.fields.get("process_create_time", 0)
        if event.event_type == 1 and generation > 0:
            self._entries[event.pid] = generation
        elif event.event_type in (2, 3):
            if self._entries.get(event.pid) == generation:
                self._entries.pop(event.pid, None)

    def generation_for(self, pid: int) -> int | None:
        return self._entries.get(pid)

    def generation_for_event(self, event: Event) -> int | None:
        """Reject evidence timestamped before the cached process was born.

        FIFO sequence numbers are assigned on insertion, not when producers
        first capture an event. This is an additional conservative check, not
        a replacement for a generation field in a future file-event ABI.
        Wall-clock rollback can cause a safe false negative here.
        """
        generation = self.generation_for(event.pid)
        if self.loss_detected or generation is None or event.filetime < generation:
            return None
        return generation
