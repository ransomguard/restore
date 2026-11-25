"""Timeout-aware Windows named-pipe JSONL sender for the separate UI receiver.

This module never starts the UI or firewall daemon. It only writes to an
existing named pipe, with one persistent handle and bounded overlapped writes.
Duplex delivery requires a validated application-level commit ACK. The durable
sender retains queued records until that ACK; raw outbox ACKs are independent.
"""

from __future__ import annotations

import ctypes as C
import json
import os
from typing import Any

UI_PIPE = r"\\.\pipe\Ransom0_UI"
MAX_MESSAGE_BYTES = 65_536
LEGACY_BATCH_ITEMS = 20
MAX_BATCH_ITEMS = 64


def parse_commit_ack(response, allowed):
    if not isinstance(response, dict):
        raise ValueError("Invalid UI commit ACK")
    ack = response.get("ack")
    if (response.get("deliveryVersion") != 1 or not isinstance(ack, list)
            or not all(isinstance(x, str) and x in allowed for x in ack)):
        raise ValueError("Invalid UI commit ACK")
    advertised = response.get("maxBatchItems", LEGACY_BATCH_ITEMS)
    limit = min(advertised, MAX_BATCH_ITEMS) if type(advertised) is int and advertised >= LEGACY_BATCH_ITEMS else LEGACY_BATCH_ITEMS
    return ack, limit


def encode_ui_jsonl(message: dict[str, Any]) -> bytes:
    if not isinstance(message, dict):
        raise ValueError("UI message must be a JSON object")
    # JSON ASCII escapes keep arbitrary Unicode data intact even if the
    # third-party receiver decodes byte chunks independently as UTF-8.
    payload = (json.dumps(message, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ValueError("UI message exceeds the bounded pipe payload size")
    return payload


DWORD = C.c_uint32
BOOL = C.c_int32
HANDLE = C.c_void_p


class _Overlapped(C.Structure):
    _fields_ = [("Internal", C.c_size_t), ("InternalHigh", C.c_size_t),
                ("Offset", DWORD), ("OffsetHigh", DWORD), ("hEvent", HANDLE)]


class WindowsUiPipe:
    def __init__(self, path: str = UI_PIPE, *, timeout_ms: int = 150, duplex: bool = False, ack_timeout_ms: int | None = None):
        if os.name != "nt":
            raise OSError("The local UI named pipe is available only on Windows")
        if not isinstance(path, str) or not path.startswith("\\\\.\\pipe\\"):
            raise ValueError("UI destination must be a local Windows named pipe")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 2000:
            raise ValueError("timeout_ms must be between 1 and 2000")
        self.path = path
        self.duplex = duplex
        self.timeout_ms = timeout_ms
        self.ack_timeout_ms = timeout_ms if ack_timeout_ms is None else ack_timeout_ms
        if type(self.ack_timeout_ms) is not int or not 1 <= self.ack_timeout_ms <= 10_000:
            raise ValueError('ack_timeout_ms must be between 1 and 10000')
        self.handle = None
        self.peer_batch_limit = LEGACY_BATCH_ITEMS
        self.k = C.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "WaitNamedPipeW": ([C.c_wchar_p, DWORD], BOOL),
            "CreateFileW": ([C.c_wchar_p, DWORD, DWORD, C.c_void_p, DWORD, DWORD, HANDLE], HANDLE),
            "CreateEventW": ([C.c_void_p, BOOL, BOOL, C.c_wchar_p], HANDLE),
            "WriteFile": ([HANDLE, C.c_void_p, DWORD, C.POINTER(DWORD), C.POINTER(_Overlapped)], BOOL),
            "ReadFile": ([HANDLE, C.c_void_p, DWORD, C.POINTER(DWORD), C.POINTER(_Overlapped)], BOOL),
            "GetOverlappedResult": ([HANDLE, C.POINTER(_Overlapped), C.POINTER(DWORD), BOOL], BOOL),
            "WaitForSingleObject": ([HANDLE, DWORD], DWORD),
            "CancelIoEx": ([HANDLE, C.POINTER(_Overlapped)], BOOL),
            "CloseHandle": ([HANDLE], BOOL),
        }
        for name, (argtypes, restype) in signatures.items():
            fn = getattr(self.k, name)
            fn.argtypes, fn.restype = argtypes, restype

    def _connect(self) -> None:
        if self.handle is not None:
            return
        if not self.k.WaitNamedPipeW(self.path, self.timeout_ms):
            raise OSError(C.get_last_error(), "UI pipe is unavailable or busy")
        from .service_pipe import CLIENT_FLAGS, verify_peer
        access = 0xC0000000 if self.duplex else 0x40000000
        if os.environ.get("RANSOM0_SERVICE_STORAGE") == "1":
            access = 3 if self.duplex else 2
        handle = self.k.CreateFileW(self.path, access, 0, None, 3, CLIENT_FLAGS, None)
        if handle == C.c_void_p(-1).value:
            raise OSError(C.get_last_error(), "UI pipe connection failed")
        try:
            verify_peer(handle, "ui/ransom0-ui.exe")
        except OSError:
            self.k.CloseHandle(handle)
            raise
        self.handle = handle

    def send(self, message: dict[str, Any]) -> None:
        data = encode_ui_jsonl(message)
        self._connect()
        assert self.handle is not None
        event_handle = self.k.CreateEventW(None, True, False, None)
        if not event_handle:
            self.close()
            raise OSError(C.get_last_error(), "UI pipe event allocation failed")
        overlapped = _Overlapped()
        overlapped.hEvent = event_handle
        buffer = C.create_string_buffer(data)
        written = DWORD(0)
        pending = False
        failed = False
        try:
            ok = self.k.WriteFile(self.handle, buffer, len(data),
                                  C.byref(written), C.byref(overlapped))
            if not ok:
                error = C.get_last_error()
                if error != 997:  # ERROR_IO_PENDING
                    raise OSError(error, "UI pipe write failed")
                pending = True
                wait = self.k.WaitForSingleObject(event_handle, self.timeout_ms)
                if wait == 258:  # WAIT_TIMEOUT
                    raise TimeoutError("UI pipe write timed out")
                if wait != 0:
                    raise OSError(C.get_last_error(), "UI pipe wait failed")
                ok = self.k.GetOverlappedResult(self.handle, C.byref(overlapped), C.byref(written), False)
                pending = False
                if not ok:
                    raise OSError(C.get_last_error(), "UI pipe overlapped write failed")
            if written.value != len(data):
                raise OSError("UI pipe accepted a partial JSONL frame")
        except BaseException:
            failed = True
            raise
        finally:
            if pending:
                # Keep the OVERLAPPED buffer/event alive until cancellation
                # completes, including when an unexpected exception escapes.
                self.k.CancelIoEx(self.handle, C.byref(overlapped))
                self.k.GetOverlappedResult(self.handle, C.byref(overlapped), C.byref(written), True)
            if failed:
                self.close()
            self.k.CloseHandle(event_handle)

    def exchange(self, items: list[dict[str, Any]]) -> list[str]:
        """Send a bounded batch and require an application-level commit ACK."""
        import time
        if not self.duplex:
            raise ValueError("ACK requires duplex pipe")
        self.send({"deliveryVersion": 1, "items": items})
        data = bytearray()
        deadline = time.monotonic() + self.ack_timeout_ms / 1000
        try:
            while b"\n" not in data:
                if time.monotonic() >= deadline:
                    raise TimeoutError("UI commit ACK timed out")
                event = self.k.CreateEventW(None, True, False, None)
                if not event:
                    raise OSError("UI read event allocation failed")
                ov = _Overlapped(); ov.hEvent = event
                buffer = C.create_string_buffer(4096); received = DWORD(0)
                pending = False
                try:
                    ok = self.k.ReadFile(self.handle, buffer, len(buffer), C.byref(received), C.byref(ov))
                    if not ok:
                        error = C.get_last_error()
                        if error != 997:
                            raise OSError(error, "UI ACK read failed")
                        pending = True
                        wait = self.k.WaitForSingleObject(event, max(1, int((deadline-time.monotonic())*1000)))
                        if wait != 0:
                            raise TimeoutError("UI commit ACK timed out")
                        ok = self.k.GetOverlappedResult(self.handle, C.byref(ov), C.byref(received), False)
                        pending = False
                        if not ok:
                            raise OSError(C.get_last_error(), "UI ACK completion failed")
                    if not received.value:
                        raise OSError("UI closed before commit ACK")
                    data.extend(buffer.raw[:received.value])
                    if len(data) > 8192:
                        raise ValueError("Oversized UI ACK")
                finally:
                    if pending:
                        self.k.CancelIoEx(self.handle, C.byref(ov))
                        self.k.GetOverlappedResult(self.handle, C.byref(ov), C.byref(received), True)
                    self.k.CloseHandle(event)
            response = json.loads(data)
            allowed = {item["id"] for item in items}
            ack, self.peer_batch_limit = parse_commit_ack(response, allowed)
            return ack
        finally:
            # No stale/partial ACK can be attributed to the next batch.
            self.close()

    def close(self) -> None:
        if self.handle is not None:
            self.k.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self) -> "WindowsUiPipe":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
