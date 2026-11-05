"""Client for the EXISTING Ransom0 Firewall Manager daemon.

The external daemon is independently owned. This module neither installs nor
starts it, and never changes its source. Each command opens a fresh local named
pipe, writes one compact JSON object (NO newline), reads one JSON+LF response,
then closes. The daemon reads at most 4095 request bytes in one ReadFile call.

An ``active`` response reports daemon policy state, NOT independently verified
WFP enforcement. Current daemon limitations (outbound-only, DNS/53 permit, and
global allowlist) are explicitly outside this client's contract.
"""

from __future__ import annotations

import ctypes as C
import json
import os
import time
from typing import Any, Callable

FIREWALL_PIPE = r"\\.\pipe\Ransom0_Firewall"
MAX_REQUEST_BYTES = 4095
MAX_RESPONSE_BYTES = 65_536
_ACTIONS = frozenset({"on", "off", "get", "set", "refresh"})


class FirewallIpcError(RuntimeError):
    """Unable to obtain a validated acknowledgement from the daemon."""


class FirewallProtocolError(FirewallIpcError):
    """The external daemon returned a malformed or contradictory response."""


def encode_firewall_request(action: str, *, whitelist: list[str] | None = None) -> bytes:
    if type(action) is not str or action not in _ACTIONS:
        raise ValueError("Unknown firewall IPC action")
    if whitelist is not None:
        if action not in ("on", "set"):
            raise ValueError("Only on/set may replace the firewall whitelist")
        if not isinstance(whitelist, list) or len(whitelist) > 32 or any(
            not isinstance(value, str) or not value or len(value) > 500
            or any(ord(ch) < 33 or ch.isspace() for ch in value)
            for value in whitelist
        ):
            raise ValueError("Whitelist must contain at most 32 nonempty safe targets")
        if len(set(whitelist)) != len(whitelist):
            raise ValueError("Duplicate whitelist targets")
    data: dict[str, Any] = {"action": action}
    if whitelist is not None:
        data["whitelist"] = whitelist
    encoded = json.dumps(data, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_REQUEST_BYTES:
        raise ValueError("Firewall request exceeds the daemon's single-read capacity")
    return encoded


def decode_firewall_response(raw: bytes, *, action: str,
                             requested_whitelist: list[str] | None = None) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES or not raw.endswith(b"\n"):
        raise FirewallProtocolError("Firewall response must end in one bounded newline frame")
    if raw.count(b"\n") != 1:
        raise FirewallProtocolError("Unexpected multiple firewall response frames")
    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON response key")
            result[key] = value
        return result

    def reject_nonfinite(_value: str) -> None:
        raise ValueError("Non-finite JSON response number")

    try:
        response = json.loads(raw[:-1].decode("utf-8", errors="strict"),
                              object_pairs_hook=unique_keys, parse_constant=reject_nonfinite)
    except (UnicodeError, ValueError):
        raise FirewallProtocolError("Firewall response is not valid UTF-8 JSON") from None
    if not isinstance(response, dict) or type(response.get("success")) is not bool:
        raise FirewallProtocolError("Firewall response has no boolean success result")
    if response.get("action") is not None and response["action"] != action:
        raise FirewallProtocolError("Firewall response action mismatch")
    if response["success"] is False:
        # Avoid echoing untrusted daemon error text; it may contain request data.
        raise FirewallIpcError(f"Firewall daemon rejected action {action}")
    if response.get("action") != action:
        raise FirewallProtocolError("Successful firewall response has no matching action")
    if type(response.get("active")) is not bool:
        raise FirewallProtocolError("Firewall response lacks a boolean active state")
    if action == "on" and response["active"] is not True:
        raise FirewallProtocolError("Firewall on response did not acknowledge active state")
    if action == "off" and response["active"] is not False:
        raise FirewallProtocolError("Firewall off response did not acknowledge disabled state")
    if action in ("get", "on", "set", "refresh"):
        items = response.get("whitelist")
        if not isinstance(items, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("value"), str)
            or item.get("type") not in {"ipv4", "ipv6", "domain", "url", "port"}
            or not isinstance(item.get("data"), dict)
            for item in items
        ):
            raise FirewallProtocolError("Firewall response contains an invalid whitelist")
        if requested_whitelist is not None:
            values = [item["value"] for item in items]
            if set(values) != set(requested_whitelist) or len(values) != len(requested_whitelist):
                raise FirewallProtocolError("Daemon did not acknowledge the complete requested whitelist")
    return response


DWORD = C.c_uint32
BOOL = C.c_int32
HANDLE = C.c_void_p


class _Overlapped(C.Structure):
    _fields_ = [("Internal", C.c_size_t), ("InternalHigh", C.c_size_t),
                ("Offset", DWORD), ("OffsetHigh", DWORD), ("hEvent", HANDLE)]


class _WindowsPipeExchange:
    """Per-request duplex pipe with overlapped I/O and cancellation draining.

    The caller passes a total deadline. Windows cancellation may itself take
    longer if a broken driver refuses to complete outstanding I/O; retaining
    C buffers until cancellation completes is necessary for memory safety.
    """

    def __init__(self, path: str = FIREWALL_PIPE) -> None:
        if os.name != "nt":
            raise OSError("Firewall IPC requires Windows")
        if path != FIREWALL_PIPE:
            raise ValueError("Firewall IPC must use the known local daemon pipe")
        self.path = path
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

    @staticmethod
    def _remaining_ms(deadline: float) -> int:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Firewall IPC operation deadline exceeded")
        return max(1, min(60_000, int(remaining * 1000)))

    def _transfer(self, handle: int, data: bytes | None, size: int, deadline: float) -> bytes | int:
        event = self.k.CreateEventW(None, True, False, None)
        if not event:
            raise OSError(C.get_last_error(), "Firewall IPC event allocation failed")
        overlap = _Overlapped()
        overlap.hEvent = event
        buffer = C.create_string_buffer(data) if data is not None else C.create_string_buffer(size)
        done = DWORD(0)
        pending = False
        try:
            function = self.k.WriteFile if data is not None else self.k.ReadFile
            ok = function(handle, buffer, len(data) if data is not None else size,
                          C.byref(done), C.byref(overlap))
            if not ok:
                code = C.get_last_error()
                if code != 997:  # ERROR_IO_PENDING
                    raise OSError(code, "Firewall IPC pipe I/O failed")
                pending = True
                wait = self.k.WaitForSingleObject(event, self._remaining_ms(deadline))
                if wait == 258:
                    raise TimeoutError("Firewall IPC read/write timed out")
                if wait != 0:
                    raise OSError(C.get_last_error(), "Firewall IPC wait failed")
                ok = self.k.GetOverlappedResult(handle, C.byref(overlap), C.byref(done), False)
                pending = False
                if not ok:
                    raise OSError(C.get_last_error(), "Firewall IPC overlapped I/O failed")
            if done.value > (len(data) if data is not None else size):
                raise FirewallProtocolError("Firewall IPC transferred beyond supplied buffer")
            return done.value if data is not None else buffer.raw[:done.value]
        finally:
            if pending:
                self.k.CancelIoEx(handle, C.byref(overlap))
                self.k.GetOverlappedResult(handle, C.byref(overlap), C.byref(done), True)
            self.k.CloseHandle(event)

    def __call__(self, request: bytes, timeout_ms: int) -> bytes:
        deadline = time.monotonic() + timeout_ms / 1000.0
        if not self.k.WaitNamedPipeW(self.path, self._remaining_ms(deadline)):
            raise OSError(C.get_last_error(), "Firewall daemon pipe unavailable")
        handle = self.k.CreateFileW(self.path, 0xC0000000, 0, None, 3, 0x40000000, None)
        if handle == C.c_void_p(-1).value:
            raise OSError(C.get_last_error(), "Firewall daemon connection failed")
        try:
            written = self._transfer(handle, request, 0, deadline)
            if written != len(request):
                raise FirewallProtocolError("Firewall daemon request was not fully written")
            response = bytearray()
            while True:
                self._remaining_ms(deadline)
                chunk = self._transfer(handle, None, min(4096, MAX_RESPONSE_BYTES + 1 - len(response)), deadline)
                assert isinstance(chunk, bytes)
                if not chunk:
                    raise FirewallProtocolError("Firewall daemon closed before the complete response")
                response.extend(chunk)
                if len(response) > MAX_RESPONSE_BYTES:
                    raise FirewallProtocolError("Firewall response exceeded the size limit")
                if b"\n" in chunk:
                    return bytes(response)
        finally:
            self.k.CloseHandle(handle)


class FirewallIpcClient:
    """Validated request/response API. A transport seam enables offline tests."""

    def __init__(self, *, timeout_ms: int = 3000,
                 transport: Callable[[bytes, int], bytes] | None = None) -> None:
        if type(timeout_ms) is not int or not 100 <= timeout_ms <= 30_000:
            raise ValueError("Firewall IPC timeout must be 100..30000 ms")
        self.timeout_ms = timeout_ms
        self._transport = transport

    def request(self, action: str, *, whitelist: list[str] | None = None) -> dict[str, Any]:
        payload = encode_firewall_request(action, whitelist=whitelist)
        transport = self._transport or _WindowsPipeExchange()
        try:
            response = transport(payload, self.timeout_ms)
        except (OSError, TimeoutError, FirewallIpcError):
            raise
        except Exception:
            raise FirewallIpcError("Unexpected firewall pipe transport failure") from None
        return decode_firewall_response(response, action=action, requested_whitelist=whitelist)
