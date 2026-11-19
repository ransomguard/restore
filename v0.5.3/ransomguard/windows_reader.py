"""Windows IOCTL client with timed initial waits and cancellation draining.

The ordinary observation loop does not issue termination, file-containment or
network-policy commands. A separately callable, explicit terminate_checked()
IPC method is available to a future authorized response coordinator; there is
no automatic call site and no CLI kill command in this release.
Cancellation must finish before OVERLAPPED buffers can be released. A broken
driver can therefore exceed the initial timeout; it is not an overall deadline.
"""

from __future__ import annotations

import ctypes as C
import os
import struct
from typing import Any

from .protocol import (DEVICE_PATH, GET_EVENT, GET_STATUS, MAGIC, MAX_EVENT_SIZE,
                       REGISTER_ENGINE, TERMINATE_PROCESS, UNREGISTER_ENGINE, VERSION,
                       SET_INTERNAL_STORAGE, GET_INTAKE_STATUS, GET_EVENT_BATCH,
                       GET_QUEUE_STATS, EVENT_BATCH_BYTES, split_event_batch)

DWORD = C.c_uint32
BOOL = C.c_int32
HANDLE = C.c_void_p
ULONG_PTR = C.c_size_t


class OVERLAPPED(C.Structure):
    _fields_ = [("Internal", ULONG_PTR), ("InternalHigh", ULONG_PTR),
                ("Offset", DWORD), ("OffsetHigh", DWORD), ("hEvent", HANDLE)]


class WindowsDriverReader:
    def __init__(self, device_path: str = DEVICE_PATH):
        if os.name != "nt":
            raise OSError("Driver observation requires Windows")
        self.k = C.WinDLL("kernel32", use_last_error=True)
        self._configure()
        self.handle = None
        self.registered = False
        self.batch_supported = None
        self.native_read = None
        self.native_read_seconds = 0.0
        self.native_read_calls = 0
        from pathlib import Path
        native_path = Path(__file__).resolve().parent.parent / 'native' / 'rg_intake.dll'
        if native_path.is_file():
            self.native_library = C.CDLL(str(native_path))
            self.native_read = self.native_library.RgReadBatch
            self.native_read.argtypes = [HANDLE, DWORD, C.c_void_p, DWORD, DWORD,
                                        C.POINTER(DWORD), C.POINTER(C.c_double)]
            self.native_read.restype = DWORD
        handle = self.k.CreateFileW(device_path, 0xC0000000, 0, None, 3, 0x40000000, None)
        if handle == C.c_void_p(-1).value:
            raise C.WinError(C.get_last_error())
        self.handle = handle
        try:
            self._ioctl(REGISTER_ENGINE, struct.pack("<II", MAGIC, VERSION), 0, 5000)
            self.registered = True
        except BaseException:
            self.k.CloseHandle(self.handle)
            self.handle = None
            raise

    def _configure(self) -> None:
        api = self.k
        signatures = {
            "CreateFileW": ([C.c_wchar_p, DWORD, DWORD, C.c_void_p, DWORD, DWORD, HANDLE], HANDLE),
            "CreateEventW": ([C.c_void_p, BOOL, BOOL, C.c_wchar_p], HANDLE),
            "DeviceIoControl": ([HANDLE, DWORD, C.c_void_p, DWORD, C.c_void_p, DWORD,
                                 C.POINTER(DWORD), C.POINTER(OVERLAPPED)], BOOL),
            "GetOverlappedResult": ([HANDLE, C.POINTER(OVERLAPPED), C.POINTER(DWORD), BOOL], BOOL),
            "WaitForSingleObject": ([HANDLE, DWORD], DWORD),
            "CancelIoEx": ([HANDLE, C.POINTER(OVERLAPPED)], BOOL),
            "CloseHandle": ([HANDLE], BOOL),
        }
        for name, (argtypes, restype) in signatures.items():
            function = getattr(api, name)
            function.argtypes = argtypes
            function.restype = restype

    def _ioctl(self, code: int, data: bytes, output_size: int, timeout_ms: int) -> bytes | None:
        if self.handle is None:
            raise RuntimeError("Driver handle is closed")
        event_handle = self.k.CreateEventW(None, True, False, None)
        if not event_handle:
            raise C.WinError(C.get_last_error())
        overlap = OVERLAPPED()
        overlap.hEvent = event_handle
        incoming = C.create_string_buffer(data) if data else None
        outgoing = C.create_string_buffer(output_size) if output_size else None
        returned = DWORD(0)
        pending = False
        try:
            ok = self.k.DeviceIoControl(self.handle, code, incoming, len(data), outgoing, output_size,
                                        C.byref(returned), C.byref(overlap))
            if not ok:
                error = C.get_last_error()
                if error != 997:  # ERROR_IO_PENDING
                    raise C.WinError(error)
                pending = True
                wait = self.k.WaitForSingleObject(event_handle, timeout_ms)
                if wait == 258:  # WAIT_TIMEOUT: cancel this exact request only.
                    cancelled = self.k.CancelIoEx(self.handle, C.byref(overlap))
                    cancel_error = C.get_last_error() if not cancelled else 0
                    if cancel_error not in (0, 1168):  # already completed is a valid race
                        raise C.WinError(cancel_error)
                    # Cancellation is asynchronous; retain all buffers until completion.
                    self.k.WaitForSingleObject(event_handle, 0xFFFFFFFF)
                elif wait != 0:
                    raise C.WinError(C.get_last_error())
                ok = self.k.GetOverlappedResult(self.handle, C.byref(overlap), C.byref(returned), False)
                pending = False
                if not ok:
                    error = C.get_last_error()
                    if error == 995:  # ERROR_OPERATION_ABORTED
                        if code in (GET_EVENT, GET_EVENT_BATCH):
                            return None
                        raise TimeoutError(f"IOCTL 0x{code:08X} timed out")
                    raise C.WinError(error)
            if returned.value > output_size:
                raise RuntimeError("Driver returned more bytes than the supplied buffer")
            # Copy only initialized payload bytes, not the entire reserved batch
            # followed by another slice. Small live events otherwise copy padding.
            return C.string_at(outgoing, returned.value) if outgoing is not None else b""
        finally:
            if pending:
                # Closing an event or freeing OVERLAPPED before cancellation finishes
                # is a use-after-free; drain the I/O even while unwinding an exception.
                self.k.CancelIoEx(self.handle, C.byref(overlap))
                self.k.GetOverlappedResult(self.handle, C.byref(overlap), C.byref(returned), True)
            self.k.CloseHandle(event_handle)

    def read(self, timeout_ms: int = 1000) -> bytes | None:
        if not 1 <= timeout_ms <= 60_000:
            raise ValueError("timeout must be between 1 and 60000 ms")
        return self._ioctl(GET_EVENT, b"", MAX_EVENT_SIZE, timeout_ms)

    def read_many(self, timeout_ms: int = 1000) -> list[bytes]:
        if not 1 <= timeout_ms <= 60_000:
            raise ValueError('timeout must be between 1 and 60000 ms')
        if self.batch_supported is not False:
            try:
                if getattr(self, 'native_read', None) is not None:
                    # One GIL release spans submission/wait/cancellation/cleanup.
                    # The status/control path remains independent and unchanged.
                    buffer = C.create_string_buffer(EVENT_BATCH_BYTES)
                    returned = DWORD(0)
                    elapsed = C.c_double(0)
                    error = self.native_read(self.handle, GET_EVENT_BATCH, buffer,
                                             EVENT_BATCH_BYTES, timeout_ms,
                                             C.byref(returned), C.byref(elapsed))
                    self.native_read_calls += 1
                    self.native_read_seconds = max(self.native_read_seconds, elapsed.value)
                    if error == 995:
                        raw = None
                    elif error:
                        raise C.WinError(error)
                    elif returned.value > EVENT_BATCH_BYTES:
                        raise RuntimeError('Native read exceeded output capacity')
                    else:
                        raw = C.string_at(buffer, returned.value)
                else:
                    raw = self._ioctl(GET_EVENT_BATCH, b'', EVENT_BATCH_BYTES, timeout_ms)
            except OSError as error:
                if getattr(error, 'winerror', None) not in (1, 50):
                    raise
                self.batch_supported = False
            else:
                self.batch_supported = True
                return [] if raw is None else split_event_batch(raw)
        raw = self.read(timeout_ms)
        return [] if raw is None else [raw]

    def status(self) -> dict[str, int]:
        raw = self._ioctl(GET_STATUS, b"", 72, 5000)
        if raw is None or len(raw) != 72:
            raise RuntimeError("Unexpected status response size")
        values = struct.unpack("<IIIIIIQQQQQQ", raw)
        if values[:2] != (MAGIC, VERSION):
            raise RuntimeError("Unexpected driver status protocol")
        names = ["magic", "version", "engine_pid", "fastpath_mode", "self_protect_enabled", "queue_depth",
                 "events_generated", "events_dropped", "processes_blocked", "termination_requests_succeeded",
                 "events_delivered", "events_flushed"]
        status = dict(zip(names, values))
        try:
            intake = self._ioctl(GET_INTAKE_STATUS, b'', 24, 5000)
        except OSError as error:
            if getattr(error, 'winerror', None) not in (1, 50):
                raise
        else:
            if intake is None or len(intake) != 24:
                raise RuntimeError('Invalid intake status')
            magic, version, excluded, omitted = struct.unpack('<IIQQ', intake)
            if (magic, version) != (MAGIC, VERSION):
                raise RuntimeError('Invalid intake status protocol')
            status.update(internal_storage_excluded=excluded, file_observations_omitted=omitted)
        try:
            stats = self._ioctl(GET_QUEUE_STATS, b'', 64, 5000)
        except OSError as error:
            if getattr(error, 'winerror', None) not in (1, 50):
                raise
        else:
            if stats is None or len(stats) != 64:
                raise RuntimeError('Invalid queue statistics')
            values = struct.unpack('<IIIIIIQQQQQ', stats)
            if values[:2] != (MAGIC, VERSION):
                raise RuntimeError('Invalid queue statistics ABI')
            status.update(zip(('intake_queue_depth','intake_queue_peak','intake_queue_limit','intake_batch_limit',
                'queue_overflow_drops','queue_allocation_failures','queue_invalid_payloads',
                'batches_delivered','batch_events_delivered'), values[2:]))
        return status

    def configure_internal_storage(self, db_path) -> None:
        from pathlib import Path
        import ntpath
        from .observer_filter import _query_dos_device
        path = str(Path(db_path).resolve())
        drive, suffix = ntpath.splitdrive(path)
        device = _query_dos_device(drive)
        if not device:
            raise ValueError('Exact NT volume mapping is required for internal storage')
        encoded = (device.rstrip('\\') + suffix).encode('utf-16-le')
        if not 0 < len(encoded) < 2048:
            raise ValueError('Internal database path is too long')
        self._ioctl(SET_INTERNAL_STORAGE, struct.pack('<III', MAGIC, VERSION, len(encoded))
                    + encoded.ljust(2048, b'\0'), 0, 5000)

    def terminate_checked(self, *, pid: int, expected_create_time: int, reason: int,
                          explicit_authorization: bool = False) -> dict[str, int | bool | str]:
        """Submit a deliberate, generation-bound kernel termination request.

        The generation must originate from trusted live identity verification,
        not a file-event PID or UI timestamp. The kernel independently checks
        the actual generation and protected-process status. NTSTATUS success
        confirms the termination request was accepted, NOT that exit completed.
        """
        if explicit_authorization is not True:
            raise PermissionError("Live termination requires an explicit authorized decision")
        if type(pid) is not int or not 4 < pid <= 0xFFFFFFFF:
            raise ValueError("pid must be a non-system unsigned 32-bit process ID")
        if type(expected_create_time) is not int or not 0 < expected_create_time <= 0x7FFFFFFFFFFFFFFF:
            raise ValueError("expected_create_time must be the exact positive kernel process generation")
        if type(reason) is not int or not 0 <= reason <= 0xFFFFFFFF:
            raise ValueError("reason must be an unsigned 32-bit rule/reason value")
        request = struct.pack("<IIIIq", MAGIC, VERSION, pid, reason, expected_create_time)
        raw = self._ioctl(TERMINATE_PROCESS, request, 16, 5000)
        if raw is None or len(raw) != 16:
            raise RuntimeError("Unexpected kernel termination response size")
        magic, version, returned_pid, status = struct.unpack("<IIIi", raw)
        if (magic, version, returned_pid) != (MAGIC, VERSION, pid):
            raise RuntimeError("Kernel termination response identity mismatch")
        return {"pid": pid, "expected_create_time": expected_create_time,
                "kernel_ntstatus": f"0x{status & 0xFFFFFFFF:08X}",
                "request_accepted": status == 0, "exit_confirmed": False}

    def close(self) -> None:
        if self.handle is None:
            return
        try:
            if self.registered:
                self._ioctl(UNREGISTER_ENGINE, b"", 0, 5000)
        finally:
            self.registered = False
            self.k.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self) -> "WindowsDriverReader":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

