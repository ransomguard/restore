"""SCM client for the fixed VSS provider. No named pipe or writable input file."""
import ctypes
from ctypes import wintypes as W
import json
import os
import threading
import time
import uuid

from .service_identity import require_service_account


NAME = "Ransom0Vss"
KEY = r"SOFTWARE\Ransom0\VssBroker"
MUTATING = {"create", "delete"}
_lock = threading.Lock()


def managed():
    return os.environ.get("RANSOM0_SERVICE_STORAGE") == "1"


def _start(args):
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.OpenSCManagerW.argtypes = [W.LPCWSTR, W.LPCWSTR, W.DWORD]
    api.OpenSCManagerW.restype = W.HANDLE
    api.OpenServiceW.argtypes = [W.HANDLE, W.LPCWSTR, W.DWORD]
    api.OpenServiceW.restype = W.HANDLE
    api.StartServiceW.argtypes = [W.HANDLE, W.DWORD, ctypes.POINTER(W.LPCWSTR)]
    api.CloseServiceHandle.argtypes = [W.HANDLE]
    manager = api.OpenSCManagerW(None, None, 1)
    if not manager:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        service = api.OpenServiceW(manager, NAME, 0x10)  # SERVICE_START only
        if not service:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not api.StartServiceW(service, len(args), (W.LPCWSTR * len(args))(*args)):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            api.CloseServiceHandle(service)
    finally:
        api.CloseServiceHandle(manager)


def request(op, volume, *, snapshot=None, timeout=180):
    import winreg
    from .snapshots import SnapshotCreationFailed, SnapshotOutcomeUnknown
    require_service_account()
    data = {"op": op, "volume": volume}
    if snapshot is not None:
        data["snapshot"] = snapshot.to_dict()
    key_id = uuid.uuid4().hex
    payload = json.dumps(data, allow_nan=False)
    with _lock, winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as config:
        deadline = time.monotonic() + timeout
        while True:
            try:
                _start([key_id, payload])
                break
            except OSError as error:
                if error.winerror == 1056 and time.monotonic() < deadline:
                    # Only retry when SCM explicitly rejected this start as already running.
                    time.sleep(.1)
                    continue
                if op == "create" and error.winerror in (1053, 1067):
                    raise SnapshotOutcomeUnknown("vss_service_start_uncertain") from error
                raise
        try:
            while time.monotonic() < deadline:
                try:
                    reply = json.loads(winreg.QueryValueEx(config, "LastReply")[0])
                except FileNotFoundError:
                    reply = {}
                if reply.get("id") == key_id:
                    break
                time.sleep(.1)
            else:
                raise TimeoutError("VSS service did not publish this request's result")
        except (OSError, ValueError) as error:
            if op == "create":
                raise SnapshotOutcomeUnknown("vss_service_reply_unavailable") from error
            raise
    if reply.get("status") == "ok":
        return reply["value"]
    if reply.get("status") == "known_failure" and op == "create":
        raise SnapshotCreationFailed(reply["reason"], return_value=reply.get("return_value"))
    if op == "create":
        raise SnapshotOutcomeUnknown(reply.get("reason","vss_service_unknown"), snapshot_id=reply.get("snapshot_id"))
    raise RuntimeError("VSS service: " + str(reply.get("reason","unknown operation outcome")))
