"""Demand-start VSS provider. SCM authenticates the caller; the registry pins the volume."""
import ctypes
from ctypes import wintypes as W
import json
import os
import re

from .recovery import Snapshot, _volume_id, enumerate_snapshots
from .snapshot_retention import delete_exact, read_storage
from .snapshots import SnapshotCreationFailed, SnapshotOutcomeUnknown, _create_vss_snapshot
from .vss_service import KEY, MUTATING, NAME


def perform(request_id, message, state, *, inventory=enumerate_snapshots, space=read_storage,
            create=_create_vss_snapshot, delete=delete_exact):
    """Called once per SCM start. Provider functions receive only validated parameters."""
    if not re.fullmatch(r"[0-9a-f]{32}", request_id) or len(message) > 4096:
        raise ValueError("Invalid VSS request")
    request = json.loads(message)
    if not isinstance(request, dict) or request.get("op") not in ("list", "space", "create", "delete"):
        raise ValueError("Unknown VSS operation")
    op = request["op"]
    if set(request) != ({"volume", "op", "snapshot"} if op == "delete" else {"volume", "op"}):
        raise ValueError("Unexpected VSS arguments")
    volume = _volume_id(request["volume"])
    if volume != _volume_id(state.volume):
        raise PermissionError("Volume outside the installed VSS scope")
    if op == "list":
        return {"status":"ok","value":[s.to_dict() for s in inventory(volume)]}
    if op == "space":
        return {"status":"ok","value":space(volume)}
    previous = state.get("Requests", request_id)
    if previous is not None:
        if previous["request"] != request:
            raise ValueError("VSS request identifier collision")
        return previous.get("reply", {"status":"unknown","reason":"previous_operation_interrupted"})
    if op == "delete":
        snap = Snapshot(**request["snapshot"])
        if snap.volume_id != volume:
            raise PermissionError("Snapshot belongs to a different volume")
        saved = state.get("Owned", snap.snapshot_id)
        if not saved or Snapshot(**saved).created_at != snap.created_at or saved["volume_id"] != volume:
            raise PermissionError("Missing independent creation receipt")
        if state.get("Deleted", snap.snapshot_id) is not None:
            raise PermissionError("A deletion was already requested for this snapshot")
    state.put("Requests", request_id, {"request":request})
    try:
        if op == "create":
            created = create(volume)
            if created.volume_id != volume:
                raise SnapshotOutcomeUnknown("provider_volume_mismatch")
            state.put("Owned", created.snapshot_id, created.to_dict())
            result = created.to_dict()
        else:
            # Keep this intent even after a crash. Never repeat an uncertain deletion.
            state.put("Deleted", snap.snapshot_id, {"request":request_id})
            delete(snap)
            result = {"absent":True,"snapshot_id":snap.snapshot_id}
        reply = {"status":"ok","value":result}
    except SnapshotCreationFailed as error:
        reply = {"status":"known_failure","reason":error.reason,"return_value":error.return_value}
    except SnapshotOutcomeUnknown as error:
        reply = {"status":"unknown","reason":error.reason,"snapshot_id":error.snapshot_id}
    except Exception as error:
        reply = {"status":"unknown","reason":"provider_"+type(error).__name__}
    state.put("Requests", request_id, {"request":request,"reply":reply})
    return reply


class Registry:
    def __init__(self, root):
        import winreg
        self.root = root
        self.volume = winreg.QueryValueEx(root, "Volume")[0]

    def get(self, group, name):
        import winreg
        with winreg.OpenKey(self.root, group) as child:
            try:
                return json.loads(winreg.QueryValueEx(child, name)[0])
            except FileNotFoundError:
                return None

    def put(self, group, name, value):
        import winreg
        with winreg.OpenKey(self.root, group, 0, winreg.KEY_SET_VALUE) as child:
            winreg.SetValueEx(child, name, 0, winreg.REG_SZ, json.dumps(value, allow_nan=False))
            winreg.FlushKey(child)


def main():
    import winreg
    from .service_identity import current_user_sid
    if current_user_sid() != "S-1-5-18":
        raise PermissionError("The VSS provider requires its SCM LocalSystem identity")
    # This process never routes its own provider calls back to SCM.
    os.environ.pop("RANSOM0_SERVICE_STORAGE", None)
    os.environ.pop("RANSOM0_STORAGE_OWNER", None)
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    entry_fn = ctypes.WINFUNCTYPE(None, W.DWORD, ctypes.POINTER(W.LPWSTR))
    handler_fn = ctypes.WINFUNCTYPE(W.DWORD, W.DWORD, W.DWORD, W.LPVOID, W.LPVOID)

    class Entry(ctypes.Structure):
        _fields_ = [("name",W.LPWSTR),("main",entry_fn)]

    api.RegisterServiceCtrlHandlerExW.argtypes = [W.LPCWSTR,handler_fn,W.LPVOID]
    api.RegisterServiceCtrlHandlerExW.restype = W.HANDLE
    api.SetServiceStatus.argtypes = [W.HANDLE,W.LPVOID]
    api.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(Entry)]

    @handler_fn
    def control(code, _a, _b, _c):
        return 0 if code == 4 else 120

    @entry_fn
    def run(argc, argv):
        handle = api.RegisterServiceCtrlHandlerExW(NAME, control, None)
        if not handle:
            return
        def report(status, code=0):
            record = (W.DWORD*7)(0x10,status,0,code,0,0,0)
            if not api.SetServiceStatus(handle, ctypes.byref(record)):
                raise ctypes.WinError(ctypes.get_last_error())
        exit_code = 13
        try:
            report(4)
            if argc != 3 or not re.fullmatch(r"[a-f0-9]{32}", argv[1] or ""):
                return
            key_id = argv[1]
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY, 0,
                                winreg.KEY_READ | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                try:
                    reply = perform(key_id, argv[2], Registry(key))
                except Exception as error:
                    reply = {"status":"error","reason":str(error)[:250]}
                reply["id"] = key_id
                winreg.SetValueEx(key, "LastReply", 0, winreg.REG_SZ, json.dumps(reply, allow_nan=False))
                winreg.FlushKey(key)
                exit_code = 0
        finally:
            report(1, exit_code)

    table = (Entry*2)(Entry(NAME,run),Entry())
    if not api.StartServiceCtrlDispatcherW(table):
        raise ctypes.WinError(ctypes.get_last_error())


if __name__ == "__main__":
    main()
