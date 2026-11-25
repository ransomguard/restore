"""Native NTFS regression on throwaway stores. No service installation or live DB access."""
import ctypes as C
from contextlib import ExitStack, closing, contextmanager
from ctypes import wintypes as W
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from ransomguard.service_migration import STORES, TABLES, migrate


@contextmanager
def restricted_reader():
    # Both the normal token and a second access check restricted to BA must
    # allow the requested access. This only reduces the existing token's rights.
    adv = C.WinDLL("advapi32", use_last_error=True)
    kernel = C.WinDLL("kernel32", use_last_error=True)
    handle = W.HANDLE
    class SidAndAttributes(C.Structure):
        _fields_ = [("sid", W.LPVOID), ("attributes", W.DWORD)]
    adv.OpenProcessToken.argtypes = [handle, W.DWORD, C.POINTER(handle)]
    adv.ConvertStringSidToSidW.argtypes = [W.LPCWSTR, C.POINTER(W.LPVOID)]
    adv.CreateRestrictedToken.argtypes = [handle,W.DWORD,W.DWORD,W.LPVOID,W.DWORD,W.LPVOID,
                                          W.DWORD,C.POINTER(SidAndAttributes),C.POINTER(handle)]
    adv.ImpersonateLoggedOnUser.argtypes = [handle]
    kernel.CloseHandle.argtypes = [handle]
    kernel.GetCurrentProcess.restype = handle
    kernel.LocalFree.argtypes = [W.LPVOID]
    def check(ok):
        if not ok:
            raise C.WinError(C.get_last_error())
    with ExitStack() as cleanup:
        token, limited, sid = handle(), handle(), W.LPVOID()
        check(adv.OpenProcessToken(kernel.GetCurrentProcess(), 0x000a, C.byref(token)))
        cleanup.callback(kernel.CloseHandle, token)
        check(adv.ConvertStringSidToSidW("S-1-5-32-544", C.byref(sid)))
        cleanup.callback(kernel.LocalFree, sid)
        check(adv.CreateRestrictedToken(token,1,0,None,0,None,1,C.byref(SidAndAttributes(sid,0)),C.byref(limited)))
        cleanup.callback(kernel.CloseHandle, limited)
        check(adv.ImpersonateLoggedOnUser(limited))
        try:
            yield
        finally:
            check(adv.RevertToSelf())


def open_existing(path, access, *, directory=False):
    kernel = C.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [W.LPCWSTR,W.DWORD,W.DWORD,W.LPVOID,W.DWORD,W.DWORD,W.HANDLE]
    kernel.CreateFileW.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    h = kernel.CreateFileW(str(path),access,7,None,3,0x02000000 if directory else 0,None)
    if h == C.c_void_p(-1).value:
        return C.get_last_error()
    if not kernel.CloseHandle(h):
        raise C.WinError(C.get_last_error())
    return 0


def group_rights(paths):
    # Examine the actual NTFS objects as a second check, including when
    # Windows forbids further restricting an already sandboxed test runner.
    adv=C.WinDLL("advapi32",use_last_error=True)
    kernel=C.WinDLL("kernel32",use_last_error=True)
    p=W.LPVOID
    adv.GetNamedSecurityInfoW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,p,p,C.POINTER(p),p,C.POINTER(p)]
    adv.GetAce.argtypes=[p,W.DWORD,C.POINTER(p)]
    adv.EqualSid.argtypes=[p,p]
    adv.ConvertStringSidToSidW.argtypes=[W.LPCWSTR,C.POINTER(p)]
    kernel.LocalFree.argtypes=[p]
    admin=p()
    if not adv.ConvertStringSidToSidW("S-1-5-32-544",C.byref(admin)):
        raise C.WinError(C.get_last_error())
    values=[]
    try:
        for file in paths:
            acl,descriptor=p(),p()
            code=adv.GetNamedSecurityInfoW(str(file),1,4,None,None,C.byref(acl),None,C.byref(descriptor))
            if code:
                raise C.WinError(code)
            try:
                rights=[]
                for i in range(W.WORD.from_address(acl.value+4).value):
                    ace=p()
                    if not adv.GetAce(acl,i,C.byref(ace)):
                        raise C.WinError(C.get_last_error())
                    kind,flags=C.string_at(ace,2)
                    if kind==0 and not flags&8 and adv.EqualSid(ace.value+8,admin):
                        rights.append(W.DWORD.from_address(ace.value+4).value)
                if len(rights)!=1:
                    raise AssertionError((file.name,rights))
                values.append(rights[0])
            finally:
                kernel.LocalFree(descriptor)
    finally:
        kernel.LocalFree(admin)
    return values


def token_already_restricted():
    api=C.WinDLL("advapi32",use_last_error=True)
    kernel=C.WinDLL("kernel32",use_last_error=True)
    kernel.GetCurrentProcess.restype=W.HANDLE
    kernel.CloseHandle.argtypes=[W.HANDLE]
    api.OpenProcessToken.argtypes=[W.HANDLE,W.DWORD,C.POINTER(W.HANDLE)]
    api.IsTokenRestricted.argtypes=[W.HANDLE]
    token=W.HANDLE()
    if not api.OpenProcessToken(kernel.GetCurrentProcess(),8,C.byref(token)):
        raise C.WinError(C.get_last_error())
    try:
        return bool(api.IsTokenRestricted(token))
    finally:
        kernel.CloseHandle(token)


@unittest.skipUnless(os.name == "nt" and sys.version_info >= (3,13), "requires Windows Python 3.13+")
class StorageNtfsTests(unittest.TestCase):
    def test_private_acl_survives_migration_and_wal_creation(self):
        from ransomguard.service_identity import current_user_sid
        with tempfile.TemporaryDirectory() as fixture:
            root = Path(fixture)
            from ransomguard.storage_acl import protect_state_parent
            protect_state_parent(root)
            private = root / "private"
            private.mkdir()
            icacls = Path(os.environ["SystemRoot"]) / "System32/icacls.exe"
            subprocess.run([str(icacls),str(private),"/inheritance:r","/grant:r",
                            "*" + current_user_sid() + ":(OI)(CI)F",
                            "*S-1-5-32-544:(OI)(CI)RX","*S-1-5-18:(OI)(CI)F"],
                           check=True,capture_output=True)
            # Baseline proves this particular token can traverse and open for
            # write when a 0o700 temp directory replaces the inherited ACL.
            with tempfile.TemporaryDirectory(dir=private) as old:
                permissive = Path(old) / "control.db"
                permissive.write_bytes(b"fixture")
                self.assertEqual(group_rights([permissive]),[0x1f01ff])
                native = not token_already_restricted()
                if native:
                    with restricted_reader():
                        self.assertEqual(open_existing(permissive, 2), 0)
            source = root / "incoming"
            (source / "Runtime").mkdir(parents=True)
            for name, relative in STORES.items():
                with closing(sqlite3.connect(source / relative)) as db:
                    db.execute("CREATE TABLE " + TABLES[name] + "(seq INTEGER PRIMARY KEY)")
                    db.execute("INSERT INTO " + TABLES[name] + " VALUES (1)")
                    db.commit()
            migrate(source, private)
            stores = private / "stores"
            with ExitStack() as connections:
                files = []
                for name in STORES:
                    db = connections.enter_context(closing(sqlite3.connect(stores / name)))
                    self.assertEqual(db.execute("PRAGMA journal_mode").fetchone(), ("wal",))
                    db.execute("PRAGMA synchronous=FULL")
                    self.assertEqual(db.execute("PRAGMA synchronous").fetchone(), (2,))
                    db.execute("INSERT INTO " + TABLES[name] + " VALUES (2)")
                    db.commit()
                    self.assertEqual(db.execute("SELECT seq FROM " + TABLES[name] + " ORDER BY seq").fetchall(),[(1,),(2,)])
                    files.extend(stores / (name + suffix) for suffix in ("","-wal","-shm"))
                self.assertTrue(all(p.is_file() for p in files))
                self.assertEqual(group_rights([private,stores,*files]),[0x1200a9]*14)
                if native:
                    with restricted_reader():
                        for p in files:
                            with self.subTest(file=p.name):
                                self.assertEqual(open_existing(p,1),0)
                                for right in (2,4,0x10000):
                                    self.assertEqual(open_existing(p,right),5, (p.name,right))
                        for p in (private,stores):
                            for right in (2,4,0x40,0x10000):
                                self.assertEqual(open_existing(p,right,directory=True),5,(p.name,right))
