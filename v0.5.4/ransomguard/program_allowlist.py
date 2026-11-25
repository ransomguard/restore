"""Local, administrator-managed exemptions from automatic response only.

Never used by event intake or the kernel's self-protection/blocking rules.
Policy edits are audited separately from the high-volume collector database.
"""
import argparse
from contextlib import closing
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import uuid

from .process_identity import WindowsProcessSession


def policy_path(runtime):
    return Path(runtime) / 'program-policy' / 'allowlist.sqlite3'


def fingerprint(filename):
    """Hash an existing local EXE with Windows write/delete sharing denied."""
    if not isinstance(filename, str) or not os.path.isabs(filename) or filename.startswith(('\\\\', '//')):
        raise ValueError('로컬 실행 파일의 전체 경로가 필요합니다.')
    path = Path(filename)
    if path.suffix.lower() != '.exe' or ':' in str(path)[2:]:
        raise ValueError('로컬 .exe 파일만 등록할 수 있습니다.')
    # Do not turn a junction/symlink registration into a wider path exception.
    for part in (path, *path.parents):
        if getattr(part.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('링크 또는 재분석 지점은 등록할 수 없습니다.')
    path = path.resolve(strict=True)
    if os.name == 'nt':
        import msvcrt
        k = ctypes.WinDLL('kernel32', use_last_error=True)
        k.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                 ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        k.CreateFileW.restype = ctypes.c_void_p
        handle = k.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x08000000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), '실행 파일을 안전하게 읽지 못했습니다.')
        stream = os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY), 'rb')
    else:
        stream = path.open('rb')
    with stream:
        before = os.fstat(stream.fileno())
        if not 0 < before.st_size <= 512 * 1024 * 1024:
            raise ValueError('실행 파일 크기는 512 MiB 이하이어야 합니다.')
        if stream.read(2) != b'MZ':
            raise ValueError('Windows 실행 파일이 아닙니다.')
        stream.seek(0)
        checksum = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            checksum.update(chunk)
        digest = checksum.hexdigest()
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError('검사 중 실행 파일이 변경되었습니다.')
    return {'path': str(path), 'sha256': digest}


def _connect(runtime):
    service_mode = os.environ.get("RANSOM0_SERVICE_STORAGE") == "1"
    if service_mode:
        from .service_identity import require_service_account
        require_service_account()
        if Path(runtime).resolve() != Path(sys.executable).resolve().parent.parent / "service-state/private/stores":
            raise PermissionError("Unexpected program policy location")
    elif os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError('프로그램 예외 변경에는 관리자 권한이 필요합니다.')
    path = policy_path(runtime)
    path.parent.mkdir(exist_ok=True)
    if path.parent.is_symlink() or getattr(path.parent.lstat(), 'st_file_attributes', 0) & 0x400:
        raise ValueError('잘못된 정책 저장 경로입니다.')
    if os.name == 'nt' and not service_mode:
        # Protect policy, journal and audit together. Users can read, never edit.
        subprocess.run(['icacls.exe', str(path.parent), '/inheritance:r', '/grant:r',
                        '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)R'],
                       check=True, capture_output=True, creationflags=0x08000000)
    db = sqlite3.connect(path, timeout=5)
    db.executescript('''CREATE TABLE IF NOT EXISTS programs(
        id TEXT PRIMARY KEY,path TEXT NOT NULL COLLATE NOCASE UNIQUE,sha256 TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,action TEXT NOT NULL,record TEXT NOT NULL,created REAL NOT NULL);''')
    return db


def entries(runtime):
    path = policy_path(runtime)
    if not path.exists():
        return []
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
        return [dict(zip(('id', 'path', 'sha256', 'created'), r))
                for r in db.execute('SELECT id,path,sha256,created FROM programs ORDER BY created DESC')]


def add(runtime, filename):
    record = dict(id=str(uuid.uuid4()), **fingerprint(filename), created=time.time())
    with closing(_connect(runtime)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT count(*) FROM programs').fetchone()[0] >= 100:
            raise ValueError('프로그램 예외는 최대 100개입니다.')
        db.execute('INSERT INTO programs VALUES(:id,:path,:sha256,:created)', record)
        db.execute('INSERT INTO audit VALUES(?,?,?,?)', (str(uuid.uuid4()), 'add', json.dumps(record), time.time()))
    return entries(runtime)


def remove(runtime, id_):
    if not isinstance(id_, str) or len(id_) != 36:
        raise ValueError('잘못된 프로그램 예외 ID입니다.')
    with closing(_connect(runtime)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT id,path,sha256,created FROM programs WHERE id=?', (id_,)).fetchone()
        if row:
            db.execute('DELETE FROM programs WHERE id=?', (id_,))
            db.execute('INSERT INTO audit VALUES(?,?,?,?)', (str(uuid.uuid4()), 'remove', json.dumps(row), time.time()))
    return entries(runtime)


def match(runtime, process, *, session_factory=WindowsProcessSession, inspect_file=fingerprint):
    rules = entries(runtime)
    if not rules:
        return None
    with session_factory(process) as session:
        if session.is_exited():
            return None
        filename = session.image_path()
        rule = next((r for r in rules if os.path.normcase(r['path']) == os.path.normcase(filename)), None)
        if rule is None:
            return None
        actual = inspect_file(filename)
        if (os.path.normcase(actual['path']) != os.path.normcase(rule['path']) or
                actual['sha256'] != rule['sha256'] or session.is_exited()):
            return None
        return rule


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', required=True)
    parser.add_argument('action', choices=['program-list', 'program-add', 'program-remove'])
    args = parser.parse_args()
    try:
        if args.action == 'program-list':
            result = entries(args.runtime)
        else:
            request = json.loads(sys.stdin.read(65536))
            result = add(args.runtime, request['path']) if args.action == 'program-add' else remove(args.runtime, request['id'])
        print(json.dumps({'entries': result}, ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'error': str(error)}, ensure_ascii=False))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
