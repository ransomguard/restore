"""Resident passive intake; replace workers without unregistering the engine.

Only Python analysis/storage workers are replaceable. The driver ABI and
resident intake implementation are pinned for this process lifetime. The
bounded intake buffer does not promise unlimited pause or crash durability.
Explicit process shutdown still follows the existing kernel unregister ABI.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys
import time
import uuid

from .buffered_reader import BufferedReader
from .windows_reader import WindowsDriverReader

PINNED = ('resident.py', 'windows_reader.py', 'protocol.py', 'buffered_reader.py')


def fingerprint(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    deadline = time.monotonic() + .5
    while True:
        try:
            temporary.replace(path)
            break
        except PermissionError:
            # A status reader can briefly omit FILE_SHARE_DELETE on Windows.
            # Retain the prior complete handshake and retry the atomic replace.
            if time.monotonic() >= deadline:
                raise
            time.sleep(.01)


def source_revision(source):
    manifest = {path.name: fingerprint(path) for path in sorted(Path(source).glob('*.py'))}
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def log_windows_failure(record):
    """Report to the Windows Application log independently of the product volume's DB."""
    if os.name != 'nt':
        return
    import ctypes
    from ctypes import wintypes
    api = ctypes.WinDLL('advapi32', use_last_error=True)
    api.RegisterEventSourceW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    api.RegisterEventSourceW.restype = wintypes.HANDLE
    api.ReportEventW.argtypes = [wintypes.HANDLE, wintypes.WORD, wintypes.WORD,
        wintypes.DWORD, wintypes.LPVOID, wintypes.WORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPCWSTR), wintypes.LPVOID]
    api.DeregisterEventSource.argtypes = [wintypes.HANDLE]
    handle = api.RegisterEventSourceW(None, 'Ransom0')
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        strings = (wintypes.LPCWSTR * 1)(json.dumps(record, ensure_ascii=True))
        if not api.ReportEventW(handle, 1, 0, 1001, None, 1, 0, strings, None):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        api.DeregisterEventSource(handle)


def publish_failure(ready, result_path, args, reader, error):
    progress = args._resident_info
    stamp = time.time()
    pending = reader.queue.qsize()
    failure = {'resident_session': progress['resident_session'],
               'worker_generation': progress['worker_generation'],
               'pid': os.getpid(), 'worker_state': 'failed', 'worker_failed_at': stamp,
               'worker_error': str(error)[:2048], 'pending_intake': pending,
               'last_processed_sequence': progress.get('last_processed_sequence')}
    try:
        log_windows_failure(failure)
    except OSError as exc:
        print(f'Unable to write Windows failure event: {exc}', file=sys.stderr)
    try:
        health = json.loads(ready.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        health = {}
    if (not isinstance(health, dict) or health.get('resident_session') != progress['resident_session']
            or health.get('worker_generation') != progress['worker_generation']):
        health = {'resident': True, 'driver_registered': True, 'db': str(Path(args.db).resolve())}
    health.update(failure)
    receipt = {'state': 'worker_failed', 'request_id': progress.get('reload_request_id'),
               'pid': failure['pid'], 'at': stamp, 'error': failure['worker_error'],
               'intake_running': True, 'buffer': reader.diagnostics()}
    for path, value in ((ready, health), (result_path, receipt)):
        try:
            write_json(path, value)
        except OSError as exc:
            print(f'Unable to publish worker failure to {path.name}: {exc}', file=sys.stderr)


def request_reload(ready_path, source, *, ui_process_id=None):
    ready_path = Path(ready_path)
    ready = json.loads(ready_path.read_text(encoding='utf-8'))
    if ready.get('resident') is not True or time.time() - ready.get('observed_at', 0) > 30:
        raise RuntimeError('A healthy resident collector is required')
    request = {'id': uuid.uuid4().hex, 'expires': time.time()+120,
               'revision': source_revision(source)}
    if ui_process_id is not None:
        request['ui_process_id'] = ui_process_id
    write_json(ready_path.with_suffix('.reload.json'), request)
    return request


class Worker:
    """Load an immutable source snapshot under a fresh package namespace."""
    def __init__(self, source, cache, pinned):
        self.name = '_rg_worker_' + uuid.uuid4().hex
        self.path = Path(cache) / self.name
        self.path.mkdir(parents=True)
        self.manifest = {}
        try:
            for path in sorted(Path(source).glob('*.py')):
                data = path.read_bytes()
                compile(data, str(path), 'exec')  # Syntax failure precedes handover.
                self.manifest[path.name] = hashlib.sha256(data).hexdigest()
                (self.path / path.name).write_bytes(data)
            if any(self.manifest.get(name) != digest for name, digest in pinned.items()):
                raise ValueError('Resident/driver ABI changes require a separately planned process restart')
            self.revision = hashlib.sha256(json.dumps(self.manifest, sort_keys=True).encode()).hexdigest()
            spec = importlib.util.spec_from_file_location(self.name, self.path/'__init__.py',
                                                         submodule_search_locations=[str(self.path)])
            package = importlib.util.module_from_spec(spec)
            sys.modules[self.name] = package
            spec.loader.exec_module(package)
            module = __import__(self.name + '.cli', fromlist=['_observe'])
            self.observe = module._observe
            if not {'shared_reader', 'reload_requested'} <= set(inspect.signature(self.observe).parameters):
                raise ValueError('Worker does not implement resident handover')
        except BaseException:
            self.unload()
            raise

    def unload(self):
        for name in list(sys.modules):
            if name == self.name or name.startswith(self.name + '.'):
                del sys.modules[name]


class Handover:
    def __init__(self, source, cache, request_path, pinned, status_path):
        self.source, self.cache, self.request_path = source, cache, request_path
        self.pinned, self.status_path = pinned, status_path
        self.last_id = None
        self.pending = None
        self.next_poll = 0
        self.request = None

    def requested(self):
        if self.pending is not None:
            return True
        now = time.monotonic()
        if now < self.next_poll:
            return False
        self.next_poll = now + .25
        try:
            request = json.loads(self.request_path.read_text(encoding='utf-8-sig'))
        except (FileNotFoundError, json.JSONDecodeError):
            return False
        id_ = request.get('id')
        if not isinstance(id_, str) or not 1 <= len(id_) <= 100 or id_ == self.last_id:
            return False
        self.last_id = id_
        try:
            if request.get('expires', 0) < time.time():
                raise ValueError('Expired worker replacement request')
            if 'ui_process_id' in request:
                value = request['ui_process_id']
                if type(value) is not int or value <= 4:
                    raise ValueError('Invalid UI process ID')
            worker = Worker(self.source, self.cache, self.pinned)
            if request.get('revision') != worker.revision:
                worker.unload()
                raise ValueError('Worker source does not match prepared revision')
            self.pending, self.request = worker, request
            write_json(self.status_path, {'state': 'prepared', 'request_id': id_, 'revision': worker.revision,
                                         'pid': os.getpid(), 'at': time.time()})
            return True
        except Exception as error:
            write_json(self.status_path, {'state': 'rejected', 'request_id': id_, 'error': str(error),
                                         'old_worker_retained': True, 'pid': os.getpid(), 'at': time.time()})
            return False


def open_reader_wait(factory, seconds=30):
    # Initial migration only: do not evict the old owner, wait for its close.
    deadline = time.monotonic() + seconds
    while True:
        try:
            return factory()
        except OSError as error:
            # This KMDF control device also reports ERROR_INTERNAL_ERROR while
            # an existing exclusive engine handle is being relinquished.
            # Retry only within this bounded ownership wait; never evict it.
            if getattr(error, 'winerror', None) not in (5, 32, 183, 1242, 1359) or time.monotonic() >= deadline:
                raise
            time.sleep(.02)


def run(args, *, factory=WindowsDriverReader):
    if ((args.live_track_a or args.live_track_b) and not getattr(args, 'async_response', False)) or not args.prefetch_events or not args.ready_file:
        raise ValueError('Resident handover requires buffered intake, --ready-file and asynchronous live response')
    source = Path(__file__).resolve().parent
    ready = Path(args.ready_file)
    ready.parent.mkdir(parents=True, exist_ok=True)
    pinned = {name: fingerprint(source/name) for name in PINNED}
    cache = ready.parent / 'worker-versions'
    result_path = ready.with_suffix('.reload-result.json')
    handover = Handover(source, cache, ready.with_suffix('.reload.json'), pinned, result_path)
    # Compile/import before acquiring the driver; DB setup runs while intake is live.
    worker = Worker(source, cache, pinned)
    session = uuid.uuid4().hex
    gate_name = getattr(args, 'resident_start_gate', None)
    if gate_name:
        gate = Path(gate_name).resolve()
        if gate.parent != ready.parent.resolve():
            raise ValueError('Migration gate must be local to the ready directory')
        write_json(ready.with_suffix('.owner-wait.json'), {'pid': os.getpid(), 'session': session,
            'revision': worker.revision, 'at': time.time(), 'state': 'waiting_for_old_owner'})
    reader = BufferedReader(open_reader_wait(factory), args.prefetch_events)
    if hasattr(reader.reader, 'configure_internal_storage'):
        try:
            reader.reader.configure_internal_storage(args.db)
        except BaseException:
            reader.reader.close()
            worker.unload()
            raise
    reader.__enter__()
    # Only this registered process can omit its exact outbox/sidecar writes
    # from kernel telemetry. Checkpointing elsewhere creates self-observed I/O.
    from .storage_maintenance import StorageMaintenance
    os.environ['RANSOMGUARD_OWNED_WAL_MAINTENANCE'] = str(os.getpid())
    wal_maintenance = StorageMaintenance(Path(args.db).absolute(), reader).start()
    reader.wal_maintenance = wal_maintenance
    generation = 0
    request_id = None
    failed = False
    try:
        if gate_name:
            deadline = time.monotonic()+30
            while True:
                try:
                    if json.loads(gate.read_text()).get('session') == session:
                        break
                except (FileNotFoundError, ValueError):
                    pass
                if time.monotonic()>deadline:
                    raise RuntimeError('Initial migration gate not opened; intake tail will be preserved')
                time.sleep(.02)
        while True:
            generation += 1
            args._resident_info = {'resident': True, 'resident_session': session,
                'worker_generation': generation, 'worker_revision': worker.revision,
                'reload_request_id': request_id, 'worker_state': 'running'}
            try:
                failed = False
                worker.observe(args, shared_reader=reader, reload_requested=handover.requested)
            except Exception as error:
                failed = True
                if handover.pending is not None:
                    handover.pending.unload()
                    handover.pending = None
                publish_failure(ready, result_path, args, reader, error)
            if ready.with_suffix('.stop').exists() or args.limit:
                break
            if not failed and handover.pending is None:
                break
            # On failure, keep the handle alive; require a new checked request.
            while handover.pending is None:
                if ready.with_suffix('.stop').exists():
                    return 1 if failed else 0
                handover.requested()
                time.sleep(.1)
            previous = worker
            worker, handover.pending = handover.pending, None
            request_id = handover.request['id']
            ui_pid = handover.request.get('ui_process_id')
            if ui_pid:
                os.environ['RANSOM0_UI_PROCESS_ID'] = str(ui_pid)
            previous.unload()
            # A new ready-file generation is the completion receipt, after DB/UI startup.
    finally:
        # Full process shutdown is distinct from worker handover. Retain unread
        # Python bytes before releasing the current kernel ABI's engine handle.
        retained_ui = getattr(args, '_retained_ui_delivery', None)
        if retained_ui is not None:
            retained_ui.close()
            args._retained_ui_delivery = None
        wal_maintenance.close()
        os.environ.pop('RANSOMGUARD_OWNED_WAL_MAINTENANCE', None)
        pending = reader.stop_and_drain()
        try:
            if pending:
                from .outbox import Outbox
                with Outbox(args.db) as outbox:
                    outbox.preserve_intake(pending, 'resident_full_shutdown_unprocessed')
        finally:
            reader.reader.close()
            worker.unload()
    return 1 if failed else 0
