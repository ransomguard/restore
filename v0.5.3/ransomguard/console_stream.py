"""Raw backend output transport. No database polling, network socket, or UI formatting."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading

CHANNELS = ('kernel', 'decision', 'response')
_workers = {}
_lock = threading.Lock()

def pipe_name(runtime, channel):
    if channel not in CHANNELS:
        raise ValueError('Invalid output channel')
    identity = str(Path(runtime).resolve()).replace('\\', '/').casefold()
    digest = hashlib.sha256(identity.encode()).hexdigest()[:24]
    return r'\\.\pipe\RansomGuard-output-' + digest + '-' + channel

class Sender:
    def __init__(self, address, connector=None):
        from multiprocessing.connection import Client
        self.address = address
        self.connector = connector or Client
        self.queue = queue.Queue(512)
        self.closed = threading.Event()
        self.connection = None
        self.omitted = 0
        self.thread = threading.Thread(target=self.run, daemon=True, name='raw-console-output')
        self.thread.start()

    def offer(self, raw):
        if self.closed.is_set():
            return
        try:
            self.queue.put_nowait(raw)
        except queue.Full:
            self.omitted += 1

    def run(self):
        while not self.closed.is_set():
            try:
                raw = self.queue.get(timeout=.25)
            except queue.Empty:
                continue
            try:
                if self.connection is None:
                    self.connection = self.connector(self.address, family='AF_PIPE')
                if self.omitted:
                    self.connection.send_bytes(('CONSOLE_OUTPUT_OMITTED=' + str(self.omitted) + '\n').encode())
                    self.omitted = 0
                self.connection.send_bytes(raw)
            except (OSError, EOFError):
                if self.connection:
                    try:
                        self.connection.close()
                    except OSError:
                        pass
                self.connection = None
                # No viewer: no historical replay and no effect on event collection.

    def close(self):
        self.closed.set()
        if self.connection:
            try:
                self.connection.close()
            except OSError:
                pass
        self.thread.join(.5)

def emit(runtime, channel, line):
    if os.name != 'nt':
        return
    address = pipe_name(runtime, channel)
    with _lock:
        worker = _workers.get(address)
        if worker is None:
            worker = _workers[address] = Sender(address)
    worker.offer(line.encode('utf-8'))

def close_outputs():
    with _lock:
        workers = list(_workers.values())
        _workers.clear()
    for worker in workers:
        worker.close()

def audit(runtime, kind, payload, event_id, incident_id, occurred_at, staged):
    import re
    channels = []
    if re.match(r'^(triage_|track_[ab]_|jev_|detection_recorded|live_candidate_|automatic_(response|jev|file|evidence)_|local_ui_live_response)', kind):
        channels.append('decision')
    if re.match(r'^(host_outbound_|firewall_|incident_firewall_|termination_|kernel_termination_|process_exit_confirmed|restore_|release_|review_required|automatic_response_|local_ui_live_response|snapshot_)', kind):
        channels.append('response')
    if not channels:
        return
    # This is a producer log, not a claim that a batched transaction has committed.
    line = json.dumps(dict(occurred_at=occurred_at, event_id=event_id,
        incident_id=incident_id, kind=kind, storage_state='pending_commit' if staged else 'committed',
        payload=payload), ensure_ascii=False) + '\n'
    for channel in channels:
        emit(runtime, channel, line)

def view(runtime, channel):
    import ctypes
    from ctypes import wintypes
    from multiprocessing.connection import Listener
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    address = pipe_name(runtime, channel)
    mutex = kernel.CreateMutexW(None, False, 'Local\\' + address.rsplit('\\',1)[-1])
    if ctypes.get_last_error() == 183:
        return
    if not mutex:
        raise ctypes.WinError(ctypes.get_last_error())
    kernel.SetConsoleTitleW('RansomGuard ' + channel + ' backend stdout')
    sys.stdout = open('CONOUT$', 'w', encoding='utf-8', buffering=1)
    sys.stderr = sys.stdout
    sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
    # Disconnects and X terminate only this independent output reader.
    with Listener(address, family='AF_PIPE') as listener:
        status = Path(runtime) / ('raw-console-' + channel + '.json')
        status.write_text(json.dumps({'viewer_pid': os.getpid(), 'ready': True}), encoding='utf-8')
        while True:
            with listener.accept() as connection:
                try:
                    while True:
                        raw = connection.recv_bytes(1024*1024)
                        sys.stdout.buffer.write(raw)
                        sys.stdout.buffer.flush()
                except (EOFError, OSError):
                    pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--channel', choices=CHANNELS, required=True)
    parser.add_argument('--launch', action='store_true')
    args = parser.parse_args()
    if args.launch:
        child = subprocess.Popen([sys.executable, '-u', str(Path(__file__).resolve()),
            '--runtime', args.runtime, '--channel', args.channel],
            creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.CREATE_NEW_PROCESS_GROUP,
            close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(json.dumps({'viewer_pid':child.pid}))
    else:
        view(args.runtime, args.channel)
