"""FIFO admission for cooperating SQLite writers in one observer worker.

SQLite remains the cross-process authority. This only prevents a busy passive
batch producer repeatedly reacquiring the writer lock ahead of response audit.
No sleeps, sampling, priority changes, or kernel-collector locks are used.
"""
from collections import deque
from pathlib import Path
import sqlite3
import threading
import time


class WriterAdmission:
    def __init__(self):
        self.condition = threading.Condition()
        self.waiters = deque()
        self.owner = None

    def acquire(self, owner, timeout=30):
        token = object()
        deadline = time.monotonic()+timeout
        with self.condition:
            self.waiters.append(token)
            try:
                while self.owner is not None or self.waiters[0] is not token:
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise sqlite3.OperationalError('Cooperating writer admission timed out')
                    self.condition.wait(remaining)
                self.waiters.popleft()
                self.owner = owner
            except BaseException:
                if token in self.waiters:self.waiters.remove(token)
                self.condition.notify_all()
                raise

    def release(self, owner):
        with self.condition:
            if self.owner is not owner:
                raise RuntimeError('Writer admission ownership mismatch')
            self.owner = None
            self.condition.notify_all()


_gates = {}
_lock = threading.Lock()

def for_database(path):
    key = str(Path(path).resolve()).casefold()
    with _lock:
        return _gates.setdefault(key, WriterAdmission())
