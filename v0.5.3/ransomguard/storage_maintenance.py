"""Owned-connection WAL maintenance off the event-processing commit path.

Only the registered intake process enables this. All connections retain FULL
durability; a low-priority worker checks small WALs while the intake has room.
Never run quick_check, VACUUM, TRUNCATE, or checkpoint another application's DB.
"""
import os
from pathlib import Path
import sqlite3
import threading
import time

class StorageMaintenance:
    def __init__(self,path,reader,*,interval=1):
        self.path=Path(path);self.reader=reader;self.interval=interval
        self.stop=threading.Event();self.thread=None
        self.result={'runs':0,'busy':0,'max_seconds':0,'last_error':None}
    def start(self):
        self.thread=threading.Thread(target=self.run,name='owned-wal-maintenance',daemon=True)
        self.thread.start();return self
    def run(self):
        db=None
        try:
            while not self.stop.wait(self.interval):
                if self.reader.queue.qsize()>=128:continue
                try:
                    if Path(str(self.path)+'-wal').stat().st_size<4*1024*1024:continue
                    if db is None:
                        db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,timeout=0)
                        db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA wal_autocheckpoint=0')
                    started=time.monotonic()
                    row=db.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone()
                    self.result.update(runs=self.result['runs']+1,last_pages=list(row),
                        max_seconds=max(self.result['max_seconds'],time.monotonic()-started),last_error=None)
                    self.result['busy']+=int(bool(row[0]))
                except (OSError,sqlite3.Error) as e:
                    self.result['last_error']=type(e).__name__
        finally:
            if db is not None:db.close()
    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(30)
            if self.thread.is_alive():raise RuntimeError('Owned WAL maintenance has not stopped; keep the driver owner alive')
