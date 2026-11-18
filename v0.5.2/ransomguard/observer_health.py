"""Local, bounded health reporting and cooperative collector shutdown."""
import json
import os
from pathlib import Path
import time


class ObserverHealth:
    def __init__(self, ready_file, db_path, *, clock=time.monotonic, metadata=None, stop_check_interval=0):
        self.path = Path(ready_file) if ready_file else None
        self.stop_path = self.path.with_suffix('.stop') if self.path else None
        self.db_path = str(Path(db_path).resolve())
        self.clock = clock
        self.last = None
        self.metadata = dict(metadata or {})
        if not 0 <= stop_check_interval <= .25:
            raise ValueError('Stop check interval must be 0..0.25 seconds')
        self.stop_check_interval = stop_check_interval
        self.next_stop_check = 0
        self.stopping = False

    def stop_requested(self):
        now = self.clock()
        if not self.stopping and now >= self.next_stop_check:
            self.stopping = bool(self.stop_path and self.stop_path.is_file())
            self.next_stop_check = now + self.stop_check_interval
        return self.stopping

    def publish(self, status, *, intake=None, force=False):
        if self.path is None:
            return
        now = self.clock()
        if not force and self.last is not None and now - self.last < 5:
            return
        payload = {'pid': os.getpid(), 'db': self.db_path, 'driver_registered': True,
                   'observed_at': time.time(), 'driver_status': dict(status),
                   'intake': intake, 'stop_request_path': str(self.stop_path)}
        payload.update(self.metadata)
        from .counter_history import atomic_json
        try:
            atomic_json(self.path, payload)
        except PermissionError:
            # A busy status reader must not stop durable event processing.
            # Keep the previous complete health file and retry next cycle.
            return
        if force and self.metadata.get('reload_request_id'):
            receipt = self.path.with_suffix('.reload-result.json')
            receipt_tmp = receipt.with_suffix(receipt.suffix + '.tmp')
            receipt_tmp.write_text(json.dumps({'state': 'applied', **self.metadata,
                'request_id': self.metadata['reload_request_id'], 'pid': os.getpid(),
                'at': time.time(), 'driver_status': dict(status)}), encoding='utf-8')
            receipt_tmp.replace(receipt)
        self.last = now
