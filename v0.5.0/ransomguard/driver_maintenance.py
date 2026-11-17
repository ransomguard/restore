"""Bounded, session-bound drain handshake for a passive driver replacement.

The updater must stop the file filter first and start independent ETW capture.
This does NOT provide entropy/denial protection while the driver is paused.
No network, account, firewall, or registry configuration is changed.
"""
import json
import os
from pathlib import Path
import struct
import time

from .counter_history import atomic_json
from .protocol import MAGIC, VERSION, UPDATE_POLICY


class DriverMaintenance:
    def __init__(self, ready, reader, *, session=None, enabled=False):
        self.path = Path(ready).with_suffix('.maintenance.json') if ready and enabled else None
        self.reader = reader
        self.session = session
        self.active = None
        self.seen = None
        self.stable = None
        self.drained = False
        self.last_poll = 0

    def policy(self, enabled):
        native = getattr(self.reader, 'reader', self.reader)
        native._ioctl(UPDATE_POLICY, struct.pack('<IIIII', MAGIC, VERSION,
                      self.active['status']['fastpath_mode'], int(enabled),
                      self.active['status']['self_protect_enabled']), 0, 5000)

    def receipt(self, state, **extra):
        atomic_json(self.path.with_suffix('.result.json'), {
            'id': self.active['id'], 'pid': os.getpid(), 'session': self.session,
            'state': state, 'at': time.time(), 'full_kernel_coverage': False, **extra})

    def tick(self, raw_status, *, idle=False):
        if self.path is None:
            return
        now = time.time()
        if self.active:
            if now >= self.active['expires']:
                self.policy(True)
                self.receipt('expired_and_process_monitor_resumed')
                self.active = None
                self.drained = False
                return
            empty = idle and raw_status['queue_depth'] == 0 and self.reader.queue.empty()
            stamp = (raw_status['events_generated'], raw_status['events_delivered'])
            if not empty:
                self.stable = None
            elif self.stable is None or self.stable[0] != stamp:
                self.stable = (stamp, time.monotonic())
            elif not self.drained and time.monotonic() - self.stable[1] >= 2:
                self.drained = True
                self.receipt('drained', raw_status=raw_status,
                             buffer_pending=self.reader.queue.qsize())
            return
        if time.monotonic() - self.last_poll < .25:
            return
        self.last_poll = time.monotonic()
        try:
            request = json.loads(self.path.read_text(encoding='utf-8'))
        except (FileNotFoundError, ValueError):
            return
        if (not request.get('id') or request['id'] == self.seen
                or request.get('pid') != os.getpid() or request.get('session') != self.session
                or request.get('action') != 'pause_and_drain'
                or not 0 < request.get('expires', 0) - now <= 120):
            return
        # Only AUDIT passive collectors are eligible for this maintenance path.
        if raw_status['fastpath_mode'] != 1 or raw_status['self_protect_enabled'] != 0:
            return
        self.seen = request['id']
        self.active = {**request, 'status': raw_status}
        self.policy(False)
        self.receipt('process_monitor_paused', raw_status=raw_status)

    def close(self, *, stopping=False):
        if self.active and not (stopping and self.drained):
            self.policy(True)
            self.receipt('aborted_and_process_monitor_resumed')
