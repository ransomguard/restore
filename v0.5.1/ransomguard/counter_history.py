"""Persist raw driver epochs; restarting a driver must not erase prior losses.

One collector owns this file. It is deliberately independent of raw-event
retention. A lower cumulative counter identifies a reset, not negative loss.
An unexpected reset has an unknown observation gap, never a zero-loss claim.
"""
import json
import os
from pathlib import Path
import time
import uuid

COUNTERS = ('events_generated', 'events_delivered', 'events_dropped',
            'events_flushed', 'processes_blocked', 'termination_requests_succeeded')


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False)
        stream.flush()
        os.fsync(stream.fileno())
    deadline = time.monotonic() + .5
    while True:
        try:
            temporary.replace(path)
            break
        except PermissionError:
            # Windows readers may briefly omit FILE_SHARE_DELETE. Preserve the
            # previous complete file and retry instead of truncating it.
            if time.monotonic() >= deadline:
                raise
            time.sleep(.01)


class CounterHistory:
    def __init__(self, path):
        self.path = Path(path) if path else None
        self.state = {'schema': 1, 'epochs': [], 'current': None}
        if self.path and self.path.exists():
            self.state = json.loads(self.path.read_text(encoding='utf-8'))
            if self.state.get('schema') != 1:
                raise ValueError('Unknown driver counter history schema')
        self.saved_at = 0

    def close_epoch(self, epoch_id, *, reason):
        """Updater calls ONLY after SCM confirms the old driver has unloaded.

        Explicit boundaries also work when the next driver generates more
        events than the previous one before its first status observation.
        """
        current = self.state['current']
        if current is None:
            if self.state['epochs'] and self.state['epochs'][-1]['id'] == epoch_id:
                return
            raise ValueError('Driver epoch identity mismatch')
        if current['id'] != epoch_id:
            raise ValueError('Driver epoch identity mismatch')
        current.update(ended_at=time.time(), boundary=reason)
        self.state['epochs'].append(current)
        self.state['current'] = None
        atomic_json(self.path, self.state)

    def observe(self, raw, *, force=False):
        if not self.path:
            return dict(raw)
        values = {key: raw[key] for key in COUNTERS}
        if any(type(value) is not int or value < 0 for value in values.values()):
            raise ValueError('Invalid cumulative driver counter')
        now = time.time()
        current = self.state['current']
        reset = current and any(values[key] < current['last'][key] for key in COUNTERS)
        if reset:
            current['ended_at'] = now
            current['boundary'] = 'counter_reset_observed; unloaded interval is not kernel coverage'
            self.state['epochs'].append(current)
            current = None
        if current is None:
            current = {'id': uuid.uuid4().hex, 'started_at': now, 'last': values}
            self.state['current'] = current
            force = True
        current['last'] = values
        current['observed_at'] = now
        totals = {key: values[key] + sum(epoch['last'][key] for epoch in self.state['epochs'])
                  for key in COUNTERS}
        self.state['totals'] = totals
        if force or reset or time.monotonic() - self.saved_at >= 2:
            atomic_json(self.path, self.state)
            self.saved_at = time.monotonic()
        return {**raw, **totals}
