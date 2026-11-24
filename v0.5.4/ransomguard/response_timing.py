"""Response-worker-only timing. No tracing on the raw collector/analysis DB."""
import time
from .outbox import Outbox
from .storage_transaction import RecordConnection


class TimedConnection(RecordConnection):
    response_trace = None
    operation = 'startup'

    def note(self, phase, start):
        trace = self.response_trace
        if trace is not None and len(trace) < 192:
            trace.append({'operation': self.operation, 'phase': phase,
                          'seconds': time.perf_counter()-start})

    def execute(self, sql, parameters=()):
        start = time.perf_counter()
        try:
            return super().execute(sql, parameters)
        finally:
            phase = 'begin_immediate' if sql.strip().upper().startswith('BEGIN IMMEDIATE') else 'sql_' + sql.strip().split()[0].lower()
            self.note(phase, start)

    def commit(self):
        start = time.perf_counter()
        try:
            return super().commit()
        finally:
            self.note('commit', start)


class ResponseOutbox(Outbox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, connection_factory=TimedConnection, **kwargs)

    def append(self, kind, payload, *, incident_id=None):
        self.db.operation = kind
        start = time.perf_counter()
        try:
            return super().append(kind, payload, incident_id=incident_id)
        finally:
            self.db.note('append_total', start)

    def start_response_timing(self):
        self.db.response_trace = []

    def note_response_timing(self, phase, start):
        self.db.note(phase, start)

    def finish_response_timing(self, incident_id):
        trace, self.db.response_trace = self.db.response_trace, None
        if trace is not None:
            self.append('response_path_timing', {'schema': 1, 'clock': 'perf_counter',
                'measurements': trace, 'bounded_entries': 192,
                'nested_measurements_do_not_sum': True}, incident_id=incident_id)
