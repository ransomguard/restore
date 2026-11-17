"""Durable, bounded live response dispatch independent of the intake thread.

Jobs and exact process identities are persisted before side effects. Old jobs
are retained for review, never replayed automatically after a process restart.
The callback owns its SQLite/IPC clients on the worker thread.
"""
import json
import threading
import time
import uuid

from .outbox import Outbox
from .response_ledger import ResponseLedger


class ResponseJobs:
    def __init__(self, outbox, callback, *, max_pending=32, clock=time.time):
        if type(max_pending) is not int or not 1 <= max_pending <= 128:
            raise ValueError('Invalid response queue bound')
        self.outbox, self.callback, self.clock = outbox, callback, clock
        self.max_pending = max_pending
        self.owner = uuid.uuid4().hex
        self.cancel = threading.Event()
        self.wake = threading.Event()
        self.active = threading.Event()
        self.ready = threading.Event()
        self.error = None
        self.thread = None
        ResponseLedger(outbox.db)
        outbox.db.executescript('''
          CREATE TABLE IF NOT EXISTS response_jobs (
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, pid INTEGER NOT NULL,
            generation INTEGER NOT NULL, track TEXT NOT NULL, created REAL NOT NULL,
            state TEXT NOT NULL, reason TEXT, payload TEXT NOT NULL,
            UNIQUE(pid,generation));
          CREATE INDEX IF NOT EXISTS response_jobs_ready ON response_jobs(owner,state,created);
        ''')
        with outbox.db:
            outbox.db.execute("UPDATE response_jobs SET state='REVIEW_REQUIRED',reason='previous_worker_ended_no_replay' WHERE state IN ('READY','RUNNING')")

    def enqueue(self, job):
        if self.cancel.is_set():
            return 'stopping'
        ResponseLedger._validate(job['pid'], job['generation'], job['id'])
        if job.get('track') not in ('A', 'B'):
            raise ValueError('Unknown response track')
        encoded = json.dumps(job, ensure_ascii=False, allow_nan=False)
        if len(encoded.encode('utf-8')) > 60_000:
            raise ValueError('Response evidence exceeds bounded payload')
        db = self.outbox.db
        with db:
            if db.execute('SELECT 1 FROM response_jobs WHERE pid=? AND generation=?', (job['pid'],job['generation'])).fetchone():
                return 'duplicate'
            pending = db.execute("SELECT count(*) FROM response_jobs WHERE owner=? AND state IN ('READY','RUNNING')", (self.owner,)).fetchone()[0]
            state = 'READY' if pending < self.max_pending else 'REVIEW_REQUIRED'
            reason = None if state == 'READY' else 'response_capacity_requires_review'
            db.execute('INSERT INTO response_jobs VALUES(?,?,?,?,?,?,?,?,?)',
                       (job['id'], self.owner, job['pid'], job['generation'], job['track'], self.clock(), state, reason, encoded))
            db.commit()
        self.wake.set()
        return state

    def start(self):
        self.thread = threading.Thread(target=self._run, name='live-response', daemon=True)
        self.thread.start()
        if not self.ready.wait(10) or self.error:
            raise RuntimeError('Response worker startup failed')
        return self

    def _run(self):
        try:
            with Outbox(self.outbox.path) as outbox:
                ledger = ResponseLedger(outbox.db)
                self.ready.set()
                while not self.cancel.is_set():
                    # Active covers selection too: a shutdown cannot unload the
                    # owning driver/module while a selected job begins.
                    self.active.set()
                    row = outbox.db.execute("SELECT id,payload FROM response_jobs WHERE owner=? AND state='READY' ORDER BY created,id LIMIT 1", (self.owner,)).fetchone()
                    if not row:
                        self.active.clear()
                        self.wake.wait(.1); self.wake.clear()
                        continue
                    id_, payload = row
                    with outbox.db:
                        outbox.db.execute("UPDATE response_jobs SET state='RUNNING' WHERE id=? AND state='READY'", (id_,))
                    job = json.loads(payload)
                    state, reason = 'REVIEW_REQUIRED', 'response_cancelled_before_start'
                    if not self.cancel.is_set():
                        if ledger.claim(incident_id=id_, pid=job['pid'], process_create_time=job['generation']):
                            try:
                                state, reason = self.callback(job, outbox, self.cancel)
                                if state not in ('RELEASED', 'REVIEW_REQUIRED'):
                                    raise ValueError('Response has no terminal state')
                            except Exception as error:
                                state, reason = 'REVIEW_REQUIRED', 'response_exception_' + type(error).__name__
                            ledger.finish(id_, state=state, reason=reason)
                        else:
                            reason = 'previous_durable_reservation_no_retry'
                    with outbox.db:
                        outbox.db.execute('UPDATE response_jobs SET state=?,reason=? WHERE id=?', (state, reason, id_))
                    self.active.clear()
                with outbox.db:
                    outbox.db.execute("UPDATE response_jobs SET state='REVIEW_REQUIRED',reason='worker_stopped_before_start' WHERE owner=? AND state='READY'", (self.owner,))
        except BaseException as error:
            self.error = type(error).__name__
        finally:
            self.active.clear()
            self.ready.set()

    def request_stop(self):
        self.cancel.set(); self.wake.set()

    @property
    def stopped(self):
        return self.thread is None or not self.thread.is_alive()

    def close(self):
        self.request_stop()
        if self.thread:
            self.thread.join(1)
            if self.thread.is_alive():
                raise RuntimeError('Response still running; keep driver and intake alive until quiescent')

