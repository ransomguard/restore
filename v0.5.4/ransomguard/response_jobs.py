"""Durable, bounded live response dispatch independent of the intake thread.

Jobs and exact process identities are persisted before side effects. Old jobs
are retained for review, never replayed automatically after a process restart.
The callback owns its SQLite/IPC clients on the worker thread.
"""
import json
import threading
import time
import uuid
import sqlite3
import traceback

from .outbox import Outbox
from .response_timing import ResponseOutbox
from .response_ledger import ResponseLedger
from .late_track_a import valid_proof, promote


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
          CREATE TABLE IF NOT EXISTS response_track_a_updates (
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL);
        ''')
        with outbox.db:
            outbox.db.execute("UPDATE response_jobs SET state='REVIEW_REQUIRED',reason='previous_worker_ended_no_replay' WHERE state IN ('READY','RUNNING')")

    def enqueue(self, job):
        from pathlib import Path
        from .scope_settings import scope_lock, ScopeBusy
        try:
            with scope_lock(Path(self.outbox.path).parent,dispatch=True):
                return self._enqueue(job)
        except ScopeBusy:
            return 'scope_change_in_progress'

    def _enqueue(self, job):
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
            db.execute("DELETE FROM response_jobs WHERE pid=? AND generation=? AND state='EXEMPTED'", (job['pid'],job['generation']))
            previous = db.execute('SELECT id,owner,track,state FROM response_jobs WHERE pid=? AND generation=?', (job['pid'],job['generation'])).fetchone()
            if previous:
                if (previous[1] == self.owner and previous[2] == 'B'
                        and previous[3] in ('READY','RUNNING','REVIEW_REQUIRED') and valid_proof(job)):
                    db.execute("INSERT OR IGNORE INTO response_track_a_updates VALUES(?,?,?,'waiting')",
                               (previous[0], self.owner, encoded))
                    promoted = promote(db, self.owner, previous[0])
                    job['id'] = previous[0]
                    db.commit()
                    self.wake.set()
                    return 'TRACK_A_PROMOTED' if promoted else 'TRACK_A_EVIDENCE_RETAINED'
                from .late_track_b import promote as promote_b
                pending = db.execute("SELECT count(*) FROM response_jobs WHERE owner=? AND state IN ('READY','RUNNING')", (self.owner,)).fetchone()[0]
                if pending < self.max_pending and promote_b(db,self.owner,previous[0],job):
                    job['id']=previous[0]
                    db.commit();self.wake.set()
                    return 'TRACK_B_NEW_EVIDENCE_REASSESSMENT'
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
            with ResponseOutbox(self.outbox.path) as outbox:
                ledger = ResponseLedger(outbox.db)
                self.ready.set()
                while not self.cancel.is_set():
                    # Active covers selection too: a shutdown cannot unload the
                    # owning driver/module while a selected job begins.
                    self.active.set()
                    # Selection and payload are atomic with a READY upgrade.
                    row = None
                    if outbox.db.execute("SELECT 1 FROM response_jobs WHERE owner=? AND state='READY' LIMIT 1", (self.owner,)).fetchone():
                        outbox.db.execute('BEGIN IMMEDIATE')
                        with outbox.db:
                            row = outbox.db.execute("SELECT id,payload FROM response_jobs WHERE owner=? AND state='READY' ORDER BY created,id LIMIT 1", (self.owner,)).fetchone()
                            if row:
                                outbox.db.execute("UPDATE response_jobs SET state='RUNNING' WHERE id=? AND state='READY'", (row[0],))
                    if not row:
                        self.active.clear()
                        self.wake.wait(.1); self.wake.clear()
                        continue
                    id_, payload = row
                    job = json.loads(payload)
                    state, reason = 'REVIEW_REQUIRED', 'response_cancelled_before_start'
                    if not self.cancel.is_set():
                        claimed = (ledger.claim_track_b_reassessment(job) if job.get('resume_b_review') else
                                   ledger.claim_track_a_upgrade(job) if job.get('resume_jev_review') else
                                   ledger.claim(incident_id=id_, pid=job['pid'], process_create_time=job['generation']))
                        if claimed:
                            try:
                                state, reason = self.callback(job, outbox, self.cancel)
                                if state not in ('RELEASED', 'REVIEW_REQUIRED', 'EXEMPTED'):
                                    raise ValueError('Response has no terminal state')
                            except Exception as error:
                                state, reason = 'REVIEW_REQUIRED', 'response_exception_' + type(error).__name__
                                if isinstance(error, sqlite3.Error):
                                    try:
                                        outbox.append('response_storage_error', {
                                            'error_type': type(error).__name__,
                                            'sqlite_errorname': getattr(error, 'sqlite_errorname', None),
                                            'frames': [{'function': f.name, 'line': f.lineno}
                                                       for f in traceback.extract_tb(error.__traceback__)[-6:]],
                                        }, incident_id=id_)
                                    except sqlite3.Error:
                                        # Diagnostic storage must not skip the durable review outcome.
                                        pass
                            try:
                                outbox.finish_response_timing(id_)
                            except (OSError, sqlite3.Error):
                                # Timing is diagnostic, never a new enforcement gate.
                                pass
                            ledger.finish(id_, state=state, reason=reason)
                        else:
                            reason = 'previous_durable_reservation_no_retry'
                    with outbox.db:
                        outbox.db.execute('UPDATE response_jobs SET state=?,reason=? WHERE id=?', (state, reason, id_))
                        promote(outbox.db, self.owner, id_)
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

