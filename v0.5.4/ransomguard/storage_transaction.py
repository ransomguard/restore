"""One durable commit for a passive event, its retention state and UI enqueue."""
from contextlib import contextmanager
import sqlite3
import time


class RecordConnection(sqlite3.Connection):
    record_active = False
    record_failed = False
    writer_admission = None
    writer_admitted = False

    def execute(self, sql, parameters=()):
        # All automatic-response reservations/appends and passive batches use
        # explicit BEGIN IMMEDIATE. Hold admission for the actual transaction,
        # never across firewall calls, JEV, recovery, or the kernel read loop.
        begin = sql.strip().rstrip(';').upper() == 'BEGIN IMMEDIATE'
        acquired = False
        if begin and not self.in_transaction and self.writer_admission is not None:
            self.writer_admission.acquire(self)
            self.writer_admitted = acquired = True
        try:
            return super().execute(sql, parameters)
        except BaseException:
            if acquired:self._release_writer()
            raise
        finally:
            if self.writer_admitted and not self.in_transaction:self._release_writer()

    def executescript(self, script):
        try:
            return super().executescript(script)
        finally:
            if self.writer_admitted and not self.in_transaction:self._release_writer()

    def _release_writer(self):
        if self.writer_admitted:
            self.writer_admitted = False
            self.writer_admission.release(self)

    def commit(self):
        if not self.record_active:
            try:
                return super().commit()
            finally:
                if not self.in_transaction:self._release_writer()

    def rollback(self):
        if self.record_active:
            self.record_failed = True
        try:
            return super().rollback()
        finally:
            if not self.in_transaction:self._release_writer()

    def __exit__(self, kind, error, traceback):
        if self.record_active:
            if kind is not None:
                self.rollback()
            return False
        try:
            return super().__exit__(kind, error, traceback)
        finally:
            if not self.in_transaction:self._release_writer()

    def close(self):
        try:
            return super().close()
        finally:
            self._release_writer()

    @contextmanager
    def atomic_record(self):
        if self.in_transaction or self.record_active:
            raise RuntimeError('A record transaction cannot be nested')
        self.execute('BEGIN IMMEDIATE')
        self.record_active = True
        self.record_failed = False
        try:
            yield
            if self.record_failed:
                raise RuntimeError('A record write failed and was rolled back')
            super().commit()
        except BaseException:
            super().rollback()
            raise
        finally:
            self.record_active = False
            if not self.in_transaction:self._release_writer()


class PassiveBatch:
    """Bounded commits for passive intake; retain every uncommitted raw on error.

    Call flush before blocking reads, status/maintenance, or worker shutdown.
    Synchronous response never uses this class. Asynchronous jobs become
    visible only after commit; a separate ledger reservation precedes effects.
    """
    def __init__(self, outbox, *, limit=32, max_seconds=.02, clock=time.monotonic):
        if not 1 <= limit <= 256 or not 0 < max_seconds <= .05:
            raise ValueError('Invalid passive storage batch bounds')
        self.outbox=outbox;self.limit=limit;self.max_seconds=max_seconds;self.clock=clock
        self.scope=None;self.raws=[];self.started=0

    def flush(self):
        if self.scope is None:return
        scope,self.scope=self.scope,None
        raws,self.raws=self.raws,[]
        try:scope.__exit__(None,None,None)
        except BaseException:
            self.outbox.preserve_intake(raws,'passive_batch_commit_failed_no_live_replay')
            raise

    @contextmanager
    def record(self,raw):
        if self.scope is None:
            scope=self.outbox.db.atomic_record();scope.__enter__()
            self.scope=scope;self.started=self.clock()
        self.raws.append(raw)
        try:
            yield
        except BaseException as error:
            scope,self.scope=self.scope,None
            raws,self.raws=self.raws,[]
            scope.__exit__(type(error),error,error.__traceback__)
            self.outbox.preserve_intake(raws,'passive_batch_processing_failed_no_live_replay')
            raise
        if len(self.raws)>=self.limit or self.clock()-self.started>=self.max_seconds:
            self.flush()

