"""Crash-safe, at-most-once automatic response reservations.

An automatic action can cut outbound networking for the ENTIRE VM. An in-memory
LRU is not sufficient protection against duplicate actions after observer
restart. Claim the exact PID + kernel process-creation FILETIME durably before
any firewall/JEV/termination side effects. A crash leaves a pending reservation
that requires operator review; it must never silently retry.

This ledger is not a distributed transaction with the daemon. It records the
decision to *attempt* live response, never proof of WFP enforcement or recovery.
"""

from __future__ import annotations

from datetime import datetime, timezone
import sqlite3
from typing import Any


class ResponseLedger:
    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("Expected an outbox SQLite connection")
        self.db = connection
        self.db.execute("""CREATE TABLE IF NOT EXISTS live_response_attempts (
            incident_id TEXT PRIMARY KEY,
            pid INTEGER NOT NULL CHECK (pid > 0 AND pid <= 4294967295),
            process_create_time INTEGER NOT NULL CHECK (process_create_time > 0),
            claimed_at_utc TEXT NOT NULL,
            finished_at_utc TEXT,
            state TEXT NOT NULL,
            reason TEXT,
            UNIQUE(pid, process_create_time)
        )""")
        self.db.commit()

        self.db.execute('CREATE TABLE IF NOT EXISTS exempt_response_history AS SELECT * FROM live_response_attempts WHERE 0')
        self.db.execute('CREATE TABLE IF NOT EXISTS track_a_upgrade_history AS SELECT * FROM live_response_attempts WHERE 0')
        self.db.execute('CREATE UNIQUE INDEX IF NOT EXISTS track_a_upgrade_once ON track_a_upgrade_history(incident_id)')
        self.db.commit()

        self.db.execute('CREATE TABLE IF NOT EXISTS track_b_reassessment_history AS SELECT * FROM live_response_attempts WHERE 0')
        self.db.execute('CREATE UNIQUE INDEX IF NOT EXISTS track_b_reassessment_once ON track_b_reassessment_history(incident_id)')
        self.db.commit()

    def claim_track_b_reassessment(self, job) -> bool:
        from .late_track_b import REASON
        if job.get('track')!='B' or job.get('resume_b_review') is not True or job.get('previous_review_reason')!=REASON:return False
        self._validate(job['pid'],job['generation'],job['id'])
        self.db.execute('BEGIN IMMEDIATE')
        with self.db:
            row=self.db.execute('SELECT state,reason FROM live_response_attempts WHERE incident_id=? AND pid=? AND process_create_time=?',(job['id'],job['pid'],job['generation'])).fetchone()
            if row!=('REVIEW_REQUIRED',REASON) or self.db.execute('SELECT 1 FROM track_b_reassessment_history WHERE incident_id=?',(job['id'],)).fetchone():return False
            self.db.execute('INSERT INTO track_b_reassessment_history SELECT * FROM live_response_attempts WHERE incident_id=?',(job['id'],))
            self.db.execute("UPDATE live_response_attempts SET state='RESERVED',finished_at_utc=NULL,reason='new_track_b_evidence' WHERE incident_id=?",(job['id'],))
        return True

    def claim_track_a_upgrade(self, job) -> bool:
        from .late_track_a import valid_proof, REVIEW_REASONS
        if not valid_proof(job) or job.get('previous_review_reason') not in REVIEW_REASONS:
            return False
        self.db.execute('BEGIN IMMEDIATE')
        with self.db:
            row = self.db.execute('SELECT state,reason FROM live_response_attempts WHERE incident_id=? AND pid=? AND process_create_time=?',
                                  (job['id'], job['pid'], job['generation'])).fetchone()
            if row != ('REVIEW_REQUIRED', job['previous_review_reason']):
                return False
            if self.db.execute('SELECT 1 FROM track_a_upgrade_history WHERE incident_id=?', (job['id'],)).fetchone():
                return False
            self.db.execute('INSERT INTO track_a_upgrade_history SELECT * FROM live_response_attempts WHERE incident_id=?', (job['id'],))
            self.db.execute("UPDATE live_response_attempts SET state='RESERVED',finished_at_utc=NULL,reason='new_corroborated_track_a_evidence' WHERE incident_id=?", (job['id'],))
        return True

    @staticmethod
    def _validate(pid: int, process_create_time: int, incident_id: str) -> None:
        if type(pid) is not int or not 1 <= pid <= 0xFFFFFFFF:
            raise ValueError("Expected an exact Windows PID")
        if type(process_create_time) is not int or not 1 <= process_create_time <= 0x7FFFFFFFFFFFFFFF:
            raise ValueError("Expected an exact positive kernel FILETIME")
        if not isinstance(incident_id, str) or not 1 <= len(incident_id) <= 128:
            raise ValueError("Expected a bounded incident ID")

    def claim(self, *, incident_id: str, pid: int, process_create_time: int) -> bool:
        """Return True exactly once per process lifetime, even across restarts."""
        self._validate(pid, process_create_time, incident_id)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            # A prior exception is not a permanent grant for this process.
            # Re-evaluate current policy on the next eligible detection.
            self.db.execute("INSERT INTO exempt_response_history SELECT * FROM live_response_attempts WHERE pid=? AND process_create_time=? AND state='EXEMPTED'", (pid, process_create_time))
            self.db.execute("DELETE FROM live_response_attempts WHERE pid=? AND process_create_time=? AND state='EXEMPTED'", (pid, process_create_time))
            cursor = self.db.execute(
                """INSERT OR IGNORE INTO live_response_attempts
                   (incident_id,pid,process_create_time,claimed_at_utc,state)
                   VALUES (?,?,?,?,?)""",
                (incident_id, pid, process_create_time,
                 datetime.now(timezone.utc).isoformat(), "RESERVED"))
            was_claimed = cursor.rowcount == 1
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        return was_claimed

    def finish(self, incident_id: str, *, state: str, reason: str | None) -> None:
        if not isinstance(state, str) or state not in ("RELEASED", "REVIEW_REQUIRED", "EXEMPTED"):
            raise ValueError("Only terminal live-response states may be recorded")
        if reason is not None and (not isinstance(reason, str) or len(reason) > 256):
            raise ValueError("Reason must be a bounded string or None")
        with self.db:
            cursor = self.db.execute(
                """UPDATE live_response_attempts
                   SET finished_at_utc=?, state=?, reason=?
                   WHERE incident_id=? AND state='RESERVED'""",
                (datetime.now(timezone.utc).isoformat(), state, reason, incident_id))
            if cursor.rowcount != 1:
                raise ValueError("Unknown or already finished incident")

    def inspect(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Limit must be 1..1000")
        cursor = self.db.execute(
            """SELECT incident_id,pid,process_create_time,claimed_at_utc,
                      finished_at_utc,state,reason
               FROM live_response_attempts ORDER BY claimed_at_utc DESC LIMIT ?""", (limit,))
        keys = ("incident_id", "pid", "process_create_time", "claimed_at_utc",
                "finished_at_utc", "state", "reason")
        return [dict(zip(keys, row)) for row in cursor]
