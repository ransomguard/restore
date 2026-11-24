"""Durable event outbox. ACKs identify individual events; no silent queue eviction."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable
import uuid
from .storage_transaction import RecordConnection

# Local diagnostics remain exportable/unacknowledged, but must not consume
# capacity reserved for evidence still awaiting processing. Incident rows and
# candidates never qualify, even if their kind is accidentally reused.
LOCAL_DIAGNOSTICS = frozenset({
    'triage_identity_reset', 'triage_reset', 'triage_state_evicted',
    'observer_started', 'observer_stopped', 'driver_event_loss_observed',
    'intake_buffer_stopped',
})
EVENT_COLUMNS = 'sequence,event_id,incident_id,occurred_at,kind,payload,acknowledged_at'


class OutboxFull(RuntimeError):
    pass


class Outbox:
    def __init__(self, path: str | Path, *, max_pending: int = 100_000,
                 connection_factory=RecordConnection):
        if max_pending < 1:
            raise ValueError("max_pending must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_pending = max_pending
        self.local_diagnostics = False
        # UI ACKs and maintenance share this DB. A slow storage flush must not
        # kill the analysis worker at SQLite's default five-second busy limit.
        self.db = sqlite3.connect(self.path, factory=connection_factory, timeout=30)
        from .writer_admission import for_database
        self.db.writer_admission = for_database(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        # The resident driver owner services WAL outside the processing path.
        import os
        if os.environ.get('RANSOMGUARD_OWNED_WAL_MAINTENANCE') == str(os.getpid()):
            self.db.execute('PRAGMA wal_autocheckpoint=0')
        # Bound the indexed-write cache while preserving FULL WAL durability.
        self.db.execute("PRAGMA cache_size=-32768")
        self.db.execute("""CREATE TABLE IF NOT EXISTS events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            incident_id TEXT,
            occurred_at TEXT NOT NULL,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            acknowledged_at TEXT)""")
        self.db.commit()
        from .sqlite_counts import install_capacity_counter
        install_capacity_counter(self.db, queue="events")
        self.db.executescript(f'''
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS diagnostic_archive (
                sequence INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,
                incident_id TEXT,occurred_at TEXT NOT NULL,kind TEXT NOT NULL,
                payload TEXT NOT NULL,acknowledged_at TEXT);
            DROP VIEW IF EXISTS all_outbox_events;
            CREATE VIEW all_outbox_events AS
                SELECT {EVENT_COLUMNS} FROM events UNION ALL SELECT {EVENT_COLUMNS} FROM diagnostic_archive;
            CREATE TABLE IF NOT EXISTS intake_unprocessed (
                digest TEXT PRIMARY KEY,occurred_at TEXT NOT NULL,
                reason TEXT NOT NULL,raw BLOB NOT NULL);
            COMMIT;
        ''')

    def enable_local_diagnostics(self) -> int:
        """Move local bookkeeping atomically, without an ACK or data deletion."""
        # Static diagnostic kinds only: a partial index avoids scanning every
        # retained raw payload three times on a cold start.
        kinds = ','.join("'" + kind + "'" for kind in sorted(LOCAL_DIAGNOSTICS))
        where = f'incident_id IS NULL AND kind IN ({kinds})'
        self.db.execute('CREATE INDEX IF NOT EXISTS events_local_diagnostics ON events(event_id) WHERE ' + where)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            count = self.db.execute('SELECT COUNT(*) FROM events INDEXED BY events_local_diagnostics WHERE ' + where).fetchone()[0]
            self.db.execute('INSERT INTO diagnostic_archive SELECT ' + EVENT_COLUMNS + ' FROM events WHERE ' + where)
            self.db.execute('DELETE FROM events WHERE ' + where)
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        self.local_diagnostics = True
        return count

    def preserve_intake(self, records, reason='observer_interrupted_before_processing') -> int:
        """Retain exact bytes for review; never replay stale evidence as live authorization."""
        import hashlib
        now = datetime.now(timezone.utc).isoformat()
        rows = [(hashlib.sha256(raw).hexdigest(), now, reason, bytes(raw)) for raw in records]
        with self.db:
            self.db.executemany('INSERT OR IGNORE INTO intake_unprocessed VALUES(?,?,?,?)', rows)
        return len(rows)

    def append(self, kind: str, payload: dict[str, Any], *, incident_id: str | None = None) -> str:
        event_id = str(uuid.uuid4())
        occurred_at = datetime.now(timezone.utc).isoformat()
        serialized = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        # Serialize capacity checking and append across cooperating processes.
        if not self.db.record_active:
            self.db.execute("BEGIN IMMEDIATE")
        try:
            pending = self.db.execute("SELECT pending FROM events_capacity WHERE singleton=1").fetchone()[0]
            diagnostic = self.local_diagnostics and incident_id is None and kind in LOCAL_DIAGNOSTICS
            if pending >= self.max_pending and self.local_diagnostics and not diagnostic:
                from .retention import release_completed_capacity
                release_completed_capacity(self.db)
                pending = self.db.execute('SELECT pending FROM events_capacity WHERE singleton=1').fetchone()[0]
            if pending >= self.max_pending and not diagnostic:
                raise OutboxFull("Outbox capacity reached; unacknowledged records were retained")
            self.db.execute("INSERT INTO events(event_id,incident_id,occurred_at,kind,payload) VALUES(?,?,?,?,?)",
                            (event_id, incident_id, occurred_at, kind, serialized))
            if diagnostic:
                self.db.execute('INSERT INTO diagnostic_archive SELECT ' + EVENT_COLUMNS + ' FROM events WHERE event_id=?', (event_id,))
                self.db.execute('DELETE FROM events WHERE event_id=?', (event_id,))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        if kind != 'kernel_event':
            try:
                from .console_stream import audit
                audit(self.path.parent, kind, payload, event_id, incident_id, occurred_at, self.db.record_active)
            except Exception:
                pass # Console disconnects cannot change durable response behavior.
        return event_id

    def pending(self, limit: int = 100) -> list[dict[str, Any]]:
        """All unacknowledged evidence, including retained raw and diagnostics.

        This export/ACK backlog is deliberately distinct from intake capacity.
        """
        if not 1 <= limit <= 10_000:
            raise ValueError("limit outside supported range")
        rows = self.db.execute("SELECT sequence,event_id,incident_id,occurred_at,kind,payload FROM all_outbox_events "
                               "WHERE acknowledged_at IS NULL ORDER BY sequence LIMIT ?", (limit,)).fetchall()
        return [{"schema_version": 1, "sequence": row[0], "event_id": row[1], "incident_id": row[2],
                 "occurred_at_utc": row[3], "event_type": row[4], "data": json.loads(row[5])} for row in rows]

    def acknowledge(self, event_ids: Iterable[str], *, sent_ids: Iterable[str]) -> None:
        ids = list(event_ids)
        allowed = set(sent_ids)
        if len(ids) != len(set(ids)) or not set(ids).issubset(allowed):
            raise ValueError("ACK contains duplicate or unsent event IDs")
        now = datetime.now(timezone.utc).isoformat()
        with self.db:
            for table in ('events', 'diagnostic_archive'):
                self.db.executemany(f"UPDATE {table} SET acknowledged_at=? WHERE event_id=? AND acknowledged_at IS NULL",
                                    [(now, item) for item in ids])

    def export_jsonl(self, destination: str | Path) -> int:
        count = 0
        with Path(destination).open("w", encoding="utf-8") as stream:
            for row in self.db.execute("SELECT sequence,event_id,incident_id,occurred_at,kind,payload,acknowledged_at "
                                       "FROM all_outbox_events ORDER BY sequence"):
                stream.write(json.dumps({"schema_version": 1, "sequence": row[0], "event_id": row[1],
                                         "incident_id": row[2], "occurred_at_utc": row[3], "event_type": row[4],
                                         "data": json.loads(row[5]), "acknowledged_at": row[6]}, ensure_ascii=False) + "\n")
                count += 1
            import base64
            for digest, occurred_at, reason, raw in self.db.execute('SELECT * FROM intake_unprocessed ORDER BY occurred_at,digest'):
                stream.write(json.dumps({'schema_version': 1, 'event_type': 'intake_unprocessed',
                    'event_id': 'raw-sha256:' + digest, 'occurred_at_utc': occurred_at,
                    'data': {'reason': reason, 'raw_base64': base64.b64encode(raw).decode('ascii'),
                             'automatic_response_authorized': False}}) + '\n')
                count += 1
        return count

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Outbox":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
