"""Durable event outbox. ACKs identify individual events; no silent queue eviction."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable
import uuid


class OutboxFull(RuntimeError):
    pass


class Outbox:
    def __init__(self, path: str | Path, *, max_pending: int = 100_000):
        if max_pending < 1:
            raise ValueError("max_pending must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_pending = max_pending
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            incident_id TEXT,
            occurred_at TEXT NOT NULL,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            acknowledged_at TEXT)""")
        self.db.commit()

    def append(self, kind: str, payload: dict[str, Any], *, incident_id: str | None = None) -> str:
        event_id = str(uuid.uuid4())
        occurred_at = datetime.now(timezone.utc).isoformat()
        serialized = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        # Serialize capacity checking and append across cooperating processes.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            pending = self.db.execute("SELECT COUNT(*) FROM events WHERE acknowledged_at IS NULL").fetchone()[0]
            if pending >= self.max_pending:
                raise OutboxFull("Outbox capacity reached; unacknowledged records were retained")
            self.db.execute("INSERT INTO events(event_id,incident_id,occurred_at,kind,payload) VALUES(?,?,?,?,?)",
                            (event_id, incident_id, occurred_at, kind, serialized))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        return event_id

    def pending(self, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 10_000:
            raise ValueError("limit outside supported range")
        rows = self.db.execute("SELECT sequence,event_id,incident_id,occurred_at,kind,payload FROM events "
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
            self.db.executemany("UPDATE events SET acknowledged_at=? WHERE event_id=? AND acknowledged_at IS NULL",
                                [(now, item) for item in ids])

    def export_jsonl(self, destination: str | Path) -> int:
        count = 0
        with Path(destination).open("w", encoding="utf-8") as stream:
            for row in self.db.execute("SELECT sequence,event_id,incident_id,occurred_at,kind,payload,acknowledged_at "
                                       "FROM events ORDER BY sequence"):
                stream.write(json.dumps({"schema_version": 1, "sequence": row[0], "event_id": row[1],
                                         "incident_id": row[2], "occurred_at_utc": row[3], "event_type": row[4],
                                         "data": json.loads(row[5]), "acknowledged_at": row[6]}, ensure_ascii=False) + "\n")
                count += 1
        return count

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Outbox":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
