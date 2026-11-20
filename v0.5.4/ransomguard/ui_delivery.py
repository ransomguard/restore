"""Durable local UI delivery, independent of the raw forensic outbox ACKs.

The UI must commit its receipt and log atomically. Every new eligible file event
is enqueued. SYSTEM_STATUS is transient and coalesced, never replayed.
"""
from __future__ import annotations
import json
import sqlite3
import threading
import uuid
from contextlib import nullcontext
from .ui_pipe import WindowsUiPipe, encode_ui_jsonl, LEGACY_BATCH_ITEMS, MAX_BATCH_ITEMS


class DurableUiDelivery:
    def __init__(self, path, *, transport_factory=None, max_pending=100_000):
        self.db = sqlite3.connect(path, timeout=30, check_same_thread=False)
        import os
        if os.environ.get('RANSOMGUARD_OWNED_WAL_MAINTENANCE') == str(os.getpid()):
            self.db.execute('PRAGMA wal_autocheckpoint=0')
        self.db.execute("PRAGMA cache_size=-8192")
        self.db.execute("CREATE TABLE IF NOT EXISTS ui_pending(position INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL)")
        self.db.commit()
        from .retention import initialize
        initialize(self.db)
        from .sqlite_counts import install_capacity_counter
        install_capacity_counter(self.db, queue="ui_pending")
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.wake = threading.Event()
        # Large retained UI histories can take >2s to commit and acknowledge.
        # Intake is independent; retain rows until the real commit ACK arrives.
        self.factory = transport_factory or (lambda: WindowsUiPipe(timeout_ms=2000, duplex=True, ack_timeout_ms=10_000))
        self.max_pending = max_pending
        self.status = None
        self.last_error = None
        self.acked = 0
        self.thread = None
        self.enqueue_db = None
        self.batch_limit = LEGACY_BATCH_ITEMS
        self.capacity_table_supported = 'capacity_released' in {r[1] for r in self.db.execute('PRAGMA table_info(events)')}

    def use_enqueue_connection(self, db):
        # Only the producer thread uses this connection. Delivery/ACKs keep their
        # independent connection and cannot see an enqueue before its commit.
        own = self.db.execute('PRAGMA database_list').fetchone()[2]
        other = db.execute('PRAGMA database_list').fetchone()[2]
        if own != other:
            raise ValueError('UI enqueue must share the same outbox database')
        self.enqueue_db = db
        self.capacity_table_supported = 'capacity_released' in {r[1] for r in db.execute('PRAGMA table_info(events)')}

    def send(self, message):
        return self.send_tracked(message)

    def send_tracked(self, message, *, event_id=None, incident_id=None):
        encoded = encode_ui_jsonl(message).decode().strip()
        if len(encoded) > 60_000:
            raise ValueError("UI message leaves no envelope space")
        shared = self.enqueue_db is not None and message.get('type') != 'SYSTEM_STATUS'
        db = self.enqueue_db if shared else self.db
        # Do not acquire the delivery lock while holding a SQLite write lock:
        # an ACK worker could already hold that lock while waiting for SQLite.
        with (nullcontext() if shared else self.lock), db:
            if message.get("type") == "SYSTEM_STATUS":
                self.status = message
            else:
                if db.execute("SELECT pending FROM ui_pending_capacity WHERE singleton=1").fetchone()[0] >= self.max_pending:
                    raise RuntimeError("Durable UI queue full; raw outbox retained, intake stopped")
                delivery_id=str(uuid.uuid4())
                db.execute("INSERT INTO ui_pending(id,payload) VALUES(?,?)", (delivery_id, encoded))
                if event_id or incident_id:
                    db.execute("INSERT INTO ui_delivery_tracking(delivery_id,event_id,incident_id) VALUES(?,?,?)",(delivery_id,event_id,incident_id))
                db.commit()
        self.wake.set()

    def drain_once(self):
        with self.lock:
            rows = self.db.execute("SELECT id,payload FROM ui_pending ORDER BY position LIMIT ?", (self.batch_limit,)).fetchall()
            status, self.status = self.status, None
        items = []
        for id_, payload in rows:
            candidate = items + [{"id": id_, "message": json.loads(payload)}]
            try:
                encode_ui_jsonl({"deliveryVersion": 1, "items": candidate})
            except ValueError:
                break
            items = candidate
        # Opening an idle pipe makes the UI write connection logs, which the
        # kernel observes as new file events. Do not generate work from idleness.
        if not items and status is None:
            return False
        with self.factory() as pipe:
            if items:
                try:
                    ack = pipe.exchange(items)
                except (OSError, ValueError):
                    # A restarted/older UI may no longer support larger frames.
                    # Retain all rows and retry the legacy envelope size.
                    self.batch_limit = LEGACY_BATCH_ITEMS
                    raise
                # Independently validate transport ACKs before removing anything.
                allowed = {item["id"] for item in items}
                if not isinstance(ack, list) or any(not isinstance(x, str) or x not in allowed for x in ack):
                    raise ValueError("Unexpected UI receipt")
                if not ack:
                    raise OSError("UI did not acknowledge the pending batch")
                advertised = getattr(pipe, 'peer_batch_limit', LEGACY_BATCH_ITEMS)
                self.batch_limit = min(advertised, MAX_BATCH_ITEMS) if type(advertised) is int and advertised >= LEGACY_BATCH_ITEMS else LEGACY_BATCH_ITEMS
                with self.lock, self.db:
                    self.db.executemany("UPDATE ui_delivery_tracking SET acked=1 WHERE delivery_id=?",[(x,) for x in ack])
                    self.db.executemany("UPDATE raw_retention SET ui_state='acked' WHERE event_id=(SELECT event_id FROM ui_delivery_tracking WHERE delivery_id=?)",[(x,) for x in ack])
                    if self.capacity_table_supported:
                        self.db.executemany("""UPDATE events SET capacity_released=1
                            WHERE event_id=(SELECT event_id FROM ui_delivery_tracking WHERE delivery_id=?)
                              AND capacity_released=0 AND kind='kernel_event'
                              AND EXISTS(SELECT 1 FROM raw_retention r WHERE r.event_id=events.event_id
                                AND r.processed IS NOT NULL AND r.ui_state='acked')""",[(x,) for x in ack])
                    self.db.executemany("DELETE FROM ui_pending WHERE id=?", [(x,) for x in ack])
                    self.db.commit()
                    self.acked += len(set(ack))
            if status:
                pipe.send(status)
        return bool(items)

    def _run(self):
        while not self.stop.is_set():
            try:
                more = self.drain_once()
                self.last_error = None
                if more:
                    continue
            except (OSError, ValueError, sqlite3.Error) as error:
                self.last_error = str(error)
                self.stop.wait(1)
            self.wake.wait(.5)
            self.wake.clear()

    def diagnostics(self):
        with self.lock:
            return {"pending": self.db.execute("SELECT pending FROM ui_pending_capacity WHERE singleton=1").fetchone()[0],
                    "acknowledged": self.acked, "last_error": self.last_error,
                    "batch_limit": self.batch_limit}

    def __enter__(self):
        self.thread = threading.Thread(target=self._run, name="ui-delivery", daemon=True)
        self.thread.start()
        return self

    def close(self):
        self.stop.set(); self.wake.set()
        if self.thread:
            self.thread.join(45)
            if self.thread.is_alive():
                raise RuntimeError("UI worker did not stop; database left open")
        self.db.close()

    def __exit__(self, *args):
        self.close()
