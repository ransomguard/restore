"""Durable local UI delivery, independent of the raw forensic outbox ACKs.

The UI must commit its receipt and log atomically. File-event sampling still
applies before enqueue. SYSTEM_STATUS is transient and coalesced, never replayed.
"""
from __future__ import annotations
import json
import sqlite3
import threading
import uuid
from .ui_pipe import WindowsUiPipe, encode_ui_jsonl


class DurableUiDelivery:
    def __init__(self, path, *, transport_factory=None, max_pending=100_000):
        self.db = sqlite3.connect(path, timeout=5, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS ui_pending(position INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL)")
        self.db.commit()
        from .retention import initialize
        initialize(self.db)
        from .sqlite_counts import install_capacity_counter
        install_capacity_counter(self.db, queue="ui_pending")
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.factory = transport_factory or (lambda: WindowsUiPipe(timeout_ms=2000, duplex=True))
        self.max_pending = max_pending
        self.status = None
        self.last_error = None
        self.acked = 0
        self.thread = None

    def send(self, message):
        return self.send_tracked(message)

    def send_tracked(self, message, *, event_id=None, incident_id=None):
        encoded = encode_ui_jsonl(message).decode().strip()
        if len(encoded) > 60_000:
            raise ValueError("UI message leaves no envelope space")
        with self.lock, self.db:
            if message.get("type") == "SYSTEM_STATUS":
                self.status = message
            else:
                if self.db.execute("SELECT pending FROM ui_pending_capacity WHERE singleton=1").fetchone()[0] >= self.max_pending:
                    raise RuntimeError("Durable UI queue full; raw outbox retained, intake stopped")
                delivery_id=str(uuid.uuid4())
                self.db.execute("INSERT INTO ui_pending(id,payload) VALUES(?,?)", (delivery_id, encoded))
                if event_id or incident_id:
                    self.db.execute("INSERT INTO ui_delivery_tracking(delivery_id,event_id,incident_id) VALUES(?,?,?)",(delivery_id,event_id,incident_id))
                self.db.commit()
        self.wake.set()

    def drain_once(self):
        with self.lock:
            rows = self.db.execute("SELECT id,payload FROM ui_pending ORDER BY position LIMIT 20").fetchall()
            status, self.status = self.status, None
        items = []
        for id_, payload in rows:
            candidate = items + [{"id": id_, "message": json.loads(payload)}]
            try:
                encode_ui_jsonl({"deliveryVersion": 1, "items": candidate})
            except ValueError:
                break
            items = candidate
        with self.factory() as pipe:
            if items:
                ack = pipe.exchange(items)
                # Independently validate transport ACKs before removing anything.
                allowed = {item["id"] for item in items}
                if not isinstance(ack, list) or any(not isinstance(x, str) or x not in allowed for x in ack):
                    raise ValueError("Unexpected UI receipt")
                if not ack:
                    raise OSError("UI did not acknowledge the pending batch")
                with self.lock, self.db:
                    self.db.executemany("UPDATE ui_delivery_tracking SET acked=1 WHERE delivery_id=?",[(x,) for x in ack])
                    self.db.executemany("UPDATE raw_retention SET ui_state='acked' WHERE event_id=(SELECT event_id FROM ui_delivery_tracking WHERE delivery_id=?)",[(x,) for x in ack])
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
                    "acknowledged": self.acked, "last_error": self.last_error}

    def __enter__(self):
        self.thread = threading.Thread(target=self._run, name="ui-delivery", daemon=True)
        self.thread.start()
        return self

    def close(self):
        self.stop.set(); self.wake.set()
        if self.thread:
            self.thread.join(7)
            if self.thread.is_alive():
                raise RuntimeError("UI worker did not stop; database left open")
        self.db.close()

    def __exit__(self, *args):
        self.close()
