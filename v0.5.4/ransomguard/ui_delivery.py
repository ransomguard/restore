"""Durable local UI delivery, independent of the raw forensic outbox ACKs.

The UI must commit its receipt and log atomically. Every new eligible file event
is enqueued. SYSTEM_STATUS is transient and coalesced, never replayed.
"""
from __future__ import annotations
import json
import os
import sqlite3
import threading
import uuid
import time
import shutil
from pathlib import Path
from contextlib import nullcontext, contextmanager
from .ui_pipe import WindowsUiPipe, encode_ui_jsonl, LEGACY_BATCH_ITEMS, MAX_BATCH_ITEMS, MAX_MESSAGE_BYTES


def build_delivery_items(rows):
    """Select the same bounded prefix without re-encoding every growing prefix."""
    size = len(encode_ui_jsonl({"deliveryVersion": 1, "items": []}))
    items = []
    for id_, payload in rows:
        item = {"id": id_, "message": json.loads(payload)}
        # Each JSONL item includes a newline; envelopes need commas instead.
        try:
            addition = len(encode_ui_jsonl(item)) - 1 + bool(items)
        except ValueError:
            break
        if size + addition > MAX_MESSAGE_BYTES:
            break
        size += addition
        items.append(item)
    return items


@contextmanager
def resident_delivery(owner, path):
    """Keep committed UI delivery alive across a failed analysis worker.

    The owner is the resident args object, retained across worker generations.
    No new event is analysed here; only existing UI receipts are processed.
    """
    sink = getattr(owner, '_retained_ui_delivery', None)
    if sink is None:
        sink = DurableUiDelivery(path).__enter__()
        owner._retained_ui_delivery = sink
    failed = False
    try:
        yield sink
    except BaseException:
        failed = True
        raise
    finally:
        # Never retain the failed worker's soon-to-be-closed producer connection.
        sink.enqueue_db = None
        if not failed:
            sink.close()
            owner._retained_ui_delivery = None


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
        self.last_status_pid = None
        self.last_status_at = None
        self.next_report = 0.0
        self.acked = 0
        self.thread = None
        self.timings = {'batches': 0, 'exchange_seconds': 0.0, 'ack_db_seconds': 0.0,
                        'max_exchange_seconds': 0.0, 'max_ack_db_seconds': 0.0}
        self.enqueue_db = None
        self.batch_limit = LEGACY_BATCH_ITEMS
        self.detached_ui = False
        self.spool_byte_limit = 512*1024*1024
        self.disk_reserve = 2*1024*1024*1024
        self._disk_checked = 0.0
        self._disk_free = 0
        self.path = Path(path).absolute()
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

    def enable_detached_spool(self):
        # Install once, with an atomic initial count. ACK/delete triggers keep
        # the budget exact without repeated scans or in-memory event copies.
        with self.lock:
            # Response publishers open a short-lived sink on the same database.
            # Reuse the initialized accounting without scanning the backlog or
            # taking a schema write lock for every completed response.
            objects = {r[0] for r in self.db.execute(
                "SELECT name FROM sqlite_master WHERE name IN "
                "('ui_spool_bytes','ui_spool_insert','ui_spool_delete','ui_spool_update')")}
            if len(objects) == 4 and self.db.execute(
                    'SELECT 1 FROM ui_spool_bytes WHERE singleton=1').fetchone():
                self.detached_ui = True
                return
            self.db.executescript('''BEGIN IMMEDIATE;
              CREATE TABLE IF NOT EXISTS ui_spool_bytes(singleton INTEGER PRIMARY KEY CHECK(singleton=1),bytes INTEGER NOT NULL);
              INSERT OR IGNORE INTO ui_spool_bytes SELECT 1,COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM ui_pending;
              CREATE TRIGGER IF NOT EXISTS ui_spool_insert AFTER INSERT ON ui_pending BEGIN
                UPDATE ui_spool_bytes SET bytes=bytes+length(CAST(NEW.payload AS BLOB)) WHERE singleton=1; END;
              CREATE TRIGGER IF NOT EXISTS ui_spool_delete AFTER DELETE ON ui_pending BEGIN
                UPDATE ui_spool_bytes SET bytes=bytes-length(CAST(OLD.payload AS BLOB)) WHERE singleton=1; END;
              CREATE TRIGGER IF NOT EXISTS ui_spool_update AFTER UPDATE OF payload ON ui_pending BEGIN
                UPDATE ui_spool_bytes SET bytes=bytes+length(CAST(NEW.payload AS BLOB))-length(CAST(OLD.payload AS BLOB)) WHERE singleton=1; END;
              COMMIT;''')
            self.detached_ui = True

    def check_spool_budget(self, db, encoded):
        used=db.execute('SELECT bytes FROM ui_spool_bytes WHERE singleton=1').fetchone()[0]
        if used+len(encoded.encode('utf8'))>self.spool_byte_limit:
            raise RuntimeError('Durable UI spool byte budget exhausted; evidence retained')
        now=time.monotonic()
        if now-self._disk_checked>=1 or not self._disk_checked:
            self._disk_free=shutil.disk_usage(self.path.parent).free
            self._disk_checked=now
        if self._disk_free<self.disk_reserve:
            raise RuntimeError('Durable UI spool disk reserve exhausted; evidence retained')

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
                if self.detached_ui:
                    self.check_spool_budget(db,encoded)
                elif db.execute("SELECT pending FROM ui_pending_capacity WHERE singleton=1").fetchone()[0] >= self.max_pending:
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
        items = build_delivery_items(rows)
        # Opening an idle pipe makes the UI write connection logs, which the
        # kernel observes as new file events. Do not generate work from idleness.
        if not items and status is None:
            return False
        with self.factory() as pipe:
            if items:
                try:
                    exchange_started = time.monotonic()
                    ack = pipe.exchange(items)
                except (OSError, ValueError):
                    # A restarted/older UI may no longer support larger frames.
                    # Retain all rows and retry the legacy envelope size.
                    self.batch_limit = LEGACY_BATCH_ITEMS
                    raise
                exchange_elapsed = time.monotonic() - exchange_started
                self.timings['exchange_seconds'] += exchange_elapsed
                self.timings['max_exchange_seconds'] = max(self.timings['max_exchange_seconds'], exchange_elapsed)
                # Independently validate transport ACKs before removing anything.
                allowed = {item["id"] for item in items}
                if not isinstance(ack, list) or any(not isinstance(x, str) or x not in allowed for x in ack):
                    raise ValueError("Unexpected UI receipt")
                if not ack:
                    raise OSError("UI did not acknowledge the pending batch")
                advertised = getattr(pipe, 'peer_batch_limit', LEGACY_BATCH_ITEMS)
                self.batch_limit = min(advertised, MAX_BATCH_ITEMS) if type(advertised) is int and advertised >= LEGACY_BATCH_ITEMS else LEGACY_BATCH_ITEMS
                ack_started = time.monotonic()
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
                ack_elapsed = time.monotonic() - ack_started
                self.timings['ack_db_seconds'] += ack_elapsed
                self.timings['max_ack_db_seconds'] = max(self.timings['max_ack_db_seconds'], ack_elapsed)
                self.timings['batches'] += 1
            if status:
                pipe.send(status)
                self.last_status_pid = (status.get('data') or {}).get('engineProcessId')
                self.last_status_at = time.time()
        return bool(items)

    def _run(self):
        while not self.stop.is_set():
            try:
                more = self.drain_once()
                self.last_error = None
                self.report_service_delivery()
                if more:
                    continue
            except (OSError, ValueError, sqlite3.Error) as error:
                self.last_error = str(error)
                self.report_service_delivery()
                self.stop.wait(1)
            self.wake.wait(.5)
            self.wake.clear()

    def report_service_delivery(self):
        if os.environ.get("RANSOM0_SERVICE_STORAGE") != "1" or time.monotonic() < self.next_report:
            return
        self.next_report = time.monotonic()+10
        from .resident import write_json
        try:
            write_json(self.path.parent/"ui-delivery-health.json", {"pid":os.getpid(),"at":time.time(),
                "acknowledged":self.acked,"last_error":self.last_error,"last_status_pid":self.last_status_pid,
                "last_status_at":self.last_status_at})
        except OSError:
            pass

    def diagnostics(self):
        with self.lock:
            return {"pending": self.db.execute("SELECT pending FROM ui_pending_capacity WHERE singleton=1").fetchone()[0],
                    "acknowledged": self.acked, "last_error": self.last_error,
                    "batch_limit": self.batch_limit, "timings": dict(self.timings)}

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
