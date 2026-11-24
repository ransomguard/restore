"""Conservative local raw-event retention; never fabricates an external ACK."""
import time

# Seek through a bounded age-ordered slice before checking incident holds.
# A large protected prefix must not cause a history-sized scan every second.
CLEANUP_QUERY = """SELECT r.rowid,r.event_id,r.processed,r.ui_state
 FROM raw_retention r INDEXED BY raw_retention_due
 WHERE r.processed IS NOT NULL AND r.processed<?
   AND (r.processed,r.ui_state,r.rowid)>(?,?,?)
 ORDER BY r.processed,r.ui_state,r.rowid LIMIT ?"""
ELIGIBLE_RAW = """SELECT 1 FROM events e JOIN raw_retention r ON r.event_id=e.event_id
 WHERE e.event_id=? AND e.kind='kernel_event' AND r.processed IS NOT NULL
 AND r.ui_state IN ('acked','not_required')
 AND NOT EXISTS(SELECT 1 FROM retention_holds h
  WHERE h.pid=r.pid AND (h.generation=0 OR h.generation=r.generation)
  AND NOT EXISTS(SELECT 1 FROM retention_resolution z
    WHERE z.pid=h.pid AND z.generation=h.generation AND z.ui_finalized=1
    AND (z.state='EXEMPTED' OR (z.state='RELEASED'
      AND EXISTS(SELECT 1 FROM ui_delivery_tracking t WHERE t.incident_id=z.incident_id)
      AND NOT EXISTS(SELECT 1 FROM ui_delivery_tracking t WHERE t.incident_id=z.incident_id AND t.acked=0)))))"""

def release_completed_capacity(db, *, limit=10000):
    """Free intake slots, NOT evidence, ACKs, holds, or UI history.

    Called inside the caller's transaction. A raw row must have completed
    local processing and have an actual UI receipt (or explicit sampling).
    Unresolved incident evidence remains available to analysis and export.
    """
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError('Invalid capacity release batch')
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='raw_retention'").fetchone():
        return 0
    rows = db.execute('''
        SELECT e.event_id FROM events e INDEXED BY events_capacity_raw_due CROSS JOIN raw_retention r ON r.event_id=e.event_id
        WHERE e.kind='kernel_event' AND e.capacity_released=0 AND e.acknowledged_at IS NULL
          AND r.processed IS NOT NULL AND r.ui_state IN ('acked','not_required')
        LIMIT ?''', (limit,)).fetchall()
    # One large UPDATE journals every old payload in a SQLite statement rollback
    # file, even in WAL mode. Keep the outer atomic transaction but update one
    # indexed row per statement so that statement journals stay bounded.
    db.executemany('UPDATE events SET capacity_released=1 WHERE event_id=?', rows)
    return len(rows)

def initialize(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS raw_retention(event_id TEXT PRIMARY KEY,pid INTEGER,generation INTEGER,processed REAL,ui_state TEXT NOT NULL DEFAULT 'pending');
    CREATE INDEX IF NOT EXISTS raw_retention_due ON raw_retention(processed,ui_state);
    CREATE TABLE IF NOT EXISTS retention_holds(pid INTEGER,generation INTEGER,reason TEXT,PRIMARY KEY(pid,generation));
    CREATE TABLE IF NOT EXISTS retention_resolution(pid INTEGER,generation INTEGER,incident_id TEXT,state TEXT,ui_finalized INTEGER,PRIMARY KEY(pid,generation));
    CREATE TABLE IF NOT EXISTS ui_delivery_tracking(delivery_id TEXT PRIMARY KEY,event_id TEXT,incident_id TEXT,acked INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS ui_tracking_event ON ui_delivery_tracking(event_id);
    CREATE INDEX IF NOT EXISTS ui_tracking_incident ON ui_delivery_tracking(incident_id,acked);
    CREATE TABLE IF NOT EXISTS retention_scan(singleton INTEGER PRIMARY KEY,processed REAL,ui_state TEXT,row_id INTEGER);
    INSERT OR IGNORE INTO retention_scan VALUES(1,0,'',0);
    CREATE TABLE IF NOT EXISTS retention_stats(singleton INTEGER PRIMARY KEY,deleted INTEGER NOT NULL,last_run REAL);
    INSERT OR IGNORE INTO retention_stats VALUES(1,0,NULL);
    ''')
    db.commit()

class RawRetention:
    def __init__(self,db,*,grace_seconds=120,batch_limit=2000,capacity_limit=10000,interval=30,detached_ui=False):
        if type(batch_limit) is not int or not 1 <= batch_limit <= 2000:
            raise ValueError('Invalid retention batch')
        if type(capacity_limit) is not int or not 1 <= capacity_limit <= 10000:
            raise ValueError('Invalid retention capacity batch')
        if not 1 <= interval <= 30:
            raise ValueError('Invalid retention interval')
        self.db=db;self.grace=max(120,grace_seconds);self.last_run=0
        self.detached_ui=detached_ui
        self.batch_limit=batch_limit;self.capacity_limit=capacity_limit;self.interval=interval
        initialize(db)
    def begin(self,event_id,event,generation):
        with self.db:self.db.execute('INSERT INTO raw_retention(event_id,pid,generation) VALUES(?,?,?)',(event_id,event.pid,generation or 0))
    def protect(self,pid,generation,reason):
        with self.db:self.db.execute('INSERT OR REPLACE INTO retention_holds VALUES(?,?,?)',(pid,generation or 0,reason))
    def finish(self,event_id,outcome):
        # Rate-limited file events and the UI's own storage writes were never
        # intended for the UI. All other sends require a real commit receipt.
        with self.db:
            self.db.execute("UPDATE raw_retention SET processed=?,ui_state=CASE WHEN ? IN ('rate_limited','ui_storage_skipped') THEN 'not_required' ELSE ui_state END WHERE event_id=?",(time.time(),outcome,event_id))
            # Free intake space immediately; retain evidence, holds and ACKs.
            self.db.execute("""UPDATE events SET capacity_released=1
                WHERE event_id=? AND capacity_released=0 AND kind='kernel_event'
                  AND EXISTS(SELECT 1 FROM raw_retention r WHERE r.event_id=events.event_id
                    AND r.processed IS NOT NULL AND r.ui_state IN ('acked','not_required'))""",(event_id,))
            if self.detached_ui:
                # Release only the processing slot after analysis AND durable UI
                # enqueue. Never acknowledge/delete evidence or bypass holds.
                self.db.execute("""UPDATE events SET capacity_released=1
                    WHERE event_id=? AND kind='kernel_event' AND capacity_released=0
                    AND EXISTS(SELECT 1 FROM raw_retention r WHERE r.event_id=events.event_id AND r.processed IS NOT NULL)
                    AND EXISTS(SELECT 1 FROM ui_delivery_tracking t JOIN ui_pending p ON p.id=t.delivery_id
                               WHERE t.event_id=events.event_id)""",(event_id,))
    def resolution(self,result,outcomes):
        # Exemptions have a durable outbox audit but no fabricated threat alert.
        # Each raw event must still have its own UI receipt before deletion.
        finalized = result.state == 'EXEMPTED' or (bool(outcomes) and all(x=='sent' for x in outcomes))
        with self.db:self.db.execute('INSERT OR REPLACE INTO retention_resolution VALUES(?,?,?,?,?)',(result.process.pid,result.process.create_time,result.incident_id,result.state,int(finalized)))
    def cleanup(self,*,now=None,force=False):
        now=time.time() if now is None else now
        if not force and now-self.last_run<self.interval:return 0
        self.last_run=now
        self.db.execute('BEGIN IMMEDIATE')
        try:
            release_completed_capacity(self.db,limit=self.capacity_limit)
            cursor=self.db.execute('SELECT processed,ui_state,row_id FROM retention_scan WHERE singleton=1').fetchone()
            scan=self.db.execute(CLEANUP_QUERY,(now-self.grace,*cursor,self.batch_limit*4)).fetchall()
            if not scan and cursor!=(0,'',0):
                cursor=(0,'',0)
                scan=self.db.execute(CLEANUP_QUERY,(now-self.grace,*cursor,self.batch_limit*4)).fetchall()
            rows=[]
            for row_id,event_id,processed,ui_state in scan:
                cursor=(processed,ui_state,row_id)
                if self.db.execute(ELIGIBLE_RAW,(event_id,)).fetchone():rows.append((event_id,))
                if len(rows)>=self.batch_limit:break
            self.db.execute('UPDATE retention_scan SET processed=?,ui_state=?,row_id=? WHERE singleton=1',cursor)
            self.db.executemany('DELETE FROM events WHERE event_id=?',rows)
            self.db.executemany('DELETE FROM raw_retention WHERE event_id=?',rows)
            self.db.executemany('DELETE FROM ui_delivery_tracking WHERE event_id=?',rows)
            self.db.execute('UPDATE retention_stats SET deleted=deleted+?,last_run=? WHERE singleton=1',(len(rows),now))
            self.db.commit();return len(rows)
        except BaseException:self.db.rollback();raise
