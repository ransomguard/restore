"""Conservative local raw-event retention; never fabricates an external ACK."""
import time

def initialize(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS raw_retention(event_id TEXT PRIMARY KEY,pid INTEGER,generation INTEGER,processed REAL,ui_state TEXT NOT NULL DEFAULT 'pending');
    CREATE INDEX IF NOT EXISTS raw_retention_due ON raw_retention(processed,ui_state);
    CREATE TABLE IF NOT EXISTS retention_holds(pid INTEGER,generation INTEGER,reason TEXT,PRIMARY KEY(pid,generation));
    CREATE TABLE IF NOT EXISTS retention_resolution(pid INTEGER,generation INTEGER,incident_id TEXT,state TEXT,ui_finalized INTEGER,PRIMARY KEY(pid,generation));
    CREATE TABLE IF NOT EXISTS ui_delivery_tracking(delivery_id TEXT PRIMARY KEY,event_id TEXT,incident_id TEXT,acked INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS ui_tracking_event ON ui_delivery_tracking(event_id);
    CREATE INDEX IF NOT EXISTS ui_tracking_incident ON ui_delivery_tracking(incident_id,acked);
    CREATE TABLE IF NOT EXISTS retention_stats(singleton INTEGER PRIMARY KEY,deleted INTEGER NOT NULL,last_run REAL);
    INSERT OR IGNORE INTO retention_stats VALUES(1,0,NULL);
    ''')
    db.commit()

class RawRetention:
    def __init__(self,db,*,grace_seconds=120):
        self.db=db;self.grace=max(120,grace_seconds);self.last_run=0
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
    def resolution(self,result,outcomes):
        with self.db:self.db.execute('INSERT OR REPLACE INTO retention_resolution VALUES(?,?,?,?,?)',(result.process.pid,result.process.create_time,result.incident_id,result.state,int(bool(outcomes) and all(x=='sent' for x in outcomes))))
    def cleanup(self,*,now=None,force=False):
        now=time.time() if now is None else now
        if not force and now-self.last_run<30:return 0
        self.last_run=now
        self.db.execute('BEGIN IMMEDIATE')
        try:
            rows=self.db.execute('''SELECT r.event_id FROM raw_retention r JOIN events e ON e.event_id=r.event_id
            WHERE e.kind='kernel_event' AND r.processed IS NOT NULL AND r.processed<? AND r.ui_state IN ('acked','not_required')
            AND NOT EXISTS(SELECT 1 FROM retention_holds h WHERE h.pid=r.pid AND (h.generation=0 OR h.generation=r.generation)
              AND NOT EXISTS(SELECT 1 FROM retention_resolution z WHERE z.pid=h.pid AND z.generation=h.generation AND z.state='RELEASED' AND z.ui_finalized=1
                AND EXISTS(SELECT 1 FROM ui_delivery_tracking t WHERE t.incident_id=z.incident_id)
                AND NOT EXISTS(SELECT 1 FROM ui_delivery_tracking t WHERE t.incident_id=z.incident_id AND t.acked=0)))
            ORDER BY e.sequence LIMIT 2000''',(now-self.grace,)).fetchall()
            self.db.executemany('DELETE FROM events WHERE event_id=?',rows)
            self.db.executemany('DELETE FROM raw_retention WHERE event_id=?',rows)
            self.db.executemany('DELETE FROM ui_delivery_tracking WHERE event_id=?',rows)
            self.db.execute('UPDATE retention_stats SET deleted=deleted+?,last_run=? WHERE singleton=1',(len(rows),now))
            self.db.commit();return len(rows)
        except BaseException:self.db.rollback();raise
