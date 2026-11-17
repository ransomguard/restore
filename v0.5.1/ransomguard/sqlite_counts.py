"""Transactional O(1) capacity counters, including writes from other connections."""
def install_capacity_counter(db, *, queue):
    if queue not in ('events', 'ui_pending'):
        raise ValueError('Unsupported queue')
    table = queue + '_capacity'
    if queue == 'events':
        # Migrate once under the same write lock as appends. Retained evidence
        # is still unacknowledged/exportable; it simply isn't intake work.
        db.execute('BEGIN IMMEDIATE')
        try:
            columns = {r[1] for r in db.execute('PRAGMA table_info(events)')}
            if 'capacity_released' not in columns:
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='view' AND name='all_outbox_events'").fetchone():
                    db.execute('DROP VIEW all_outbox_events')
                    cols = 'sequence,event_id,incident_id,occurred_at,kind,payload,acknowledged_at'
                    db.execute(f'CREATE VIEW all_outbox_events AS SELECT {cols} FROM events UNION ALL SELECT {cols} FROM diagnostic_archive')
                db.execute('ALTER TABLE events ADD COLUMN capacity_released INTEGER NOT NULL DEFAULT 0 CHECK(capacity_released IN (0,1))')
            db.execute("CREATE INDEX IF NOT EXISTS events_capacity_raw_due ON events(event_id) WHERE kind='kernel_event' AND capacity_released=0 AND acknowledged_at IS NULL")
            db.execute('CREATE TABLE IF NOT EXISTS capacity_migrations(version INTEGER PRIMARY KEY)')
            if not db.execute('SELECT 1 FROM capacity_migrations WHERE version=2').fetchone():
                for suffix in ('insert', 'delete', 'ack', 'update'):
                    db.execute('DROP TRIGGER IF EXISTS events_capacity_' + suffix)
                db.execute('CREATE TABLE IF NOT EXISTS events_capacity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),pending INTEGER NOT NULL CHECK(pending>=0))')
                db.execute('INSERT OR REPLACE INTO events_capacity SELECT 1,COUNT(*) FROM events WHERE acknowledged_at IS NULL AND capacity_released=0')
                new = '(NEW.acknowledged_at IS NULL AND NEW.capacity_released=0)'
                old = '(OLD.acknowledged_at IS NULL AND OLD.capacity_released=0)'
                db.execute(f'CREATE TRIGGER events_capacity_insert AFTER INSERT ON events WHEN {new} BEGIN UPDATE events_capacity SET pending=pending+1 WHERE singleton=1; END')
                db.execute(f'CREATE TRIGGER events_capacity_delete AFTER DELETE ON events WHEN {old} BEGIN UPDATE events_capacity SET pending=pending-1 WHERE singleton=1; END')
                db.execute(f'CREATE TRIGGER events_capacity_update AFTER UPDATE OF acknowledged_at,capacity_released ON events WHEN {old}!={new} BEGIN UPDATE events_capacity SET pending=pending+{new}-{old} WHERE singleton=1; END')
                db.execute('INSERT INTO capacity_migrations VALUES(2)')
            db.commit()
        except BaseException:
            db.rollback()
            raise
        return
    eligible = 'acknowledged_at IS NULL' if queue == 'events' else '1'
    new = 'NEW.acknowledged_at IS NULL' if queue == 'events' else '1'
    old = 'OLD.acknowledged_at IS NULL' if queue == 'events' else '1'
    # Acquire before initializing the count and triggers, so no append can race migration.
    ack_trigger = """CREATE TRIGGER IF NOT EXISTS events_capacity_ack AFTER UPDATE OF acknowledged_at ON events
        WHEN (OLD.acknowledged_at IS NULL) != (NEW.acknowledged_at IS NULL)
        BEGIN UPDATE events_capacity SET pending=pending+CASE WHEN NEW.acknowledged_at IS NULL THEN 1 ELSE -1 END WHERE singleton=1; END;""" if queue == "events" else ""
    db.executescript(f'''
    BEGIN IMMEDIATE;
    CREATE TABLE IF NOT EXISTS {table}(singleton INTEGER PRIMARY KEY CHECK(singleton=1),pending INTEGER NOT NULL CHECK(pending>=0));
    INSERT OR IGNORE INTO {table} SELECT 1,COUNT(*) FROM {queue} WHERE {eligible};
    CREATE TRIGGER IF NOT EXISTS {table}_insert AFTER INSERT ON {queue} WHEN {new}
      BEGIN UPDATE {table} SET pending=pending+1 WHERE singleton=1; END;
    CREATE TRIGGER IF NOT EXISTS {table}_delete AFTER DELETE ON {queue} WHEN {old}
      BEGIN UPDATE {table} SET pending=pending-1 WHERE singleton=1; END;
    {ack_trigger}
    COMMIT;
    ''')
