"""Transactional O(1) capacity counters, including writes from other connections."""
def install_capacity_counter(db, *, queue):
    if queue not in ('events', 'ui_pending'):
        raise ValueError('Unsupported queue')
    table = queue + '_capacity'
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
