"""Wait for durable receipts before capacity exhaustion; never delete evidence."""
import time

class DeliveryPressure:
    def __init__(self,db,limit,*,clock=time.monotonic,detached_ui=False):
        self.db=db;self.clock=clock;self.next=0;self.paused=False
        self.high=max(1,int(limit*.8));self.low=max(0,int(limit*.5))
        self.pending=0;self.waits=0
        self.detached_ui=detached_ui
    def blocked(self):
        now=self.clock()
        if now<self.next:return self.paused
        self.next=now+.02
        # These are constant-size maintained counters, not history scans.
        self.pending=self.db.execute('SELECT pending FROM events_capacity WHERE singleton=1').fetchone()[0]
        if self.detached_ui and self.pending>=self.high:
            # Upgrade compatibility: bounded release of already processed rows
            # whose UI payload remains durably queued. No ACK/deletion occurs.
            with self.db:
                rows=self.db.execute('''SELECT e.event_id FROM events e INDEXED BY events_capacity_raw_due
                  CROSS JOIN raw_retention r ON r.event_id=e.event_id
                  WHERE e.kind='kernel_event' AND e.capacity_released=0 AND e.acknowledged_at IS NULL
                  AND r.processed IS NOT NULL
                  AND EXISTS(SELECT 1 FROM ui_delivery_tracking t JOIN ui_pending p ON p.id=t.delivery_id WHERE t.event_id=e.event_id)
                  LIMIT 512''').fetchall()
                self.db.executemany('UPDATE events SET capacity_released=1 WHERE event_id=?',rows)
            self.pending=self.db.execute('SELECT pending FROM events_capacity WHERE singleton=1').fetchone()[0]
        if not self.detached_ui:
            self.pending=max(self.pending,self.db.execute('SELECT pending FROM ui_pending_capacity WHERE singleton=1').fetchone()[0])
        previous=self.paused
        self.paused=self.pending>self.low if self.paused else self.pending>=self.high
        if self.paused and not previous:self.waits+=1
        return self.paused
