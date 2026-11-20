"""Wait for durable receipts before capacity exhaustion; never delete evidence."""
import time

class DeliveryPressure:
    def __init__(self,db,limit,*,clock=time.monotonic):
        self.db=db;self.clock=clock;self.next=0;self.paused=False
        self.high=max(1,int(limit*.8));self.low=max(0,int(limit*.5))
        self.pending=0;self.waits=0
    def blocked(self):
        now=self.clock()
        if now<self.next:return self.paused
        self.next=now+.02
        # These are constant-size maintained counters, not history scans.
        self.pending=max(self.db.execute('SELECT pending FROM events_capacity WHERE singleton=1').fetchone()[0],
                         self.db.execute('SELECT pending FROM ui_pending_capacity WHERE singleton=1').fetchone()[0])
        previous=self.paused
        self.paused=self.pending>self.low if self.paused else self.pending>=self.high
        if self.paused and not previous:self.waits+=1
        return self.paused
