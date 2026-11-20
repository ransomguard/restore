"""Bounded passive intake. No eviction; pending records are exposed for durable shutdown."""
import queue,threading,time

class RawQueue(queue.Queue):
    """Bound both record count and raw bytes; never evict unread evidence."""
    def __init__(self, capacity, byte_limit=384*1024*1024):
        super().__init__(capacity)
        if type(byte_limit) is not int or byte_limit<1:raise ValueError('Invalid byte limit')
        self.byte_limit=byte_limit;self.bytes=0;self.peak_bytes=0
    def _put(self, item):
        super()._put(item);self.bytes+=len(item);self.peak_bytes=max(self.peak_bytes,self.bytes)
    def _get(self):
        item=super()._get();self.bytes-=len(item);return item
    def put(self, item, block=True, timeout=None):
        if not isinstance(item,bytes) or len(item)>self.byte_limit:raise ValueError('Invalid raw record size')
        if timeout is not None and timeout<0:raise ValueError('Invalid timeout')
        with self.not_full:
            end=None if timeout is None else time.monotonic()+timeout
            while self._qsize()>=self.maxsize or self.bytes+len(item)>self.byte_limit:
                if not block:raise queue.Full
                remaining=None if end is None else end-time.monotonic()
                if remaining is not None and remaining<=0:raise queue.Full
                self.not_full.wait(remaining)
            self._put(item);self.unfinished_tasks+=1;self.not_empty.notify()

class BufferedReader:
    def __init__(self,reader,capacity=8192,*,preserve=None):
        if not 1<=capacity<=131072:raise ValueError('Invalid intake capacity')
        self.reader=reader;self.queue=RawQueue(capacity);self.stop=threading.Event()
        self.error=None;self.tail=[];self.peak=0;self.read_count=0;self.full_waits=0
        self.read_calls=0;self.peak_batch=0
        self.max_read_seconds=0;self.max_cycle_seconds=0;self.slow_read_count=0;self.last_slow_read_at=None
        self.preserve=preserve
        self.thread=threading.Thread(target=self._run,name='kernel-intake',daemon=True)
    def __enter__(self):self.thread.start();return self
    def _run(self):
        try:
            while not self.stop.is_set():
                cycle_started=time.monotonic()
                if hasattr(self.reader,'read_many'):
                    records=self.reader.read_many(timeout_ms=100)
                else:
                    raw=self.reader.read(timeout_ms=100);records=[] if raw is None else [raw]
                elapsed=time.monotonic()-cycle_started
                self.max_read_seconds=max(self.max_read_seconds,elapsed)
                if elapsed>.5:
                    self.slow_read_count+=1;self.last_slow_read_at=time.time()
                self.read_calls+=1;self.read_count+=len(records);self.peak_batch=max(self.peak_batch,len(records))
                for index,raw in enumerate(records):
                    while True:
                        try:self.queue.put(raw,timeout=.05);self.peak=max(self.peak,self.queue.qsize());break
                        except queue.Full:
                            self.full_waits+=1
                            if self.stop.is_set():self.tail=records[index:];return
                        except BaseException:
                            self.tail=records[index:];raise
                self.max_cycle_seconds=max(self.max_cycle_seconds,time.monotonic()-cycle_started)
        except BaseException as error:self.error=error
    def read(self):
        try:return self.queue.get(timeout=.2)
        except queue.Empty:
            if self.error:raise self.error
            return None
    def status(self):return self.reader.status()
    def stop_and_drain(self):
        self.stop.set();self.thread.join(5)
        if self.thread.is_alive():raise RuntimeError('Intake thread failed to stop; do not close active driver handle')
        pending=[]
        while True:
            try:pending.append(self.queue.get_nowait())
            except queue.Empty:break
        pending.extend(self.tail);self.tail=[]
        return pending
    def diagnostics(self):
        result={'read':self.read_count,'peak_buffer':self.peak,'backpressure_waits':self.full_waits,'capacity':self.queue.maxsize,'read_calls':self.read_calls,'peak_batch':self.peak_batch}
        result.update(buffer_bytes=self.queue.bytes,peak_buffer_bytes=self.queue.peak_bytes,buffer_byte_limit=self.queue.byte_limit)
        result.update(max_read_seconds=self.max_read_seconds,max_cycle_seconds=self.max_cycle_seconds,
                      slow_read_count=self.slow_read_count,last_slow_read_at=self.last_slow_read_at)
        if hasattr(self,'wal_maintenance'):result['wal_maintenance']=dict(self.wal_maintenance.result)
        if hasattr(self.reader,'native_read_calls'):
            result.update(native_read_enabled=self.reader.native_read is not None,
                          native_read_calls=self.reader.native_read_calls,
                          max_native_read_seconds=self.reader.native_read_seconds)
        return result
    def __exit__(self,*args):
        pending=self.stop_and_drain()
        try:
            if pending:
                if self.preserve is None:raise RuntimeError('Unpersisted intake records remain')
                self.preserve(pending)
        finally:self.reader.close()
