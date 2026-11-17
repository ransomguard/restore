"""Bounded passive intake. No eviction; pending records are exposed for durable shutdown."""
import queue,threading
class BufferedReader:
    def __init__(self,reader,capacity=8192,*,preserve=None):
        if not 1<=capacity<=16384:raise ValueError('Invalid intake capacity')
        self.reader=reader;self.queue=queue.Queue(capacity);self.stop=threading.Event()
        self.error=None;self.tail=[];self.peak=0;self.read_count=0;self.full_waits=0
        self.read_calls=0;self.peak_batch=0
        self.preserve=preserve
        self.thread=threading.Thread(target=self._run,name='kernel-intake',daemon=True)
    def __enter__(self):self.thread.start();return self
    def _run(self):
        try:
            while not self.stop.is_set():
                if hasattr(self.reader,'read_many'):
                    records=self.reader.read_many(timeout_ms=100)
                else:
                    raw=self.reader.read(timeout_ms=100);records=[] if raw is None else [raw]
                self.read_calls+=1;self.read_count+=len(records);self.peak_batch=max(self.peak_batch,len(records))
                for index,raw in enumerate(records):
                    while True:
                        try:self.queue.put(raw,timeout=.05);self.peak=max(self.peak,self.queue.qsize());break
                        except queue.Full:
                            self.full_waits+=1
                            if self.stop.is_set():self.tail=records[index:];return
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
    def diagnostics(self):return {'read':self.read_count,'peak_buffer':self.peak,'backpressure_waits':self.full_waits,'capacity':self.queue.maxsize,'read_calls':self.read_calls,'peak_batch':self.peak_batch}
    def __exit__(self,*args):
        pending=self.stop_and_drain()
        try:
            if pending:
                if self.preserve is None:raise RuntimeError('Unpersisted intake records remain')
                self.preserve(pending)
        finally:self.reader.close()
