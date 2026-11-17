"""Bounded passive intake. No eviction; pending records are exposed for durable shutdown."""
import queue,threading
class BufferedReader:
    def __init__(self,reader,capacity=8192):
        if not 1<=capacity<=8192:raise ValueError('Invalid intake capacity')
        self.reader=reader;self.queue=queue.Queue(capacity);self.stop=threading.Event()
        self.error=None;self.tail=None;self.peak=0;self.read_count=0;self.full_waits=0
        self.thread=threading.Thread(target=self._run,name='kernel-intake',daemon=True)
    def __enter__(self):self.thread.start();return self
    def _run(self):
        try:
            while not self.stop.is_set():
                raw=self.reader.read(timeout_ms=100)
                if raw is None:continue
                self.read_count+=1
                while True:
                    try:self.queue.put(raw,timeout=.05);self.peak=max(self.peak,self.queue.qsize());break
                    except queue.Full:
                        self.full_waits+=1
                        if self.stop.is_set():self.tail=raw;return
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
        if self.tail is not None:pending.append(self.tail);self.tail=None
        return pending
    def diagnostics(self):return {'read':self.read_count,'peak_buffer':self.peak,'backpressure_waits':self.full_waits,'capacity':self.queue.maxsize}
    def __exit__(self,*args):
        self.stop.set();self.thread.join(5)
        if self.thread.is_alive():raise RuntimeError('Intake worker still active')
        if not self.queue.empty() or self.tail is not None:raise RuntimeError('Unpersisted intake records remain')
        self.reader.close()
