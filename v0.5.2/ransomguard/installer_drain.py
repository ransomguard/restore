"""Session-bound graceful installer shutdown after file-filter stop.

Creates an explicitly recorded coverage gap, not continuous protection.
Never starts/stops services, touches firewall, clears queues, or kills a process.
"""
import json,os,struct,time
from pathlib import Path
from .protocol import UPDATE_POLICY,MAGIC,VERSION

class InstallerDrain:
    def __init__(self,ready,reader,session):
        self.path=Path(ready).with_suffix('.install-stop.json') if ready else None
        self.reader=reader;self.session=session;self.active=False;self.stable=None;self.original=None;self.drained=False
    def pause(self):
        native=getattr(self.reader,'reader',self.reader)
        s=self.original
        native._ioctl(UPDATE_POLICY,struct.pack('<IIIII',MAGIC,VERSION,s['fastpath_mode'],0,s['self_protect_enabled']),0,5000)
    def ready_to_close(self):
        if not self.path:return True
        if not self.active:
            try:r=json.loads(self.path.read_text(encoding='utf-8'))
            except (OSError,ValueError):return True
            if (r.get('pid')!=os.getpid() or r.get('session')!=self.session or r.get('file_filter_stopped') is not True
                or not 0<r.get('expires',0)-time.time()<=120):return True
            self.expires=r['expires'];self.original=self.reader.status();self.pause();self.active=True
        if time.time()>self.expires:raise RuntimeError('Installer drain deadline expired; inspect preserved intake')
        s=self.reader.status()
        empty=s['queue_depth']==0 and self.reader.queue.empty()
        if not empty:self.stable=None;return False
        if self.stable is None:self.stable=time.monotonic();return False
        self.drained=time.monotonic()-self.stable>=2
        return self.drained
    def finish(self):
        if self.active and self.drained:self.pause() # LivePipeline.close restores its previous policy first.
