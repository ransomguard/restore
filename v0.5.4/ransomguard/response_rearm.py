"""Recover future response after a drained loss epoch; never replay old jobs."""
import json
from pathlib import Path
import time


class ResponseRearm:
    def __init__(self, ready, pipeline, *, resident=False, clock=time.monotonic, request=None):
        self.ready=Path(ready) if ready else None
        self.pipeline=pipeline
        self.enabled=bool(self.ready and pipeline and resident)
        self.clock=clock;self.since=None;self.last=None;self.requested=False
        self.request=request;self.last_error=None

    def tick(self,status,pending):
        if not self.enabled or self.requested:return None
        values=(status.get('events_dropped'),status.get('events_flushed'))
        if any(type(x) is not int for x in values):self.since=None;return None
        if values!=self.pipeline.baseline:self.pipeline.invalid.set()
        if not self.pipeline.invalid.is_set():self.since=None;return None
        # Keep all jobs from the invalid worker invalid, including queued jobs.
        # Only a fresh worker gets a new identity/triage window and baseline.
        if pending!=0 or status.get('queue_depth')!=0 or self.pipeline.jobs.active.is_set():
            self.since=None;self.last=values;return None
        now=self.clock()
        if self.since is None or values!=self.last:
            self.since=now;self.last=values;return None
        if now-self.since<5:return None
        try:
            if self.request is None:
                from .resident import request_reload
                installation=json.loads((self.ready.parent/'installation.json').read_text(encoding='utf-8-sig'))
                result=request_reload(self.ready,Path(installation['recovery_root'])/'ransomguard')
            else:result=self.request()
        except (OSError,ValueError,KeyError) as error:
            self.last_error=type(error).__name__;self.since=now
            return None
        self.last_error=None
        self.requested=True
        return {'reason':'collection_loss_drained_new_evidence_epoch','request_id':result['id'],
                'dropped':values[0],'flushed':values[1],'old_jobs_replayed':False}
