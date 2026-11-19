import unittest
from dataclasses import replace
from ransomguard.protocol import Event
from ransomguard.correlation_identity import RecoverableProcessRegistry
from ransomguard.triage import TriageIntake,TriageConfig
from ransomguard.track_a import TrackACorroborator

class Handle:
 def __init__(self,generation=100):self.generation=generation;self.running=True;self.closed=False
 def alive(self):return self.running and not self.closed
 def close(self):self.closed=True

def event(kind,seq,pid=123,stamp=1000,created=100,entropy=True):
 fields={'process_create_time':created} if kind in (1,2,3) else {'flags':8 if entropy else 0,'path':r'\Device\Lab\a.txt','new_extension':''}
 return Event(kind,'process_created' if kind==1 else 'file_write_attempted',seq,stamp,pid,fields)

class IdentityTests(unittest.TestCase):
 def test_new_lifecycle_recovers_after_gap_but_old_cache_does_not(self):
  r=RecoverableProcessRegistry(opener=lambda _:Handle())
  r.update(event(1,1));r.update(event(4,3,entropy=False))
  self.assertIsNone(r.generation_for_event(event(4,3,entropy=False)))
  r.update(event(1,4,created=200));r.update(event(4,5))
  self.assertEqual(r.generation_for_event(event(4,5)),200)
  self.assertTrue(r.ever_loss_detected);self.assertEqual(r.epoch,1);r.close()
 def test_preexisting_process_resolves_by_live_handle_not_pid_only(self):
  r=RecoverableProcessRegistry(opener=lambda _:Handle());t=TriageIntake(TriageConfig())
  e=event(4,1);r.update(e);g=r.generation_for_event(e)
  records=t.ingest(e,correlated_create_time=g,identity_source=r.identity_source)
  self.assertEqual(records[-1].kind,'track_b_candidate');self.assertEqual(records[-1].payload['identity_source'],'live_handle_query')
  self.assertFalse(records[-1].payload['identity_authorization']);r.close()
 def test_old_event_after_pid_reuse_is_rejected(self):
  handles=iter([Handle(100),Handle(2000)])
  r=RecoverableProcessRegistry(opener=lambda _:next(handles));e=event(4,1);r.update(e);self.assertEqual(r.generation_for_event(e),100)
  r.handles[123].running=False;e=event(4,2,stamp=1500);r.update(e)
  self.assertIsNone(r.generation_for_event(e));self.assertEqual(r.identity_resolution['reason'],'event_predates_process_creation');r.close()
 def test_excluded_storage_advances_sequence_without_evidence(self):
  t=TriageIntake(TriageConfig());t.ingest(event(1,1),correlated_create_time=100)
  self.assertEqual(t.ingest(event(4,2),correlated_create_time=None,ignore_file_evidence=True),[])
  rows=t.ingest(event(4,3),correlated_create_time=100)
  self.assertEqual(rows[-1].kind,'track_b_candidate');self.assertEqual(rows[-1].payload['counts']['write_attempts'],1)
 def test_resolution_does_not_attach_old_unknown_evidence(self):
  t=TriageIntake(TriageConfig());t.ingest(event(4,1),correlated_create_time=None)
  rows=t.ingest(event(4,2),correlated_create_time=100,identity_source='live_handle_query')
  self.assertEqual(rows[-1].kind,'track_b_candidate');self.assertEqual(rows[-1].payload['counts']['write_attempts'],1)
 def test_access_denial_stays_deferred_with_bounded_retries(self):
  def denied(_):raise PermissionError('denied')
  r=RecoverableProcessRegistry(opener=denied,clock=lambda:1)
  for seq in range(1,100):
   e=event(4,seq);r.update(e);self.assertIsNone(r.generation_for_event(e))
  self.assertEqual(r.stats['queries'],1);self.assertEqual(r.identity_resolution['reason'],'live_query_failed');self.assertTrue(r.identity_resolution['retry_backoff']);self.assertIn('denied',r.identity_resolution['detail']);r.close()
 def test_track_a_does_not_bridge_loss_epoch(self):
  r=RecoverableProcessRegistry(opener=lambda _:Handle());a=TrackACorroborator(r'\Device\Lab')
  for e in (event(1,1),event(4,2)):
   r.update(e);a.ingest(e,r)
  r.invalidate()
  e=event(1,4);r.update(e);a.ingest(e,r)
  block=Event(3,'process_creation_blocked',5,3000,456,{'parent_pid':123,'creator_pid':123,'matched_rule_id':1001,'process_create_time':2000})
  r.update(block);self.assertIsNone(a.ingest(block,r));r.close()

if __name__=='__main__':unittest.main()

