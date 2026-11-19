from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ransomguard import program_allowlist as policy
from ransomguard.incidents import ProcessInstance
from ransomguard.live_response import LiveResponseCoordinator
from ransomguard.outbox import Outbox
from ransomguard.response_ledger import ResponseLedger

class Session:
    filename = ''
    def __init__(self, process):
        if process.create_time != 123: raise RuntimeError('wrong generation')
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def is_exited(self): return False
    def image_path(self): return self.filename

class AnalysisOnlyJev:
    def evaluate(self, evidence):
        return {'score':0.9,'request_id':'OFFLINE_TEST_DOUBLE','request_state':evidence}

class NoEffects:
    def __getattr__(self, name): raise AssertionError('Unexpected side effect: '+name)

class ProgramAllowlistTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.base=Path(temp.name);self.exe=self.base/'normal.exe'
        self.exe.write_bytes(b'MZ harmless fixture');Session.filename=str(self.exe)
        self.identity=ProcessInstance(1234,123)
        for p in (patch('ctypes.windll.shell32.IsUserAnAdmin',return_value=1),
                  patch('ransomguard.program_allowlist.subprocess.run')):
            p.start();self.addCleanup(p.stop)
    def match(self, identity=None):
        return policy.match(self.base,identity or self.identity,session_factory=Session)
    def test_add_match_remove_audit(self):
        row=policy.add(self.base,str(self.exe))[0]
        self.assertEqual(self.match()['sha256'],row['sha256'])
        self.assertEqual(policy.remove(self.base,row['id']),[])
        self.assertIsNone(self.match())
        with closing(sqlite3.connect(policy.policy_path(self.base))) as db:
            self.assertEqual(db.execute('select count(*) from audit').fetchone()[0],2)
    def test_hash_path_generation(self):
        policy.add(self.base,str(self.exe));self.exe.write_bytes(b'MZ changed')
        self.assertIsNone(self.match())
        Session.filename=str(self.base/'child.exe');self.assertIsNone(self.match())
        with self.assertRaises(RuntimeError):self.match(ProcessInstance(1234,124))
    def test_tracks_skip_effects_keep_logs(self):
        policy.add(self.base,str(self.exe));real_match=policy.match
        with Outbox(self.base/'observe.sqlite3') as outbox:
            with patch.object(policy,'match',side_effect=lambda r,p:real_match(r,p,session_factory=Session)):
                for track in ('A','B'):
                    result=LiveResponseCoordinator(outbox=outbox,firewall=NoEffects(),driver=NoEffects(),jev=AnalysisOnlyJev(),recovery=NoEffects()).respond(track=track,process=self.identity,jev_state={'writes':5},track_a_confirmed=True,explicit_authorization=True)
                    self.assertEqual(result.state,'EXEMPTED')
                    if track=='B':self.assertEqual(result.jev_classification,'malicious')
                    self.assertFalse(result.exit_confirmed or result.recovery_verified or result.firewall_hold_retained)
            self.assertEqual(outbox.db.execute("select count(*) from events where kind='automatic_response_exempted'").fetchone()[0],2)
    def test_read_error_never_exempts(self):
        with Outbox(self.base/'observe.sqlite3') as outbox,patch.object(policy,'match',side_effect=OSError()):
            result=LiveResponseCoordinator(outbox=outbox,firewall=NoEffects(),driver=NoEffects(),decision_guard=lambda:False).respond(track='A',process=self.identity,track_a_confirmed=True,explicit_authorization=True)
            self.assertEqual(result.state,'REVIEW_REQUIRED')
    def test_reconsider_same_generation_preserve_audit(self):
        with closing(sqlite3.connect(':memory:')) as db:
            ledger=ResponseLedger(db)
            self.assertTrue(ledger.claim(incident_id='first',pid=1234,process_create_time=123))
            ledger.finish('first',state='EXEMPTED',reason='exception')
            self.assertTrue(ledger.claim(incident_id='second',pid=1234,process_create_time=123))
            self.assertEqual(db.execute('select incident_id from exempt_response_history').fetchone()[0],'first')
            ledger.finish('second',state='REVIEW_REQUIRED',reason='review')
            self.assertFalse(ledger.claim(incident_id='third',pid=1234,process_create_time=123))
    def test_bad_paths(self):
        for name in ('normal.exe',str(self.base/'normal.txt')):
            with self.assertRaises(ValueError):policy.add(self.base,name)
