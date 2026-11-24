import copy
import json
import time
from tests.test_backlog_evidence import UpgradeTests
from ransomguard.response_jobs import ResponseJobs
from ransomguard.late_track_b import new_verified_facts, REASON


class ReassessmentTests(UpgradeTests):
    def prepare(self, reason=REASON):
        self.b['evidence'] = {'evidence': {'sample_source_paths': ['a']},
            'verified_write_effects': {'changed_relative_paths': ['a'],
                                      'files_unverified': 0, 'bounded_scan_incomplete': False}}
        self.calls = []
        def callback(job, *_):
            self.calls.append(copy.deepcopy(job))
            return ('RELEASED', 'done') if job.get('resume_b_review') else ('REVIEW_REQUIRED', reason)
        self.worker = ResponseJobs(self.box, callback).start()
        self.worker.enqueue(self.b)
        self.wait_for(lambda: self.box.db.execute('SELECT state FROM response_jobs').fetchone() == ('REVIEW_REQUIRED',))
        incoming = copy.deepcopy(self.b)
        incoming.update(id='new-id', filetime=self.b['filetime']+300_000_000, deadline=time.time()+30)
        incoming['evidence'] = {'evidence': {'sample_source_paths': ['b']}}
        return incoming

    def test_new_evidence_once_keeps_identity_cutoff_and_audit(self):
        incoming = self.prepare()
        self.assertEqual(self.worker.enqueue(incoming), 'TRACK_B_NEW_EVIDENCE_REASSESSMENT')
        self.wait_for(lambda: self.box.db.execute('SELECT state FROM response_jobs').fetchone() == ('RELEASED',))
        job = self.calls[-1]
        self.assertEqual(job['id'], self.b['id'])
        self.assertEqual(job['recovery_filetime'], self.b['filetime'])
        self.assertEqual(job['evidence']['evidence']['sample_source_paths'], ['a', 'b'])
        self.assertEqual(self.box.db.execute('SELECT state,reason FROM track_b_reassessment_history').fetchone(), ('REVIEW_REQUIRED', REASON))
        self.assertEqual(self.worker.enqueue(incoming), 'duplicate')
        self.assertEqual(len(self.calls), 2)

    def test_same_paths_do_not_repeat_jev(self):
        incoming = self.prepare()
        incoming['evidence']['evidence']['sample_source_paths'] = ['a']
        self.assertEqual(self.worker.enqueue(incoming), 'duplicate')

    def test_expired_incident_does_not_repeat(self):
        incoming = self.prepare()
        incoming['filetime'] = self.b['filetime'] + 181*10_000_000
        self.assertEqual(self.worker.enqueue(incoming), 'duplicate')

    def test_termination_failure_cannot_repeat_as_b(self):
        incoming = self.prepare('process_exit_not_confirmed')
        self.assertEqual(self.worker.enqueue(incoming), 'duplicate')

    def test_prior_worker_cannot_replay(self):
        incoming = self.prepare()
        self.worker.owner = 'different-owner'
        self.assertEqual(self.worker.enqueue(incoming), 'duplicate')

    def test_hash_checks_require_additional_verified_changes(self):
        job = {'prior_changed_paths':['a'], 'evidence':{'verified_write_effects':{
            'changed_relative_paths':['a'], 'files_unverified':0, 'bounded_scan_incomplete':False}}}
        self.assertFalse(new_verified_facts(job))
        effects=job['evidence']['verified_write_effects']
        effects['changed_relative_paths'].append('b')
        self.assertTrue(new_verified_facts(job))
        effects['files_unverified']=1
        self.assertFalse(new_verified_facts(job))
