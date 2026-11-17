import unittest
from dataclasses import replace
from ransomguard.track_a import TrackACorroborator
from ransomguard.protocol import Event, ProcessRegistry


class TrackATests(unittest.TestCase):
    def setUp(self):
        self.registry = ProcessRegistry()
        self.gate = TrackACorroborator(r'\Device\HarddiskVolume3\Lab')
        self.created = Event(1,'process_created',1,1000,600,{'process_create_time':900})
        self.write = Event(4,'file_write_attempted',2,2000,600,{'path':r'\Device\HarddiskVolume3\Lab\a.txt','flags':8})
        self.block = Event(3,'process_creation_blocked',3,3000,700,{'parent_pid':600,'creator_pid':600,'matched_rule_id':1001,'process_create_time':2500})

    def feed(self, event):
        self.registry.update(event)
        return self.gate.ingest(event,self.registry)

    def test_same_generation_corroboration(self):
        self.feed(self.created);self.feed(self.write)
        result=self.feed(self.block)
        self.assertEqual((result['pid'],result['create_time']),(600,900))

    def test_delayed_old_file_event_cannot_authorize_reused_pid(self):
        # FIFO sequence is assigned at enqueue, after the event timestamp.
        # A delayed old write may therefore have a newer sequence number.
        self.feed(replace(self.created, filetime=5000,
                          fields={'process_create_time':4900}))
        self.feed(self.write)  # timestamp 2000 predates this generation
        self.assertIsNone(self.feed(replace(self.block,filetime=6000)))

    def test_preexisting_process_without_observed_creation_is_not_authorized(self):
        self.feed(self.write)
        self.assertIsNone(self.feed(self.block))

    def test_exit_and_reuse_require_new_write_evidence(self):
        self.feed(self.created);self.feed(self.write)
        self.feed(Event(2,'process_exited',3,2500,600,{'process_create_time':900}))
        self.feed(replace(self.created,sequence=4,filetime=3000,
                          fields={'process_create_time':2900}))
        self.assertIsNone(self.feed(replace(self.block,sequence=5,filetime=3500)))

    def test_automatic_evidence_is_not_labeled_as_operator_confirmation(self):
        from ransomguard.live_response import ResponseResult
        from ransomguard.incidents import ProcessInstance
        from ransomguard.ui_bridge import live_result_to_ui_messages
        result=ResponseResult('lab','A',ProcessInstance(600,900))
        result.kernel_termination_accepted=result.exit_confirmed=True
        message=live_result_to_ui_messages(result,protected_root='lab',track_a_corroborated=True)[0]
        self.assertEqual(message['data']['ruleName'],'TRACK_A_CORROBORATED_LAB')

    def test_parent_pid_alone_is_insufficient(self):
        self.feed(self.created)
        self.assertIsNone(self.feed(replace(self.block,sequence=2)))

    def test_outside_scope_or_no_entropy_is_insufficient(self):
        for fields in ({'path':r'\Device\HarddiskVolume3\Lab-other\a','flags':8},
                       {'path':r'\Device\HarddiskVolume3\Lab\a','flags':0}):
            self.setUp();self.feed(self.created);self.feed(replace(self.write,fields=fields))
            self.assertIsNone(self.feed(self.block))

    def test_loss_reuse_stale_and_different_creator_defer(self):
        for change in ('loss','reuse','stale','creator'):
            self.setUp();self.feed(self.created);self.feed(self.write)
            blocked=self.block
            if change=='loss':self.registry.invalidate()
            if change=='reuse':self.registry._entries[600]=901
            if change=='stale':blocked=replace(blocked,filetime=100_002_001)
            if change=='creator':blocked=replace(blocked,fields={**blocked.fields,'creator_pid':999})
            self.assertIsNone(self.feed(blocked),change)
