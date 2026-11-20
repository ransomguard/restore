import unittest
from ransomguard.incidents import ProcessInstance
from ransomguard.live_response import ResponseResult
from ransomguard.ui_bridge import live_result_to_ui_messages

class RecoveryNoticeTests(unittest.TestCase):
    def test_missing_snapshot_is_visible_without_fake_success_or_id(self):
        result=ResponseResult('stale-case','B',ProcessInstance(100,133000000000000001))
        result.state='REVIEW_REQUIRED';result.reason='recovery_snapshot_stale_or_not_preincident'
        result.firewall_hold_retained=True
        messages=live_result_to_ui_messages(result,protected_root=r'C:\Lab',now_seconds=1)
        self.assertEqual(len(messages),2)
        alerts=[m for m in messages if m['type']=='ALERT']
        self.assertEqual(len(alerts),1)
        self.assertEqual(alerts[0]['data']['action'],'REVIEW_REQUIRED')
        self.assertFalse(alerts[0]['data']['terminationConfirmed'])
        self.assertIsNone(alerts[0]['data']['threatScore'])
        message=next(m for m in messages if m['type']=='VSS_STATUS')
        self.assertEqual(message['type'],'VSS_STATUS')
        self.assertEqual(message['data']['action'],'RESTORE_FAILED')
        self.assertIsNone(message['data']['snapshotId'])
        self.assertFalse(message['data']['recoveryVerified'])
        self.assertEqual(message['data']['recoveredFiles'],[])
        self.assertTrue(message['data']['decision']['firewallHoldRetained'])

    def test_ambiguous_jev_is_not_fabricated_as_restore_attempt(self):
        result=ResponseResult('review-case','B',ProcessInstance(100,133000000000000001))
        result.state='REVIEW_REQUIRED';result.reason='jev_ambiguous_demo_threshold'
        messages=live_result_to_ui_messages(result,protected_root=r'C:\Lab')
        self.assertEqual(len(messages),1)
        self.assertEqual(messages[0]['type'],'ALERT')
        self.assertEqual(messages[0]['data']['action'],'REVIEW_REQUIRED')
        self.assertFalse(messages[0]['data']['decision']['recoveryVerified'])
        self.assertFalse(messages[0]['data']['terminationConfirmed'])
