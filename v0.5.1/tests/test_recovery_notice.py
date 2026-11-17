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
        self.assertEqual(len(messages),1)
        message=messages[0]
        self.assertEqual(message['type'],'VSS_STATUS')
        self.assertEqual(message['data']['action'],'RESTORE_FAILED')
        self.assertIsNone(message['data']['snapshotId'])
        self.assertFalse(message['data']['recoveryVerified'])
        self.assertEqual(message['data']['recoveredFiles'],[])
        self.assertTrue(message['data']['decision']['firewallHoldRetained'])

    def test_ambiguous_jev_is_not_fabricated_as_restore_attempt(self):
        result=ResponseResult('review-case','B',ProcessInstance(100,133000000000000001))
        result.state='REVIEW_REQUIRED';result.reason='jev_ambiguous_demo_threshold'
        self.assertEqual(live_result_to_ui_messages(result,protected_root=r'C:\Lab'),[])
