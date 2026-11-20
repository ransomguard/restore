import tempfile
import unittest
from pathlib import Path
from ransomguard.firewall_control import FirewallHoldManager, FirewallProfile
from tests.test_firewall_ipc import FakeFirewallDaemon


class DashboardPolicyTests(unittest.TestCase):
    def test_daemon_restart_reasserts_owned_review_hold_without_releasing_it(self):
        with tempfile.TemporaryDirectory() as folder:
            daemon = FakeFirewallDaemon()
            daemon.allowlist = ['192.0.2.8:443']
            path=Path(folder)/'holds.sqlite3'
            profile=FirewallProfile('https://api.typesafe.ai')
            with FirewallHoldManager(path,profile,client=daemon) as owner:
                owner.acquire('incident','A');owner.retain_for_review('incident')
            daemon.active=False;daemon.allowlist=[]
            with FirewallHoldManager(path,profile,client=daemon) as owner:
                self.assertTrue(owner.reconcile_owned_holds()['reasserted'])
                self.assertEqual(daemon.allowlist, profile.allowlist + ['192.0.2.8:443'])
                self.assertEqual(owner.status()['holds'][0]['state'],'review_required')
                self.assertFalse(owner.reconcile_owned_holds()['reasserted'])
                owner.operator_review_release('incident',operator_verified_safe=True)
                self.assertEqual(daemon.allowlist,['192.0.2.8:443'])

    def test_reconcile_does_not_adopt_drifted_or_uncertain_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            daemon=FakeFirewallDaemon()
            with FirewallHoldManager(Path(folder)/'holds.sqlite3',FirewallProfile('https://api.typesafe.ai'),client=daemon) as owner:
                self.assertEqual(owner.reconcile_owned_holds()['active_holds'],0)
                self.assertFalse(daemon.active)
                owner.acquire('incident','A')
                daemon.allowlist=['192.0.2.9:443']
                with self.assertRaises(RuntimeError):owner.reconcile_owned_holds()
                self.assertEqual(daemon.allowlist,['192.0.2.9:443'])
                owner.db.execute('UPDATE firewall_owner SET policy_acknowledged=0');owner.db.commit()
                daemon.active=False
                with self.assertRaises(RuntimeError):owner.reconcile_owned_holds()
                self.assertFalse(daemon.active)
                self.assertEqual(owner.status(with_daemon=False)['active_holds'],1)

    def test_saved_exceptions_survive_restart_and_overlapping_holds(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'holds.sqlite3'
            daemon = FakeFirewallDaemon()
            daemon.allowlist = ['192.0.2.8:443', 'https://example.com']
            saved = list(daemon.allowlist)
            profile = FirewallProfile('https://api.typesafe.ai')
            with FirewallHoldManager(path, profile, client=daemon) as owner:
                owner.acquire('a', 'A')
                owner.acquire('b', 'B')
                owner.release('a')
                self.assertTrue(daemon.active)
                self.assertEqual(daemon.allowlist, profile.allowlist + saved)
            with FirewallHoldManager(path, profile, client=daemon) as owner:
                owner.release('b')
                self.assertFalse(daemon.active)
                self.assertEqual(daemon.allowlist, saved)
                self.assertEqual(owner.status()['active_holds'], 0)

    def test_failed_restore_does_not_claim_release(self):
        with tempfile.TemporaryDirectory() as folder:
            daemon = FakeFirewallDaemon()
            with FirewallHoldManager(Path(folder)/'holds.sqlite3', FirewallProfile('https://api.typesafe.ai'), client=daemon) as owner:
                owner.acquire('a', 'A')
                daemon.fail_action = 'set'
                with self.assertRaises(TimeoutError):
                    owner.release('a')
                self.assertEqual(owner.status(with_daemon=False)['active_holds'], 1)
