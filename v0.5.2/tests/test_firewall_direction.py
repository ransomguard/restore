import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from ransomguard.firewall_control import FirewallHoldManager, FirewallProfile, FirewallHoldError
from ransomguard.firewall_ipc import encode_firewall_request, decode_firewall_response, FirewallProtocolError
from tests.test_firewall_ipc import FakeFirewallDaemon


class DirectionDaemon(FakeFirewallDaemon):
    def __init__(self):
        super().__init__()
        self.direction = 'both'

    def request(self, action, *, whitelist=None, direction=None):
        if direction is not None:
            self.direction = {'out': 'outbound', 'in': 'inbound', 'both': 'both'}[direction]
        result = super().request(action, whitelist=whitelist)
        if action != 'off':
            result['direction'] = self.direction
        return result


class DirectionTests(unittest.TestCase):
    def test_wire_direction_and_incremental_ack(self):
        for action in ('on', 'set', 'add', 'remove'):
            wire = encode_firewall_request(action, whitelist=[], direction='out')
            self.assertEqual(json.loads(wire)['direction'], 'out')
        for action, direction in [('get', 'out'), ('off', 'both'), ('set', []), ('set', 'invalid')]:
            with self.assertRaises(ValueError):
                encode_firewall_request(action, direction=direction)
        response = {'success': True, 'action': 'add', 'active': False, 'direction': 'outbound',
                    'whitelist': [{'value': 'existing', 'type': 'domain', 'data': {}}]}
        raw = (json.dumps(response) + '\n').encode()
        decode_firewall_response(raw, action='add', requested_whitelist=[], requested_direction='out')
        with self.assertRaises(FirewallProtocolError):
            decode_firewall_response(raw, action='add', requested_direction='both')

    def test_baseline_direction_survives_restart_and_is_restored(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / 'holds.db'
            daemon = DirectionDaemon()
            daemon.allowlist = ['https://baseline.example']
            profile = FirewallProfile('https://api.example')
            with FirewallHoldManager(db, profile, client=daemon) as manager:
                manager.acquire('A', 'A')
                self.assertEqual(daemon.direction, 'outbound')
                self.assertEqual(manager.db.execute('SELECT direction FROM firewall_baseline').fetchone()[0], 'both')
            with FirewallHoldManager(db, profile, client=daemon) as manager:
                manager.release('A')
                self.assertFalse(daemon.active)
                self.assertEqual(daemon.direction, 'both')
                self.assertEqual(daemon.allowlist, ['https://baseline.example'])

    def test_direction_drift_cannot_release_or_overwrite_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            daemon = DirectionDaemon()
            with FirewallHoldManager(Path(temp)/'holds.db', FirewallProfile('https://api.example'), client=daemon) as manager:
                manager.acquire('A', 'A')
                daemon.direction = 'both'
                with self.assertRaises(FirewallHoldError):
                    manager.release('A')
                with self.assertRaises(FirewallHoldError):
                    manager.acquire('B', 'B')
                self.assertEqual(sum(action == 'on' for action, _ in daemon.calls), 1)
                self.assertNotIn('off', [action for action, _ in daemon.calls])
                self.assertEqual(manager.status(with_daemon=False)['active_holds'], 2)

    def test_legacy_database_migrates_outbound_without_losing_hold(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'holds.db'
            with closing(sqlite3.connect(path)) as db:
                db.executescript('''CREATE TABLE firewall_owner(singleton INTEGER PRIMARY KEY, allowlist_json TEXT, policy_acknowledged INTEGER);
                    CREATE TABLE firewall_baseline(singleton INTEGER PRIMARY KEY, allowlist_json TEXT);
                    INSERT INTO firewall_owner VALUES(1, '["https://api.example"]', 0);
                    INSERT INTO firewall_baseline VALUES(1, '[]');''')
            with FirewallHoldManager(path, FirewallProfile('https://api.example'), client=DirectionDaemon()) as manager:
                self.assertEqual(manager._profile_row(), (['https://api.example'], False, 'out'))
                self.assertEqual(manager.db.execute('SELECT direction FROM firewall_baseline').fetchone()[0], 'out')
