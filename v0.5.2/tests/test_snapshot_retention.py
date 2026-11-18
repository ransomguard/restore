from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from ransomguard.recovery import Snapshot, RecoveryEngine, build_plan
from ransomguard.snapshot_retention import (GiB, RetentionPolicy, SnapshotRetention,
    protection_state, managed_creation, policy_path, pin_recovery, finish_recovery_pin, _DELETE_SCRIPT)
from ransomguard.snapshot_guard import snapshot_guard

VOLUME = r'\\?\Volume{11111111-1111-1111-1111-111111111111}' + '\\'
NOW = datetime(2026, 11, 18, 12, tzinfo=timezone.utc)


@contextmanager
def database(path):
    db=sqlite3.connect(path)
    try:
        with db:
            yield db
    finally:
        db.close()


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.db = self.base/'snapshots.sqlite3'
        self.items = [Snapshot('{00000000-0000-0000-0000-%012d}' % i, VOLUME,
            NOW-timedelta(hours=6-i), r'\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy'+str(i)) for i in range(1, 6)]
        with database(self.db) as db:
            db.execute('CREATE TABLE snapshot_attempts(volume_id,status,result_json)')
            for s in self.items:
                db.execute('INSERT INTO snapshot_attempts VALUES(?,?,?)', (VOLUME, 'created', json.dumps({
                    'created':True, 'reason':'vss_create_verified', 'snapshot':s.to_dict()})))
        self.foreign = Snapshot('{ffffffff-ffff-ffff-ffff-ffffffffffff}', VOLUME,
            NOW-timedelta(days=7), r'\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99')
        self.live = self.items+[self.foreign]
        self.deleted = []
        self.pins = set()
        self.config = {'policy':asdict(RetentionPolicy(max_count=3)), 'schema_version':1, 'enabled':True,
            'outbox_db':str(self.base/'events.db'), 'holds_db':str(self.base/'holds.db'),
            'manifest_paths':[str(self.base/'manifest.json')]}
        Path(self.config['manifest_paths'][0]).write_text(json.dumps({'schema_version':1,'manifest':['file.txt']}))
        with database(self.config['holds_db']) as db:
            db.execute('CREATE TABLE firewall_holds(incident_id,created_at)')
        with database(self.config['outbox_db']) as db:
            db.executescript('CREATE TABLE live_response_attempts(incident_id,claimed_at_utc,state);'
                'CREATE TABLE response_jobs(id,created,state);CREATE TABLE events(incident_id,kind,payload);')
        self.space = {'used_bytes':GiB, 'allocated_bytes':GiB, 'os_max_bytes':6*GiB, 'free_bytes':10*GiB}

    def delete(self, item):
        self.deleted.append(item.snapshot_id)
        self.live.remove(item)

    def manager(self, **overrides):
        args = dict(inventory=lambda _:list(self.live), storage=lambda _:dict(self.space),
                    delete=self.delete, protections=lambda *_:(self.pins, []), clock=lambda:NOW)
        args.update(overrides)
        return SnapshotRetention(self.db, self.config, **args)

    def test_preview_is_readonly_and_only_our_oldest_are_candidates(self):
        before = self.db.read_bytes()
        r=self.manager().run(VOLUME)
        self.assertFalse(self.deleted); self.assertEqual(before,self.db.read_bytes())
        self.assertEqual(r['candidates'],[s.snapshot_id for s in self.items[:3]])
        self.assertNotIn(self.foreign.snapshot_id,r['candidates'])

    def test_count_limit_deletes_oldest_exact_ids_and_retains_foreign(self):
        r=self.manager().run(VOLUME,apply=True)
        self.assertEqual(self.deleted,[s.snapshot_id for s in self.items[:2]])
        self.assertEqual(r['owned_count'],3);self.assertIn(self.foreign,self.live)
        with database(self.db) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM snapshot_deletions WHERE state='deleted'").fetchone()[0],2)

    def test_age_limit_preserves_latest_two_and_pinned_old_copy(self):
        self.config['policy'].update(max_count=12,max_age_seconds=7200)
        self.pins.add(self.items[0].snapshot_id)
        self.manager().run(VOLUME,apply=True)
        self.assertEqual(self.deleted,[s.snapshot_id for s in self.items[1:3]])

    def test_protected_count_over_limit_blocks_new_creation(self):
        self.pins.update(s.snapshot_id for s in self.items)
        r=self.manager().run(VOLUME,apply=True,reserve_for_creation=True)
        self.assertFalse(r['creation_allowed']);self.assertFalse(self.deleted)

    def test_creation_reserves_one_slot(self):
        r=self.manager().run(VOLUME,apply=True,reserve_for_creation=True)
        self.assertEqual(r['owned_count'],2);self.assertTrue(r['creation_allowed'])

    def test_capacity_remeasured_after_each_delete(self):
        self.config['policy']['max_count']=12
        self.space.update(used_bytes=5*GiB,allocated_bytes=5*GiB)
        def delete(item):
            self.delete(item);self.space.update(used_bytes=3*GiB,allocated_bytes=3*GiB)
        r=self.manager(delete=delete).run(VOLUME,apply=True)
        self.assertEqual(len(self.deleted),1);self.assertFalse(r['pressure'])

    def test_allocated_bytes_and_existing_os_cap_are_respected(self):
        self.config['policy']['max_count']=12
        self.space['allocated_bytes']=5*GiB
        self.assertTrue(self.manager().run(VOLUME)['pressure'])
        self.space.update(allocated_bytes=GiB,os_max_bytes=GiB)
        self.assertFalse(self.manager().run(VOLUME,reserve_for_creation=True)['creation_allowed'])

    def test_capacity_cannot_force_protected_or_foreign_deletion(self):
        self.space['free_bytes']=0;self.pins.update(s.snapshot_id for s in self.items)
        r=self.manager().run(VOLUME,apply=True)
        self.assertFalse(self.deleted);self.assertEqual(r['status'],'blocked')

    def test_reference_is_refreshed_between_deletions(self):
        self.config['policy']['max_count']=2
        def delete(item):
            self.delete(item);self.pins.add(self.items[1].snapshot_id)
        self.manager(delete=delete).run(VOLUME,apply=True)
        self.assertNotIn(self.items[1].snapshot_id,self.deleted)

    def test_uncertain_delete_is_not_retried(self):
        delete=Mock(side_effect=TimeoutError('uncertain'))
        first=self.manager(delete=delete).run(VOLUME,apply=True)
        second=self.manager(delete=delete).run(VOLUME,apply=True)
        self.assertEqual(delete.call_count,1);self.assertEqual(first['status'],'blocked')
        self.assertIn('Previous deletion',second['reason'])

    def test_success_return_without_absence_is_failure(self):
        r=self.manager(delete=lambda _:None).run(VOLUME,apply=True)
        self.assertEqual(r['status'],'blocked');self.assertFalse(r['deleted'])

    def test_other_snapshot_disappearance_stops_further_deletions(self):
        def delete(item):
            self.delete(item);self.live.remove(self.foreign)
        r=self.manager(delete=delete).run(VOLUME,apply=True)
        self.assertEqual(len(self.deleted),1);self.assertEqual(r['status'],'blocked')

    def test_missing_owned_copy_does_not_delete_some_other_copy(self):
        self.live.remove(self.items[0]);self.live.remove(self.items[1])
        r=self.manager().run(VOLUME,apply=True)
        self.assertFalse(self.deleted);self.assertEqual(len(r['missing_owned_ids']),2)

    def test_receipt_metadata_mismatch_blocks_everything(self):
        s=self.items[0];self.live[0]=Snapshot(s.snapshot_id,s.volume_id,s.created_at+timedelta(seconds=1),s.device_path)
        r=self.manager().run(VOLUME,apply=True)
        self.assertEqual(r['status'],'blocked');self.assertFalse(self.deleted)

    def test_device_renumbering_preserves_guid_volume_timestamp_ownership(self):
        s=self.items[0];self.live[0]=Snapshot(s.snapshot_id,s.volume_id,s.created_at,s.device_path+'0')
        r=self.manager().run(VOLUME,apply=True)
        self.assertEqual(r['status'],'ready');self.assertIn(s.snapshot_id,self.deleted)

    def test_reconciled_or_unrecorded_copies_are_not_owned(self):
        with database(self.db) as db:db.execute("UPDATE snapshot_attempts SET status='reconciled_created'")
        r=self.manager().run(VOLUME,apply=True)
        self.assertEqual(r['owned_count'],0);self.assertFalse(self.deleted)

    def test_unknown_creation_blocks_deletion(self):
        with database(self.db) as db:db.execute("UPDATE snapshot_attempts SET status='unknown' WHERE rowid=1")
        self.assertEqual(self.manager().run(VOLUME,apply=True)['status'],'blocked')
        self.assertFalse(self.deleted)

    def test_missing_corrupt_protection_sources_fail_closed(self):
        Path(self.config['holds_db']).unlink()
        r=self.manager(protections=protection_state).run(VOLUME,apply=True)
        self.assertEqual(r['status'],'blocked');self.assertFalse(self.deleted)
        self.assertFalse(Path(self.config['holds_db']).exists())

    def test_review_hold_without_raw_history_retains_preclaim_copies(self):
        with database(self.config['holds_db']) as db:
            db.execute('INSERT INTO firewall_holds VALUES(?,?)',('old-review',self.items[1].created_at.isoformat()))
        pins,_=protection_state(self.config,self.live)
        self.assertIn(self.items[0].snapshot_id,pins);self.assertIn(self.items[1].snapshot_id,pins)
        self.assertNotIn(self.items[2].snapshot_id,pins)

    def test_pending_job_and_explicit_manifest_pin_are_retained(self):
        with database(self.config['outbox_db']) as db:
            db.execute('INSERT INTO response_jobs VALUES(?,?,?)',('pending',self.items[0].created_at.timestamp(),'READY'))
        Path(self.config['manifest_paths'][0]).write_text(json.dumps({'schema_version':1,'manifest':['a'],'snapshot_id':self.items[2].snapshot_id}))
        pins,_=protection_state(self.config,self.live)
        self.assertIn(self.items[0].snapshot_id,pins);self.assertIn(self.items[2].snapshot_id,pins)

    def test_completed_job_does_not_pin(self):
        with database(self.config['outbox_db']) as db:
            db.execute('INSERT INTO response_jobs VALUES(?,?,?)',('done',NOW.timestamp(),'RELEASED'))
        self.assertFalse(protection_state(self.config,self.live)[0])

    def test_invalid_time_and_manifest_fail_closed(self):
        with database(self.config['holds_db']) as db:db.execute('INSERT INTO firewall_holds VALUES(?,?)',('bad','invalid'))
        r=self.manager(protections=protection_state).run(VOLUME,apply=True)
        self.assertEqual(r['status'],'blocked');self.assertFalse(self.deleted)

    def test_recovery_gate_excludes_cleanup_thread(self):
        entered=threading.Event()
        def worker():
            with snapshot_guard():entered.set()
        with snapshot_guard():
            t=threading.Thread(target=worker);t.start()
            self.assertFalse(entered.wait(.1))
        t.join(3);self.assertTrue(entered.is_set())

    def test_bounded_limits_and_exact_delete_contract(self):
        for values in ({'max_count':1},{'min_keep':13},{'max_used_bytes':1},{'max_age_seconds':1},{'max_count':True}):
            with self.assertRaises(ValueError):RetentionPolicy(**values)
        self.assertIn('Remove-CimInstance',_DELETE_SCRIPT)
        self.assertIn('metadata changed',_DELETE_SCRIPT)
        self.assertNotIn('vssadmin',_DELETE_SCRIPT)

    def test_managed_creation_is_not_called_while_protected_capacity_exceeded(self):
        policy_path(self.db).write_text(json.dumps(self.config))
        creation=Mock()
        with patch('ransomguard.snapshot_retention.SnapshotRetention.run',return_value={'creation_allowed':False}):
            result=managed_creation(type('C',(),{'state_db':self.db})(),'C:\\',VOLUME,creation)
        self.assertFalse(result['attempted']);creation.assert_not_called()

    def test_live_pin_survives_failure_and_restart_then_verified_release(self):
        policy_path(self.db).write_text(json.dumps(self.config))
        plan=build_plan(self.items[0],volume_root='C:\\',protected_root='C:\\Lab',manifest=['a'],incident_at=NOW)
        with patch('ransomguard.snapshots.default_state_db',return_value=self.db):
            state=pin_recovery(plan)
        finish_recovery_pin(state,plan.job_id,verified=False)
        first=self.manager().run(VOLUME,apply=True)
        self.assertIn(self.items[0].snapshot_id,first['protected_ids'])
        self.assertNotIn(self.items[0].snapshot_id,self.deleted)
        finish_recovery_pin(state,plan.job_id,verified=True)
        self.config['policy']['max_count']=2
        self.manager().run(VOLUME,apply=True)
        self.assertIn(self.items[0].snapshot_id,self.deleted)

    def test_missing_required_policy_never_bypasses_to_creation(self):
        creation=Mock()
        result=managed_creation(type('C',(),{'state_db':self.db})(),'C:\\',VOLUME,creation)
        self.assertEqual(result['reason'],'retention_policy_unavailable');creation.assert_not_called()

    def test_clock_rollback_blocks_cleanup(self):
        result=self.manager(clock=lambda:NOW-timedelta(days=1)).run(VOLUME,apply=True)
        self.assertEqual(result['status'],'blocked');self.assertFalse(self.deleted)

    def test_five_minute_task_cannot_create_snapshots(self):
        from ransomguard.scheduling import build_retention_task_xml
        xml=build_retention_task_xml(python_executable=r'C:\Lab\python.exe',config_path=r'C:\Lab\config.json',
            state_db=r'C:\Lab\state.db',outbox_db=r'C:\Lab\outbox.db',user_sid='S-1-5-21-1-2-3-1001',volume_root='C:\\',now=NOW)
        self.assertIn('PT5M',xml);self.assertIn('snapshot-retention',xml)
        self.assertNotIn('snapshot-run',xml);self.assertIn('InteractiveToken',xml)

    def setup_options(self):
        python=self.base/'python.exe';python.touch()
        config=self.base/'config.json';config.write_text(json.dumps({'schema_version':1,'recovery':{
            'snapshot_policy':'hourly_only','snapshot_interval_seconds':3600,
            'snapshot_creation_triggers':['hourly_schedule'],'volume_root':'C:\\'}}))
        return dict(python=python,config=config,outbox=self.config['outbox_db'],holds=self.config['holds_db'],
            manifests=self.config['manifest_paths'],user_sid='S-1-5-21-1-2-3-1001',output=self.base/'new-task.xml')

    def test_setup_check_preserves_original_ownership_and_creates_nothing(self):
        from deployment.configure_snapshot_retention import configure
        options=self.setup_options();before=self.db.read_bytes()
        with patch('deployment.configure_snapshot_retention.default_state_db',return_value=self.db):
            result=configure(**options,check=True)
        self.assertFalse(result['configured']);self.assertEqual(self.db.read_bytes(),before)
        self.assertFalse(policy_path(self.db).exists());self.assertFalse(options['output'].exists())

    def test_setup_rejects_different_existing_policy_without_overwrite(self):
        from deployment.configure_snapshot_retention import configure
        options=self.setup_options();policy_path(self.db).write_text('{"different":true}')
        with patch('deployment.configure_snapshot_retention.default_state_db',return_value=self.db):
            with self.assertRaises(ValueError):configure(**options)
        self.assertEqual(policy_path(self.db).read_text(),'{"different":true}')


if __name__=='__main__':unittest.main()
