import hashlib
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ransomguard.recovery import LocalSnapshotBackend, RecoveryEngine, RecoveryValidationError, build_plan
from ransomguard.recovery_catalog import catalog_snapshot, require_fresh_snapshot
from ransomguard.response_commands import recovery_plan_from_template
from tests.test_recovery import INCIDENT, VOLUME, snapshot


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.source=self.base/'snapshot';self.dest=self.base/'live'
        (self.source/'protected'/'한글 폴더').mkdir(parents=True);(self.dest/'protected').mkdir(parents=True)
        for index in range(40):
            (self.source/'protected'/'한글 폴더'/f'doc {index}.txt').write_bytes(f'original {index}'.encode())
        self.backend=LocalSnapshotBackend(snapshot_root=self.source,volume_root=self.dest)

    def catalog(self, **kw):
        return catalog_snapshot(snapshot(),volume_root='C:\\',protected_root=r'C:\protected',
                                reference_at=INCIDENT,backend=self.backend,**kw)

    def test_40_files_unicode_hashes_and_actual_fixture_restore(self):
        value=self.catalog();self.assertEqual(len(value['manifest']),40)
        self.assertFalse(value['automatic_activation']);self.assertFalse(value['complete_affected_file_list'])
        plan=build_plan(snapshot(),volume_root='C:\\',protected_root=r'C:\protected',manifest=value['manifest'],incident_at=INCIDENT)
        result=RecoveryEngine(backend=self.backend).execute(plan,allow_local_test=True,containment_confirmed=True)
        self.assertEqual(result['files_verified'],40)
        for item in value['manifest']:
            data=(self.dest/'protected'/Path(*item['relative_path'].split('\\'))).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(),item['expected_sha256'])

    def test_limits_never_return_partial_catalog(self):
        for limits in ({'max_files':39},{'max_total_bytes':3},{'max_file_bytes':1}):
            with self.subTest(limits=limits), self.assertRaises(RecoveryValidationError):self.catalog(**limits)

    def test_symlink_refused(self):
        target=self.base/'outside';target.write_bytes(b'outside')
        try:(self.source/'protected'/'link').symlink_to(target)
        except OSError:self.skipTest('OS does not grant symlink privilege')
        with self.assertRaises(RecoveryValidationError):self.catalog()

    def test_old_future_and_invalid_age_refused(self):
        for item in (snapshot(age=timedelta(hours=3)),snapshot(age=timedelta(seconds=-1))):
            with self.assertRaises(RecoveryValidationError):require_fresh_snapshot(item,INCIDENT)
        for limit in (False,0,60.5,86401):
            with self.assertRaises(RecoveryValidationError):self.catalog(max_age_seconds=limit)

    def test_catalog_pins_snapshot_even_when_newer_exists(self):
        value=self.catalog();file=self.base/'manifest.json';file.write_text(json.dumps(value))
        with patch('ransomguard.response_commands.volume_id_for_root',return_value=VOLUME), \
             patch('ransomguard.response_commands.enumerate_snapshots',return_value=[snapshot(),snapshot(2,age=timedelta(minutes=3))]):
            selected=recovery_plan_from_template(str(file),incident_at=INCIDENT.isoformat())
        self.assertEqual(selected.snapshot.snapshot_id,snapshot().snapshot_id)
        with patch('ransomguard.response_commands.volume_id_for_root',return_value=VOLUME), \
             patch('ransomguard.response_commands.enumerate_snapshots',return_value=[snapshot(2)]):
            with self.assertRaises(RecoveryValidationError):recovery_plan_from_template(str(file),incident_at=INCIDENT.isoformat())

    def test_stale_legacy_manifest_is_refused(self):
        file=self.base/'manifest.json';file.write_text(json.dumps({'schema_version':1,'volume_root':'C:\\','protected_root':r'C:\protected','manifest':['one.txt']}))
        with patch('ransomguard.response_commands.volume_id_for_root',return_value=VOLUME), \
             patch('ransomguard.response_commands.enumerate_snapshots',return_value=[snapshot(age=timedelta(hours=3))]):
            with self.assertRaises(RecoveryValidationError):recovery_plan_from_template(str(file),incident_at=INCIDENT.isoformat())

    def test_live_response_retains_hold_and_precise_stale_reason(self):
        from tests.test_live_response import ResponseTests
        from ransomguard.recovery import SnapshotFreshnessError
        fixture=ResponseTests();fixture.setUp()
        try:
            def stale():raise SnapshotFreshnessError('old snapshot')
            result=fixture.coordinator.respond(track='B',process=fixture.process,jev_state={'fixture':True},
                recovery_plan_provider=stale,recovery_required=True,explicit_authorization=True)
            self.assertEqual(result.state,'REVIEW_REQUIRED')
            self.assertEqual(result.reason,'recovery_snapshot_stale_or_not_preincident')
            self.assertTrue(result.firewall_hold_retained)
            self.assertEqual(fixture.recovery.calls,[])
        finally:fixture.tearDown()
