from datetime import datetime,timezone
import json,os,queue,sqlite3,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from ransomguard.protection_setup import configure_scope,validate_folder,save_json,ensure_response_database
from ransomguard.health_report import report
from ransomguard.snapshots import HourlySnapshotCoordinator
from ransomguard.recovery import Snapshot
from ransomguard.storage_maintenance import StorageMaintenance
from ransomguard.installer_drain import InstallerDrain

class PrototypeSetupTests(unittest.TestCase):
    def test_periodic_snapshot_does_not_initialize_live_outbox(self):
        with tempfile.TemporaryDirectory() as t:
            b=Path(t);ensure_response_database(b)
            with patch('ransomguard.outbox.Outbox',side_effect=AssertionError('Live writer must not open')):
                ensure_response_database(b)
            from contextlib import closing
            with closing(sqlite3.connect(b/'observe.sqlite3')) as db:
                db.execute('DROP TABLE response_jobs')
                db.commit()
            with self.assertRaises(ValueError):ensure_response_database(b)

    def test_drain_rejects_other_session_and_preserves_unrequested_stop(self):
        with tempfile.TemporaryDirectory() as t:
            ready=Path(t)/'observer-ready.json'
            reader=SimpleNamespace(queue=queue.Queue(),status=lambda:(_ for _ in ()).throw(AssertionError('No driver call')))
            d=InstallerDrain(ready,reader,'this-session')
            self.assertTrue(d.ready_to_close())
            save_json(ready.with_suffix('.install-stop.json'),dict(pid=os.getpid(),session='other',file_filter_stopped=True,expires=time.time()+30))
            self.assertTrue(d.ready_to_close());self.assertFalse(d.active)
    def test_health_never_opens_database_and_preserves_totals(self):
        with tempfile.TemporaryDirectory() as t:
            b=Path(t);save_json(b/'observer-ready.json',dict(observed_at=90,worker_state='running',pid=99,counter_totals={'events_dropped':103110}))
            with patch('sqlite3.connect',side_effect=AssertionError('No DB in a health query')):
                r=report(b,now=100)
            self.assertTrue(r['collector_ready']);self.assertEqual(r['counters']['events_dropped'],103110)
            self.assertFalse(report(b,now=110)['collector_ready'])

    def test_old_baseline_status_is_not_presented_as_ready(self):
        with tempfile.TemporaryDirectory() as t:
            b=Path(t);save_json(b/'protection-status.json',dict(at=100,ready=True,files=3))
            self.assertTrue(report(b,now=101)['recovery']['ready'])
            r=report(b,now=7301)
            self.assertFalse(r['recovery']['ready'])
            self.assertEqual(r['recovery']['reason'],'baseline_status_stale')
            self.assertTrue(json.loads((b/'protection-status.json').read_text())['ready'])

    @unittest.skipUnless(os.name=='nt','Windows path validation')
    def test_scope_requires_consent_and_rejects_application_and_volume(self):
        with tempfile.TemporaryDirectory() as t:
            b=Path(t);runtime=b/'runtime';runtime.mkdir();folder=b/'documents';folder.mkdir()
            with self.assertRaises(ValueError):configure_scope(runtime,folder,acknowledge_folder_revert=False)
            with self.assertRaises(ValueError):validate_folder(folder.anchor)
            with self.assertRaises(ValueError):validate_folder(runtime,forbidden=(str(runtime),))
            configure_scope(runtime,folder,acknowledge_folder_revert=True)
            config=json.loads((runtime/'protection.json').read_text())
            self.assertEqual(config['snapshot_budget_gib'],8)
            self.assertFalse((runtime/'protected-manifest.json').exists())

    def test_explicit_setup_refreshes_baseline_but_schedule_keeps_cooldown(self):
        at=datetime.now(timezone.utc);volume='\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\'
        s=Snapshot('{22222222-2222-2222-2222-222222222222}',volume,at,r'\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1')
        with tempfile.TemporaryDirectory() as t:
            calls=[]
            def create(*a,**k):calls.append(1);return s
            c=HourlySnapshotCoordinator(Path(t)/'state.db',volume_resolver=lambda x:volume,create_fn=create,clock=lambda:at)
            self.assertTrue(c.run(trigger='initial_setup')['created'])
            self.assertTrue(c.run(trigger='initial_setup')['created'])
            self.assertFalse(c.run()['attempted']);self.assertEqual(len(calls),2)
            with self.assertRaises(ValueError):c.run(trigger='incident')

    def test_background_checkpoint_preserves_rows_and_defers_when_reader_busy(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'outbox.db';q=queue.Queue();q.put(1)
            db=sqlite3.connect(p);db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA wal_autocheckpoint=0')
            db.execute('CREATE TABLE evidence(payload BLOB)');db.executemany('INSERT INTO evidence VALUES(?)',[(b'x'*8192,)]*600);db.commit()
            q.qsize=lambda:200
            m=StorageMaintenance(p,SimpleNamespace(queue=q),interval=.01).start()
            time.sleep(.05);self.assertEqual(m.result['runs'],0)
            q.qsize=lambda:0
            limit=time.monotonic()+3
            while m.result['runs']==0 and time.monotonic()<limit:time.sleep(.01)
            m.close();self.assertGreater(m.result['runs'],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],600)
            db.close()
