from contextlib import closing
import argparse
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from ransomguard import scope_settings as s


class ScopeTests(unittest.TestCase):
    def test_bounded_settings_wait_acquires_after_short_background_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            held=threading.Event()
            def background():
                with s.scope_lock(tmp):
                    held.set();time.sleep(.15)
            worker=threading.Thread(target=background);worker.start()
            try:
                self.assertTrue(held.wait(1))
                with s.scope_lock(tmp,timeout=1):pass
            finally:worker.join(2)

    def test_hold_and_review_block_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp)
            with closing(sqlite3.connect(b/'holds.sqlite3',isolation_level=None)) as db:
                db.execute('CREATE TABLE firewall_holds(incident_id TEXT)');db.execute("INSERT INTO firewall_holds VALUES('pending')")
            with self.assertRaises(RuntimeError):s.assert_idle(b)
            with closing(sqlite3.connect(b/'holds.sqlite3',isolation_level=None)) as db:db.execute('DELETE FROM firewall_holds')
            with closing(sqlite3.connect(b/'observe.sqlite3',isolation_level=None)) as db:
                db.execute('CREATE TABLE response_jobs(state TEXT)');db.execute("INSERT INTO response_jobs VALUES('REVIEW_REQUIRED')")
            with self.assertRaises(RuntimeError):s.assert_idle(b)
            with closing(sqlite3.connect(b/'observe.sqlite3',isolation_level=None)) as db:db.execute("UPDATE response_jobs SET state='RELEASED'")
            s.assert_idle(b)

    def test_scope_lock_excludes_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            with s.scope_lock(tmp):
                with self.assertRaises(s.ScopeBusy):
                    with s.scope_lock(tmp):pass
            with s.scope_lock(tmp):pass

    def test_observer_can_disable_live_and_rollback_original_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp);args=argparse.Namespace(db=str(b/'observe.sqlite3'),live_track_a=True,live_track_b=True,config='original')
            s.save_json(b/'scope-settings-enabled.json',{'schema_version':1})
            s.apply_observer_scope(args)
            self.assertFalse(args.live_track_b)
            (b/'scope-settings-enabled.json').unlink()
            s.apply_observer_scope(args)
            self.assertTrue(args.live_track_b);self.assertEqual(args.config,'original')

    def test_failed_baseline_restores_all_original_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp);s.save_json(b/'protection.json',{'protected_root':'old'})
            original=(b/'protection.json').read_bytes()
            with patch.object(s,'validate_folder',return_value=('C:\\Documents','C:\\')),patch('ransomguard.protection_setup.validate_folder',return_value=('C:\\Documents','C:\\')),patch.object(s,'refresh',return_value={'ready':False,'reason':'no_snapshot'}):
                with self.assertRaisesRegex(RuntimeError,'no_snapshot'):
                    s.change(b,{'folder':'C:\\Documents','acknowledgeFolderRevert':True,'snapshotBudgetGiB':8})
            self.assertEqual(original,(b/'protection.json').read_bytes())
            self.assertFalse((b/'live-response-profile.json').exists())

    def test_first_scope_applies_after_worker_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp)
            s.save_json(b/'installation.json',{'recovery_root':str(b/'backend')})
            s.save_json(b/'response-config.json',{'recovery':{}})
            s.save_json(b/'scope-authorization.json',{'schema_version':1,'authorized_isolated_lab':True,'tracks':['A','B']})
            s.save_json(b/'jev-transport.json',{'bridge':'bridge.exe'})
            def refresh(*a,**k):
                s.save_json(b/'protection-status.json',{'ready':True,'at':__import__('time').time(),'files':1})
                return {'ready':True}
            def reload(*a,**k):
                s.save_json(b/'observer-ready.json',{'reload_request_id':'scope-test','worker_state':'running'})
                return {'id':'scope-test'}
            with patch.object(s,'validate_folder',return_value=('C:\\Documents','C:\\')),patch('ransomguard.protection_setup.validate_folder',return_value=('C:\\Documents','C:\\')),patch.object(s,'refresh',side_effect=refresh),patch('ransomguard.observer_filter._query_dos_device',return_value='\\Device\\HarddiskVolume3'),patch('ransomguard.resident.request_reload',side_effect=reload),patch('subprocess.run',return_value=argparse.Namespace(returncode=0)),patch('ransomguard.live_profile.observer_options',return_value=([],'test')):
                result=s.change(b,{'folder':'C:\\Documents','acknowledgeFolderRevert':True,'snapshotBudgetGiB':8})
            self.assertEqual(result['protectedRoot'],'C:\\Documents');self.assertTrue(result['automaticResponse'])
            self.assertTrue((b/'scope-settings-enabled.json').exists())

if __name__=='__main__':unittest.main()
