import unittest
import time
from ransomguard.supervision import assess, allow_restart, maintenance_active

DB = r"C:\RG_Test\state\observe.sqlite3"
UI = r"C:\RG_Test\Dashboard\ransom0-ui.exe"
FW = r"C:\RG_Test\firewall\r0-fw-daemon.exe"


class SupervisionTests(unittest.TestCase):
    def setUp(self):
        self.runtime = dict(mode="observe-only", ui=1, daemon=2)
        self.ready = dict(driver_registered=True, pid=3, db=DB)
        self.processes = [dict(ProcessId=1, ExecutablePath=UI), dict(ProcessId=2, ExecutablePath=FW)]
        self.observer = dict(ProcessId=3, ExecutablePath=r"C:\Python\python.exe",
                             CommandLine=f'python.exe -m ransomguard observe --db "{DB}"')

    def check(self, processes):
        return assess(processes, self.runtime, self.ready, db_path=DB, ui_path=UI, daemon_path=FW)

    def test_absent_observer_requires_known_ui_and_firewall(self):
        self.assertEqual(self.check(self.processes)[0], "restart_collector")
        self.assertEqual(self.check(self.processes[:1])[1], "firewall_daemon_missing")
        self.assertEqual(self.check(self.processes[1:])[1], "ui_closed_or_missing")

    def test_healthy_observer_and_stale_ready_pid(self):
        self.assertEqual(self.check(self.processes + [self.observer])[0], "observing")
        self.ready["pid"] = 4
        self.assertEqual(self.check(self.processes + [self.observer])[1], "collector_alive_but_not_ready")

    def test_similar_path_or_reused_ui_pid_not_adopted(self):
        self.observer["CommandLine"] += ".other"
        self.assertEqual(self.check(self.processes + [self.observer])[0], "restart_collector")
        self.processes[0]["ExecutablePath"] = r"C:\other\ransom0-ui.exe"
        self.assertEqual(self.check(self.processes)[1], "ui_closed_or_missing")

    def test_live_runtime_never_restarted(self):
        self.runtime["mode"] = "live"
        self.assertEqual(self.check(self.processes)[1], "not_passive_runtime")

    def test_only_matching_validated_finite_live_profile_can_restart(self):
        self.runtime['mode']='scoped-live-track-a-b'
        def check(mode):
            return assess(self.processes,self.runtime,self.ready,db_path=DB,ui_path=UI,
                          daemon_path=FW,authorized_live_mode=mode)
        self.assertEqual(check(None)[0],'manual_attention')
        self.assertEqual(check('scoped-live-track-b')[0],'manual_attention')
        self.assertEqual(check('scoped-live-track-a-b')[0],'restart_collector')

    def test_resident_failed_or_stale_worker_is_not_reported_healthy(self):
        self.ready.update(resident=True,worker_state='running',observed_at=time.time())
        self.assertEqual(self.check(self.processes+[self.observer])[0],'observing')
        self.ready['observed_at']=time.time()-60
        self.assertEqual(self.check(self.processes+[self.observer])[1],'resident_worker_health_stale')
        self.ready['worker_state']='failed'
        self.assertEqual(self.check(self.processes+[self.observer])[1],'resident_worker_failed_intake_retained')
        self.assertEqual(self.check([self.observer])[1],'resident_worker_failed_intake_retained')
        self.ready['pid']=4
        self.assertEqual(self.check([self.observer])[1],'ui_closed_or_missing')

    def test_restart_budget_and_clock_rollback(self):
        self.assertFalse(allow_restart([901, 902, 903], 1000)[0])
        self.assertTrue(allow_restart([1, 2, 3], 1000)[0])
        self.assertFalse(allow_restart([1001, 1002, 1003], 1000)[0])

    def test_maintenance_expires_and_is_bounded(self):
        self.assertTrue(maintenance_active(dict(created_at=10, until=50, reason="test"), 20))
        self.assertFalse(maintenance_active(dict(created_at=10, until=50, reason="test"), 50))
        self.assertFalse(maintenance_active(dict(created_at=10, until=5000, reason="test"), 20))
        self.assertFalse(maintenance_active({}, 20))
