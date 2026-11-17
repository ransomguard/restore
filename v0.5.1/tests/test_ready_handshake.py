import contextlib,io,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from ransomguard.cli import main
from ransomguard.outbox import Outbox
from tests.test_cli_integration import FakeReader


class ReadyTests(unittest.TestCase):
    def test_ready_requires_driver_and_committed_outbox_before_first_read(self):
        with tempfile.TemporaryDirectory() as folder:
            ready=Path(folder)/'ready.json';db=Path(folder)/'events.sqlite3'
            case=self
            class Reader(FakeReader):
                def status(self):
                    from ransomguard.counter_history import COUNTERS
                    return {**dict.fromkeys(COUNTERS, 0), 'magic': 0x41525747, 'version': 0x10000,
                            'engine_pid': os.getpid(), 'queue_depth': 0, 'fastpath_mode': 1,
                            'self_protect_enabled': 0}
                def read(self):
                    state=json.loads(ready.read_text())
                    case.assertTrue(state['driver_registered'])
                    case.assertEqual(state['pid'],os.getpid())
                    with Outbox(db) as out:case.assertEqual(out.pending()[0]['event_type'],'observer_started')
                    return super().read()
            with patch('ransomguard.windows_reader.WindowsDriverReader',Reader),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['observe','--db',str(db),'--ready-file',str(ready),'--limit','3']),0)

    def test_failed_driver_registration_never_reports_ready(self):
        with tempfile.TemporaryDirectory() as folder:
            ready=Path(folder)/'ready.json'
            with patch('ransomguard.windows_reader.WindowsDriverReader',side_effect=OSError('registration rejected')),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['observe','--db',str(Path(folder)/'events.sqlite3'),'--ready-file',str(ready)]),1)
            self.assertFalse(ready.exists())
