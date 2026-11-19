"""Configuration never executes the supplied programs or changes existing state."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployment_configure', ROOT/'deployment'/'configure.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rg deployment space ')
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.runtime = base/'runtime with spaces'
        self.programs = [base/name for name in ('python.exe', 'ransom0-ui.exe', 'r0-fw-daemon.exe')]
        for p in self.programs:
            p.write_bytes(b'not executable -- configuration must not run this')

    def run_config(self, **kw):
        return module.configure(ROOT, self.runtime, *self.programs, **kw)

    def test_check_does_not_write(self):
        self.run_config(check=True)
        self.assertFalse(self.runtime.exists())

    def test_isolated_python_can_import_launchers_without_running_services(self):
        self.run_config()
        for name in ('Start-RansomGuard.py', 'Watch-RansomGuard.py'):
            code = 'import runpy;runpy.run_path(' + repr(str(self.runtime/name)) + ",run_name='import_check')"
            result = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertFalse((self.runtime/'observer-ready.json').exists())

    def test_space_paths_roundtrip_and_idempotency_preserve_evidence(self):
        expected = self.run_config()
        evidence = self.runtime/'observe.sqlite3'
        evidence.write_bytes(b'existing evidence')
        self.run_config()
        self.assertEqual(evidence.read_bytes(), b'existing evidence')
        self.assertEqual(json.loads((self.runtime/'installation.json').read_text()), expected)
        path_spec = importlib.util.spec_from_file_location('paths', self.runtime/'installation_paths.py')
        paths = importlib.util.module_from_spec(path_spec)
        path_spec.loader.exec_module(paths)
        base, settings = paths.load_paths(self.runtime/'Start-RansomGuard.py')
        self.assertEqual(base, self.runtime)
        self.assertEqual(settings['ui'], self.programs[1])
        self.assertFalse((base/'live-response-profile.json').exists())

    def test_refuse_unknown_runtime(self):
        self.runtime.mkdir()
        (self.runtime/'holds.sqlite3').write_bytes(b'hold')
        with self.assertRaisesRegex(ValueError, 'empty runtime'):
            self.run_config()

    def test_refuse_changed_configuration(self):
        self.run_config()
        alternate = self.programs[0].parent/'alternate'/'python.exe'
        alternate.parent.mkdir()
        alternate.write_bytes(b'fake')
        with self.assertRaisesRegex(ValueError, 'differs'):
            module.configure(ROOT, self.runtime, alternate, *self.programs[1:])

    def test_refuse_missing_binary_and_changed_launcher(self):
        self.run_config()
        (self.runtime/'Start-RansomGuard.py').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'launcher differs'):
            self.run_config()
        self.programs[1].unlink()
        with self.assertRaisesRegex(ValueError, 'Required file missing'):
            self.run_config(check=True)
