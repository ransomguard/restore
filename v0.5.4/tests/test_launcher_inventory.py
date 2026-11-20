"""Cold boot inventory must work without an existing console Python process."""
import ast,json,subprocess,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

class InventoryTests(unittest.TestCase):
    def inventory(self,stdout):
        source=Path(__file__).resolve().parents[1]/'integration/windows/Start-RansomGuard.py'
        tree=ast.parse(source.read_text(encoding='utf8'))
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='inventory')
        ns={'json':json,'subprocess':subprocess}
        exec(compile(ast.Module(body=[function],type_ignores=[]),str(source),'exec'),ns)
        with patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=stdout)):
            return ns['inventory']()
    def test_cold_boot_empty_and_null(self):
        for value in (b'',b'\r\n',b'null\r\n',b'[]'):
            with self.subTest(value=value):self.assertEqual(self.inventory(value),[])
    def test_single_and_multiple_processes_preserved(self):
        row={'ProcessId':42,'ExecutablePath':'C:/product/python.exe'}
        self.assertEqual(self.inventory(json.dumps(row).encode()),[row])
        self.assertEqual(self.inventory(json.dumps([row,row]).encode()),[row,row])
    def test_malformed_data_is_not_treated_as_empty(self):
        for value in (b'garbage',b'[null]',b'42'):
            with self.subTest(value=value),self.assertRaises((ValueError,RuntimeError)):
                self.inventory(value)
