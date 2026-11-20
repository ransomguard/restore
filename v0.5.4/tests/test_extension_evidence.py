import unittest
from types import SimpleNamespace
from ransomguard.extension_evidence import extension_change_attempt
class ExtensionTests(unittest.TestCase):
 def test_changes_and_unchanged(self):
  for path,ext,result in [(r'C:\x\a.txt','locked',True),(r'C:\x\a.TXT','txt',False),(r'C:\x\a','txt',True),(r'C:\x\a.txt','',True),(r'C:\x\a','',False),(r'C:\x\a.tar.gz','gz',False)]:
   with self.subTest(path=path,ext=ext):self.assertIs(extension_change_attempt(SimpleNamespace(event_type=5,fields={'path':path,'new_extension':ext,'flags':16})),result)
 def test_unknown_is_not_zero(self):
  for flag in [1,2,32]:self.assertIsNone(extension_change_attempt(SimpleNamespace(event_type=5,fields={'path':r'C:\x\a.txt','new_extension':'locked','flags':flag})))
  self.assertIsNone(extension_change_attempt(SimpleNamespace(event_type=5,fields={'path':r'C:\x\a.txt','flags':16})))

class CompletionTests(unittest.TestCase):
 def test_results_are_never_inferred_from_attempts(self):
  from ransomguard.extension_evidence import rename_completion
  for flags,want in [(16,"unknown"),(16|128,"failed"),(16|128|256,"succeeded"),(256,"unknown")]:
   self.assertEqual(rename_completion(SimpleNamespace(event_type=5,fields={"flags":flags})),want)
