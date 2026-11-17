import hashlib,json,os
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
from ransomguard.file_evidence import locked_hash,measure_changes

@unittest.skipUnless(os.name=='nt','Windows sharing and handle-path validation')
class FileEvidenceTests(unittest.TestCase):
    def test_actual_bytes_are_measured_only_for_observed_approved_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'one.bin';q=root/'other.bin'
            old=b'previous';p.write_bytes(b'changed');q.write_bytes(b'changed too')
            template={'protected_root':str(root),'manifest':[{'relative_path':n,'expected_sha256':hashlib.sha256(old).hexdigest()} for n in ('one.bin','other.bin')]}
            manifest=root/'manifest.json';manifest.write_text(json.dumps(template))
            prefix=r'\Device\HarddiskVolume3'+str(root)[2:]
            evidence={'evidence':{'sample_source_paths':[prefix+r'\one.bin']}}
            with patch('ransomguard.file_evidence._query_dos_device',return_value=r'\Device\HarddiskVolume3'):
                result=measure_changes(manifest,evidence,approved_prefix=prefix)
                self.assertEqual(result['files_changed_sha256'],1)
                self.assertEqual(result['files_checked'],1)
                self.assertFalse(result['process_causation_proven'])
                self.assertEqual(result['changed_relative_paths'],['one.bin'])
                with self.assertRaises(ValueError):measure_changes(manifest,evidence,approved_prefix=prefix+r'\outside')
            with self.assertRaises(ValueError):locked_hash(p,max_bytes=1)

    def test_file_open_for_writing_is_unverified_not_a_malware_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'busy.bin';p.write_bytes(b'original')
            with p.open('wb') as writer:
                writer.write(b'busy');writer.flush()
                with self.assertRaises(OSError):locked_hash(p)
