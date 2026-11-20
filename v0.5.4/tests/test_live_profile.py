import json
from pathlib import Path
import tempfile
import unittest
from ransomguard.live_profile import observer_options


class LiveProfileTests(unittest.TestCase):
    def test_absent_profile_remains_passive(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(observer_options(Path(tmp)/'missing',state_db='holds'),([], 'observe-only'))

    def test_profile_scope_and_startup_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            config={'schema_version':1,'network':{'scope':'host_outbound','jev_url':'https://api.typesafe.ai'},
                    'decision':{'thresholds_are_demo_only':True}}
            (root/'config.json').write_text(json.dumps(config))
            (root/'manifest.json').write_text(json.dumps({'schema_version':1,'manifest':['approved.txt']}))
            profile={'schema_version':1,'authorized_isolated_lab':True,'tracks':['A','B'],
                     'nt_path_prefix':r'\Device\HarddiskVolume3\lab','config':str(root/'config.json'),
                     'manifest':str(root/'manifest.json')}
            path=root/'profile.json';path.write_text(json.dumps(profile))
            flags,mode=observer_options(path,state_db=root/'holds')
            self.assertIn('--async-response',flags)
            self.assertIn('--live-track-a',flags)
            self.assertIn('--live-track-b',flags)
            self.assertEqual(mode,'scoped-live-track-a-b')
            for change in ({'authorized_isolated_lab':False},{'nt_path_prefix':r'\Device\HarddiskVolume3'},
                           {'nt_path_prefix':r'\Device\HarddiskVolume3\lab\..\Windows'},
                           {'manifest':'relative.json'},{'tracks':[]}):
                with self.subTest(change=change):
                    path.write_text(json.dumps(profile|change))
                    with self.assertRaises(ValueError):observer_options(path,state_db=root/'holds')
            path.write_text(json.dumps(profile))
            config['network']['extra_https_targets']=['https://example.com']
            (root/'config.json').write_text(json.dumps(config))
            with self.assertRaises(ValueError):observer_options(path,state_db=root/'holds')
            path.write_text(json.dumps(profile | {'approved_extra_https_targets':['https://example.com']}))
            self.assertIn('--live-track-b', observer_options(path,state_db=root/'holds')[0])
            for targets in (['https://other.example'], ['https://*.example.com'], 'https://example.com', ['https://example.com']*2):
                path.write_text(json.dumps(profile | {'approved_extra_https_targets':targets}))
                with self.subTest(targets=targets), self.assertRaises(ValueError):
                    observer_options(path,state_db=root/'holds')
