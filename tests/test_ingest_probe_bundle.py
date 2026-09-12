import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from experiment_store import Catalog, digest_file
from ingest_probe_bundle import ingest_bundle


class BundleIngestionTests(unittest.TestCase):
    def test_captured_inputs_are_verified_and_registered(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'inputs').mkdir()
            path=root/'inputs/host.adt';path.write_bytes(b'original')
            digest,size=digest_file(path)
            manifest=dict(schema_version=1,run_id='attempt',status='finished',ended_at='recorded',
                capture={'checkpoint_events':0,'total_events':0},
                captured_inputs={'host.adt':{'sha256':digest,'size':size}})
            (root/'manifest.json').write_text(json.dumps(manifest))
            (root/'report.json').write_text(json.dumps({'run_id':'attempt','trace':[]}))
            with Catalog(root/'store',create=True) as c:
                c.define('test',{})
                ingest_bundle(c,'test',root)
                self.assertIn('input/host.adt',c.get('attempt')['record']['artifacts'])
                path.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError,'Captured input identity'):
                    ingest_bundle(c,'test',root)

    def test_terminal_bundle_retry_and_inconsistent_pairs(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            report={'run_id':'attempt','trace':[]}
            manifest={'schema_version':1,'run_id':'attempt','status':'interrupted','ended_at':'recorded','capture':{'checkpoint_events':0,'total_events':0}}
            (root/'report.json').write_text(json.dumps(report))
            with Catalog(root/'store',create=True) as c:
                c.define('test',{})
                for key,value in [('run_id','wrong'),('status','running'),('ended_at',None),('capture',{'checkpoint_events':1})]:
                    (root/'manifest.json').write_text(json.dumps({**manifest,key:value}))
                    with self.assertRaises(ValueError):ingest_bundle(c,'test',root)
                    self.assertEqual(c.list_runs(),[])
                (root/'manifest.json').write_text(json.dumps(manifest))
                self.assertEqual(ingest_bundle(c,'test',root),'attempt')
                self.assertEqual(ingest_bundle(c,'test',root),'attempt')
                self.assertEqual(len(c.list_runs()),1)
