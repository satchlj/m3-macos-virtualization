import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from experiment_store import Catalog
from import_probe_pipeline import extract_verified, register_pipeline
from run_manifest import file_identity


class PipelineImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, entries):
        path = self.root/'transfer.tar.gz'
        with tarfile.open(path, 'w:gz') as tar:
            for name, kind, value in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.REGTYPE:
                    member.size = len(value)
                    tar.addfile(member, io.BytesIO(value))
                else:
                    if kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
                        member.linkname = value
                    tar.addfile(member)
        return path, file_identity(path)

    def test_identity_mismatch_creates_nothing(self):
        path, identity = self.archive([('job/file', tarfile.REGTYPE, b'ok')])
        identity['sha256'] = '0'*64
        dest = self.root/'dest'
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            extract_verified(path, identity, dest)
        self.assertFalse(dest.exists())

    def test_unsafe_archives_leave_no_partial_extraction(self):
        cases = [
            [('job/../escape', tarfile.REGTYPE, b'x')],
            [('/absolute', tarfile.REGTYPE, b'x')],
            [('job/link', tarfile.SYMTYPE, '/tmp')],
            [('job/link', tarfile.LNKTYPE, 'job/file')],
            [('job/device', tarfile.CHRTYPE, '')],
            [('job/file', tarfile.REGTYPE, b'x')]*2,
            [('job/./file', tarfile.REGTYPE, b'x')],
        ]
        for entries in cases:
            with self.subTest(entries=entries):
                path, identity = self.archive(entries)
                dest = self.root/'dest'
                with self.assertRaises(ValueError):
                    extract_verified(path, identity, dest)
                self.assertFalse(dest.exists())

    def test_expanded_limit_and_existing_destination(self):
        path, identity = self.archive([('job/file', tarfile.REGTYPE, b'12345')])
        dest = self.root/'dest'
        with self.assertRaisesRegex(ValueError, 'byte limit'):
            extract_verified(path, identity, dest, max_bytes=4)
        self.assertFalse(dest.exists())
        dest.mkdir()
        (dest/'keep').write_text('keep')
        with self.assertRaises(FileExistsError):
            extract_verified(path, identity, dest)
        self.assertEqual((dest/'keep').read_text(), 'keep')

    def pipeline_archive(self, status='finished', phase='finished'):
        values = {
            'job/pipeline.json': {'phase': phase, 'ended_at': 'now', 'run_id': 'probe'},
            'job/config.json': {'steps': 10},
            'job/runs/probe/manifest.json': {
                'schema_version': 1, 'run_id': 'probe', 'status': status,
                'ended_at': 'now' if status != 'running' else None,
                'capture': {'checkpoint_events': 0, 'total_events': 0}},
            'job/runs/probe/report.json': {'run_id': 'probe', 'trace': []},
            'job/diagnostics.json': {'far': 123},
            'job/tables/table.bin': None,
        }
        return self.archive([(name, tarfile.REGTYPE, b'raw table' if data is None else json.dumps(data).encode()) for name, data in values.items()])

    def test_terminal_probe_and_separate_attachments_are_idempotent(self):
        path, identity = self.pipeline_archive(status='interrupted', phase='failed')
        root = extract_verified(path, identity, self.root/'dest')
        with Catalog(self.root/'catalog', create=True) as catalog:
            catalog.define('test', {})
            first = register_pipeline(catalog, 'test', root, identity)
            second = register_pipeline(catalog, 'test', root, {**identity, 'path': '/elsewhere'})
            self.assertEqual(first, second)
            self.assertTrue(first['probe_registered'])
            self.assertEqual(len(catalog.list_runs()), 2)
            probe = catalog.get('probe')['record']
            self.assertEqual(set(probe['artifacts']), {'manifest', 'report'})
            supplementary = catalog.get(first['pipeline_record'])['record']
            self.assertEqual(supplementary['provenance']['probe_run_id'], 'probe')
            self.assertIn('pipeline/tables/table.bin', supplementary['artifacts'])
            self.assertIn('pipeline/diagnostics.json', supplementary['artifacts'])
            catalog.verify()

    def test_unfinalized_probe_is_preserved_without_terminal_registration(self):
        path, identity = self.pipeline_archive(status='running', phase='failed')
        root = extract_verified(path, identity, self.root/'dest')
        with Catalog(self.root/'catalog', create=True) as catalog:
            catalog.define('test', {})
            result = register_pipeline(catalog, 'test', root, identity)
            self.assertFalse(result['probe_registered'])
            self.assertTrue((root/'runs/probe/manifest.json').exists())
            self.assertEqual(len(catalog.list_runs()), 1)

    def test_unfinalized_pipeline_and_identity_mismatch_rejected(self):
        path, identity = self.pipeline_archive(phase='probe')
        root = extract_verified(path, identity, self.root/'dest')
        with Catalog(self.root/'catalog', create=True) as catalog:
            catalog.define('test', {})
            with self.assertRaisesRegex(ValueError, 'not finalized'):
                register_pipeline(catalog, 'test', root, identity)
            (root/'pipeline.json').write_text(json.dumps({'phase': 'failed', 'ended_at': 'now', 'run_id': 'other'}))
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                register_pipeline(catalog, 'test', root, identity)
            self.assertEqual(catalog.list_runs(), [])


if __name__ == '__main__':
    unittest.main()
