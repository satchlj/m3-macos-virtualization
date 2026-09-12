import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import fetch_pipeline_archive
from fetch_pipeline_archive import fetch_and_import, parse_remote_spec
from experiment_store import Catalog
from run_manifest import atomic_json, file_identity

REMOTE = 'research@host.example:Projects/m3-tahoe-integration/artifacts/runs/X/attempt.tar.gz'


def write_pipeline_archive(path, status='finished', phase='finished'):
    """Minimal closed pipeline attempt, mirroring the importer test fixture."""
    values = {
        'job/pipeline.json': {'phase': phase, 'ended_at': 'now', 'run_id': 'probe'},
        'job/config.json': {'steps': 10},
        'job/runs/probe/manifest.json': {
            'schema_version': 1, 'run_id': 'probe', 'status': status, 'ended_at': 'now',
            'capture': {'checkpoint_events': 0, 'total_events': 0}},
        'job/runs/probe/report.json': {'run_id': 'probe', 'trace': []},
        'job/diagnostics.json': {'far': 123},
    }
    with tarfile.open(path, 'w:gz') as tar:
        for name, data in values.items():
            payload = json.dumps(data).encode()
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))
    return file_identity(path)


class FetchPipelineArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote_root = self.root/'remote'
        self.remote_archive = self.remote_root/'Projects/m3-tahoe-integration/artifacts/runs/X/attempt.tar.gz'
        self.remote_archive.parent.mkdir(parents=True)
        self.identity = write_pipeline_archive(self.remote_archive)
        atomic_json(self.remote_archive.with_name('attempt.tar.gz.identity.json'), self.identity)
        self.archives = self.root/'archives'
        self.store = self.root/'catalog'
        with Catalog(self.store, create=True) as catalog:
            catalog.define('test', {})
        self.calls = []
        patcher = mock.patch.object(fetch_pipeline_archive.subprocess, 'run', self.fake_scp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_scp(self, argv, **kwargs):
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[0], 'scp')
        self.assertTrue(kwargs.get('check'))
        host, remote_path = argv[-2].split(':', 1)
        self.assertEqual(host, 'research@host.example')
        self.calls.append(remote_path)
        source = self.remote_root/remote_path
        if not source.is_file():
            raise subprocess.CalledProcessError(1, argv)
        shutil.copyfile(source, argv[-1])
        return subprocess.CompletedProcess(argv, 0)

    def run_import(self, destination='dest'):
        return fetch_and_import('test', REMOTE, destination=self.root/destination,
                                archives=self.archives, store=self.store)

    def assert_nothing_imported(self, destination='dest'):
        self.assertFalse((self.root/destination).exists())
        with Catalog(self.store) as catalog:
            self.assertEqual(catalog.list_runs(), [])

    def test_happy_path_copies_verifies_and_registers(self):
        result = self.run_import()
        self.assertTrue(result['probe_registered'])
        self.assertTrue(result['transfer']['copied'])
        self.assertEqual(result['transfer']['sha256'], self.identity['sha256'])
        self.assertEqual(self.calls, [self.calls[0], self.calls[0][:-len('.identity.json')]])
        self.assertEqual(file_identity(self.archives/'attempt.tar.gz')['sha256'], self.identity['sha256'])
        self.assertEqual(json.loads((self.archives/'attempt.tar.gz.identity.json').read_text())['sha256'], self.identity['sha256'])
        self.assertEqual(sorted(p.name for p in self.archives.iterdir()), ['attempt.tar.gz', 'attempt.tar.gz.identity.json'])
        receipt = json.loads((self.root/'dest/import-receipt.json').read_text())
        self.assertEqual(receipt['pipeline_record'], 'pipeline:'+self.identity['sha256'])
        self.assertTrue((self.root/'dest/job/runs/probe/manifest.json').exists())
        with Catalog(self.store) as catalog:
            self.assertEqual(len(catalog.list_runs()), 2)
            catalog.verify()

    def test_digest_mismatch_extracts_and_registers_nothing(self):
        atomic_json(self.remote_archive.with_name('attempt.tar.gz.identity.json'), {**self.identity, 'sha256': '0'*64})
        with self.assertRaisesRegex(ValueError, 'does not match its identity sidecar'):
            self.run_import()
        self.assert_nothing_imported()
        self.assertEqual(list(self.archives.iterdir()), [])

    def test_existing_identical_archive_is_reused(self):
        self.archives.mkdir()
        shutil.copyfile(self.remote_archive, self.archives/'attempt.tar.gz')
        result = self.run_import()
        self.assertFalse(result['transfer']['copied'])
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(self.calls[0].endswith('.identity.json'))
        self.assertTrue(result['probe_registered'])
        self.assertTrue((self.archives/'attempt.tar.gz.identity.json').exists())

    def test_existing_different_archive_is_refused(self):
        self.archives.mkdir()
        (self.archives/'attempt.tar.gz').write_bytes(b'not the same bytes')
        with self.assertRaisesRegex(ValueError, 'refusing to overwrite'):
            self.run_import()
        self.assertEqual((self.archives/'attempt.tar.gz').read_bytes(), b'not the same bytes')
        self.assertEqual(self.calls, ['Projects/m3-tahoe-integration/artifacts/runs/X/attempt.tar.gz.identity.json'])
        self.assertFalse((self.archives/'attempt.tar.gz.identity.json').exists())
        self.assert_nothing_imported()

    def test_existing_different_sidecar_is_refused(self):
        self.archives.mkdir()
        atomic_json(self.archives/'attempt.tar.gz.identity.json', {**self.identity, 'size': self.identity['size']+1})
        with self.assertRaisesRegex(ValueError, 'different identity'):
            self.run_import()
        self.assertFalse((self.archives/'attempt.tar.gz').exists())
        self.assert_nothing_imported()

    def test_bad_remote_specs_are_rejected_before_scp(self):
        for spec in ['host.example:archive.tgz', 'host.example:archive.tar.gz; rm -rf /',
                     'host.example:with space.tar.gz', 'host.example archive.tar.gz',
                     'host.example:$(x).tar.gz', 'host.example:a/../b.tar.gz',
                     'host.example:.tar.gz', '-oProxyCommand=x:a.tar.gz',
                     'host.example:', 'archive.tar.gz', 'host`name:a.tar.gz',
                     'host.example:a.tar.gz\n', 'host.example:-a.tar.gz', '', None]:
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    parse_remote_spec(spec)
                with self.assertRaises(ValueError):
                    fetch_and_import('test', spec, destination=self.root/'dest', archives=self.archives, store=self.store)
        self.assertEqual(self.calls, [])
        self.assertEqual(parse_remote_spec(REMOTE), ('research@host.example', 'Projects/m3-tahoe-integration/artifacts/runs/X/attempt.tar.gz', 'attempt.tar.gz'))
        self.assertEqual(parse_remote_spec('host.example:/abs/path/a-1.tar.gz')[1:], ('/abs/path/a-1.tar.gz', 'a-1.tar.gz'))

    def test_existing_destination_and_missing_store_fail_early(self):
        (self.root/'dest').mkdir()
        with self.assertRaises(FileExistsError):
            self.run_import()
        with self.assertRaisesRegex(ValueError, 'Catalog does not exist'):
            fetch_and_import('test', REMOTE, destination=self.root/'other', archives=self.archives, store=self.root/'nowhere')
        self.assertEqual(self.calls, [])

    def test_cli_prints_receipt(self):
        argv = ['fetch_pipeline_archive.py', 'test', REMOTE, '--destination', str(self.root/'dest'),
                '--archives', str(self.archives), '--store', str(self.store)]
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(output):
            fetch_pipeline_archive.main()
        printed = json.loads(output.getvalue())
        self.assertEqual(printed['transfer']['remote'], REMOTE)
        self.assertEqual(printed, json.loads((self.root/'dest/import-receipt.json').read_text()))


if __name__ == '__main__':
    unittest.main()
