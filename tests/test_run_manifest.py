"""Attempt provenance, atomic checkpoints, and probe failure paths without USB."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from run_manifest import RunCapture, atomic_json, git_identity, append_event
import sptm_entry_probe as probe
from experiment_store import Catalog


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Test', '-c',
                        'user.email=test@example.invalid', 'commit', '-q', '--allow-empty', '-m', 'init'], check=True)

    def capture(self):
        return RunCapture(self.root/'runs', self.root/'report.json',
                          {'execute': False, 'device': None}, repo=self.root,
                          checkout=self.root, command=['probe', '--steps', '128'])

    def test_git_dirty_and_untracked(self):
        clean = git_identity(self.root)
        self.assertFalse(clean['dirty'])
        (self.root/'source.py').write_text('one')
        first = git_identity(self.root)
        (self.root/'source.py').write_text('two')
        second = git_identity(self.root)
        self.assertTrue(first['dirty'])
        self.assertNotEqual(first['untracked'][0]['sha256'], second['untracked'][0]['sha256'])
        subprocess.run(['git', '-C', str(self.root), 'add', 'source.py'], check=True)
        self.assertNotEqual(git_identity(self.root)['tracked_diff_sha256'], clean['tracked_diff_sha256'])

    def test_exact_runtime_input_is_retained_without_overwrite_or_path_escape(self):
        capture = self.capture()
        data = b'original ADT bytes\0'
        identity = capture.save_input('host.adt', data)
        self.assertEqual((capture.root/'inputs/host.adt').read_bytes(), data)
        self.assertEqual(identity['size'], len(data))
        with self.assertRaises(FileExistsError):
            capture.save_input('host.adt', b'changed')
        with self.assertRaises(ValueError):
            capture.save_input('../escaped', data)

    def test_atomic_write_failure_retains_previous(self):
        path = self.root/'report.json'
        atomic_json(path, {'trace': [1]})
        with patch('run_manifest.os.replace', side_effect=OSError('disk')):
            with self.assertRaises(OSError):
                atomic_json(path, {'trace': [2]})
        self.assertEqual(json.loads(path.read_text()), {'trace': [1]})

    def test_attempt_identity_and_ingestion(self):
        capture = self.capture()
        report = dict(trace=[], hardware_executed=False, guest_boot_verified=False)
        capture.finish(report)
        manifest = json.loads((capture.root/'manifest.json').read_text())
        self.assertEqual(manifest['backend'], 'offline-layout')
        self.assertIsNone(manifest['target']['firmware_version'])
        self.assertEqual(manifest['runtime_identity']['verification'], 'not-attempted')
        self.assertNotEqual(self.capture().run_id, capture.run_id)
        with Catalog(self.root/'catalog', create=True) as catalog:
            catalog.define('test', {'backend': 'offline-layout'})
            run = catalog.ingest('test', capture.root/'report.json', run_id=capture.run_id,
                                 provenance=manifest, artifacts={'manifest': capture.root/'manifest.json'})
            self.assertEqual(catalog.get(run)['record']['provenance'], manifest)
            self.assertEqual(catalog.verify()['verified_objects'], 2)

    def test_partial_interrupted_capture(self):
        capture = self.capture()
        report = {'trace': [{'kind': 'step'}], 'hardware_executed': True}
        capture.save(report)
        capture.finish(report, KeyboardInterrupt())
        manifest = json.loads((capture.root/'manifest.json').read_text())
        self.assertEqual(manifest['status'], 'interrupted')
        self.assertFalse(manifest['capture']['complete'])
        self.assertEqual(manifest['capture']['checkpoint_events'], 1)

    def test_probe_offline_and_failure_finalization(self):
        argv = ['probe', '--checkout', str(self.root), '--payload', str(self.root),
                '--report', str(self.root/'report.json')]
        for error in (None, ValueError('invalid payload'), KeyboardInterrupt()):
            with self.subTest(error=error), patch.object(sys, 'argv', argv), \
                 patch.object(probe, 'plan', side_effect=error, return_value={'images': {}}):
                previous = signal.getsignal(signal.SIGTERM)
                if error:
                    with self.assertRaises(type(error)):
                        probe.main()
                else:
                    probe.main()
                self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
        manifests = [json.loads(p.read_text()) for p in (self.root/'report.json.runs').glob('*/manifest.json')]
        self.assertEqual({m['status'] for m in manifests}, {'finished', 'failed', 'interrupted'})
        self.assertTrue(all(m['outcome']['hardware_executed'] is False for m in manifests))

    def test_windowed_trace_retains_full_ordered_journal(self):
        capture = self.capture()
        report = {'trace': [], 'trace_window': 8, 'run_id': capture.run_id}
        for index in range(25):
            append_event(report, {'pc': index})
            if index % 4 == 0:
                capture.save(report)
        capture.finish(report)
        events = [json.loads(line) for line in (capture.root/'events.jsonl').read_text().splitlines()]
        self.assertEqual([e['index'] for e in events], list(range(25)))
        self.assertEqual([e['event']['pc'] for e in events], list(range(25)))
        self.assertEqual(report['trace_start_index'], 17)
        self.assertEqual(len(report['trace']), 8)
        self.assertEqual(capture.manifest['capture']['journal_events'], 25)
        capture.save(report)
        self.assertEqual(len((capture.root/'events.jsonl').read_text().splitlines()), 25)

    def test_trace_diff_rejects_misaligned_windows(self):
        from trace_diff import compare_reports
        with self.assertRaisesRegex(ValueError, 'different logical indices'):
            compare_reports({'trace': [{}], 'trace_start_index': 2}, {'trace': [{}]})

    def test_journal_detects_evicted_unsaved_events(self):
        capture = self.capture()
        report = {'trace': [], 'trace_window': 2}
        for index in range(3): append_event(report, {'pc': index})
        with self.assertRaisesRegex(ValueError, 'checkpoint gap'):
            capture.save(report)

    def test_sigterm_is_recorded(self):
        argv = ['probe', '--checkout', str(self.root), '--payload', str(self.root),
                '--report', str(self.root/'report.json')]
        def terminate(*args):
            signal.raise_signal(signal.SIGTERM)
        with patch.object(sys, 'argv', argv), patch.object(probe, 'plan', side_effect=terminate):
            with self.assertRaises(KeyboardInterrupt):
                probe.main()
        manifest = json.loads(next((self.root/'report.json.runs').glob('*/manifest.json')).read_text())
        self.assertEqual(manifest['status'], 'interrupted')
        self.assertFalse(manifest['capture']['complete'])


if __name__ == '__main__':
    unittest.main()
