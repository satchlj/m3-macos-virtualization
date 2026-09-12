import sys
import json
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from extract_xnu_console import console_bytes, recover_console, DISPATCH_READ_PC
from run_manifest import file_identity


class ConsoleTests(unittest.TestCase):
    @staticmethod
    def event(char):
        regs = [0] * 32
        regs[0], regs[16] = char, 0x2d
        return dict(pc=DISPATCH_READ_PC, kind='real-guarded-redirect',
                    register='ESR_GL1', read=True, regs=regs)

    def test_extract_only_observed_console_dispatches(self):
        a, b = self.event(65), self.event(10)
        wrong_site = dict(a, pc=DISPATCH_READ_PC+4)
        wrong_kind = dict(a, kind='handoff-step')
        invalid = self.event(256)
        self.assertEqual(bytes(console_bytes([a, wrong_site, wrong_kind, invalid, b])), b'A\n')

    def test_complete_report_fallback_including_empty_console(self):
        with tempfile.TemporaryDirectory() as td:
            report = dict(run_id='run-a', trace=[self.event(65)],
                          trace_start_index=0, trace_total_events=1)
            data, evidence = recover_console(report, Path(td)/'runs')
            self.assertEqual(data, b'A')
            self.assertEqual(evidence['source'], 'complete-report-trace')
            report.update(trace=[], trace_total_events=0)
            self.assertEqual(recover_console(report, Path(td)/'runs')[0], b'')

    def test_rolling_report_without_archive_is_explicit_error(self):
        with tempfile.TemporaryDirectory() as td:
            report = dict(run_id='run-a', trace=[], trace_start_index=2,
                          trace_total_events=2)
            with self.assertRaisesRegex(ValueError, 'archive is unavailable'):
                recover_console(report, Path(td)/'runs')

    def test_verified_archive_and_count_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td)/'runs'/'run-a'
            bundle.mkdir(parents=True)
            archive = bundle/'events.jsonl'
            archive.write_text(json.dumps({'index': 0, 'event': self.event(66)})+'\n')
            identity = file_identity(archive)
            report = dict(run_id='run-a', trace=[self.event(66)],
                          trace_start_index=0, trace_total_events=1)
            (bundle/'report.json').write_text(json.dumps(report))
            manifest = dict(run_id='run-a', status='finished', ended_at='now',
                capture=dict(event_archive='events.jsonl', event_archive_identity=identity,
                             complete=True))
            (bundle/'manifest.json').write_text(json.dumps(manifest))
            data, evidence = recover_console(report, Path(td)/'runs')
            self.assertEqual(data, b'B')
            self.assertEqual(evidence['source'], 'verified-event-archive')
            report['trace_total_events'] = 2
            with self.assertRaisesRegex(ValueError, 'count differs'):
                recover_console(report, Path(td)/'runs')

    def test_archive_identity_failure_is_not_silent(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = Path(td)/'runs'/'run-a'
            bundle.mkdir(parents=True)
            archive = bundle/'events.jsonl'
            archive.write_text(json.dumps({'index': 0, 'event': self.event(67)})+'\n')
            report = dict(run_id='run-a', trace=[], trace_start_index=1,
                          trace_total_events=1)
            (bundle/'report.json').write_text(json.dumps(report))
            manifest = dict(run_id='run-a', status='finished', ended_at='now',
                capture=dict(event_archive='events.jsonl',
                             event_archive_identity=dict(sha256='bad', size=1), complete=True))
            (bundle/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                recover_console(report, Path(td)/'runs')
