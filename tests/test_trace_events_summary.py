import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import trace_events_summary
from trace_events_summary import MAX_CONTEXT, summarize_bundle, summarize_events
from run_manifest import atomic_json, file_identity


def step(pc):
    return {'kind': 'instruction-step', 'pc': pc, 'regs': [0]*32}


EVENTS = [
    step(0x1000), step(0x1004),
    {'kind': 'probe-control', 'pc': 0x1008, 'register': 'HCR_EL2', 'read': True, 'value': 7, 'esr': 1},
    step(0x100c), step(0x1010), step(0x1014),
    {'kind': 'emulated-zero-loop', 'pc': 0x1018, 'effects': {'skipped': 4}},
    {'kind': 'guest-debug', 'pc': 0x101c, 'sysreg': {'name': 'MDSCR_EL1'}, 'unsupported_detail': 'nonzero write'},
    step(0x1020),
    {'pc': 0x1024},
    step(0x1028), step(0x102c),
]


def write_bundle(root, events, *, status='finished', total=None, identity=None):
    root.mkdir(parents=True, exist_ok=True)
    with (root/'events.jsonl').open('w') as journal:
        for index, event in enumerate(events):
            journal.write(json.dumps({'index': index, 'event': event}, separators=(',', ':'))+'\n')
    actual = file_identity(root/'events.jsonl')
    count = len(events) if total is None else total
    atomic_json(root/'manifest.json', {
        'schema_version': 1, 'run_id': 'run', 'status': status, 'ended_at': 'now' if status != 'running' else None,
        'capture': {'complete': True, 'checkpoint_events': min(4, count), 'total_events': count,
                    'event_archive': 'events.jsonl', 'event_archive_identity': identity or actual}})
    atomic_json(root/'report.json', {'run_id': 'run', 'trace': events[-4:], 'trace_window': 4,
                                     'trace_start_index': max(0, count-4), 'trace_total_events': count})
    return actual


class TraceEventsSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name)/'run'

    def test_normal_summary(self):
        write_bundle(self.bundle, EVENTS)
        result = summarize_bundle(self.bundle)
        self.assertEqual(result['run_id'], 'run')
        self.assertEqual(result['total_events'], 12)
        self.assertEqual(result['selected'], {'first_index': 0, 'last_index': 11, 'count': 12})
        self.assertEqual(result['kind_counts'], {'emulated-zero-loop': 1, 'guest-debug': 1,
                                                 'instruction-step': 8, 'probe-control': 1, 'unclassified': 1})
        rows = result['non_step_events']
        self.assertEqual([r['index'] for r in rows], [2, 6, 7, 9])
        self.assertEqual([r['steps_since_previous'] for r in rows], [2, 3, 0, 1])
        self.assertEqual(result['trailing_steps'], 2)
        self.assertEqual(rows[0], {'index': 2, 'kind': 'probe-control', 'pc': 0x1008, 'steps_since_previous': 2,
                                   'register': 'HCR_EL2', 'read': True, 'value': 7})
        self.assertEqual(rows[1]['effects'], {'skipped': 4})
        self.assertEqual(rows[2]['unsupported_detail'], 'nonzero write')
        self.assertEqual(rows[3], {'index': 9, 'kind': 'unclassified', 'pc': 0x1024, 'steps_since_previous': 1})
        self.assertNotIn('context', rows[0])
        self.assertEqual((result['non_step_first_index'], result['non_step_last_index'], result['non_step_count']), (2, 9, 4))
        self.assertTrue(result['capture_complete'])

    def test_identity_mismatch_rejected(self):
        write_bundle(self.bundle, EVENTS, identity={'sha256': '0'*64, 'size': 1})
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            summarize_bundle(self.bundle)
        write_bundle(self.bundle, EVENTS, status='running')
        with self.assertRaisesRegex(ValueError, 'finalized'):
            summarize_bundle(self.bundle)

    def test_count_mismatch_rejected(self):
        write_bundle(self.bundle, EVENTS, total=len(EVENTS)+1)
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            summarize_bundle(self.bundle)

    def test_after_restricts_selection(self):
        write_bundle(self.bundle, EVENTS)
        result = summarize_bundle(self.bundle, after=6)
        self.assertEqual(result['total_events'], 12)
        self.assertEqual(result['selected'], {'first_index': 6, 'last_index': 11, 'count': 6})
        self.assertEqual([r['index'] for r in result['non_step_events']], [6, 7, 9])
        self.assertEqual(result['non_step_events'][0]['steps_since_previous'], 0)
        self.assertEqual(result['kind_counts']['instruction-step'], 3)
        for after in (-1, 12, 40):
            with self.subTest(after=after), self.assertRaises(ValueError):
                summarize_bundle(self.bundle, after=after)

    def test_context_is_bounded_and_resets_between_events(self):
        write_bundle(self.bundle, EVENTS)
        result = summarize_bundle(self.bundle, context=2)
        rows = result['non_step_events']
        self.assertEqual([r['index'] for r in rows[0]['context']], [0, 1])
        self.assertEqual([r['index'] for r in rows[1]['context']], [4, 5])
        self.assertEqual(rows[2]['context'], [])
        self.assertEqual([r['index'] for r in rows[3]['context']], [8])
        self.assertEqual(rows[0]['context'][0]['event'], EVENTS[0])
        after = summarize_bundle(self.bundle, context=2, after=1)['non_step_events']
        self.assertEqual([r['index'] for r in after[0]['context']], [1])
        for context in (-1, MAX_CONTEXT+1):
            with self.subTest(context=context), self.assertRaises(ValueError):
                summarize_bundle(self.bundle, context=context)
        with self.assertRaises(ValueError):
            summarize_events(iter(EVENTS), context='2')

    def test_streaming_generator_and_empty_archive(self):
        result = summarize_events(iter([]))
        self.assertEqual((result['total_events'], result['non_step_events'], result['selected']['count']), (0, [], 0))
        result = summarize_events(step(1) for _ in range(500))
        self.assertEqual(result['kind_counts'], {'instruction-step': 500})
        self.assertEqual(result['trailing_steps'], 500)

    def test_cli_writes_output_and_prints_count(self):
        write_bundle(self.bundle, EVENTS)
        output = self.bundle.parent/'summary.json'
        argv = ['trace_events_summary.py', str(self.bundle), '--output', str(output), '--after', '2', '--context', '1']
        printed = io.StringIO()
        with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(printed):
            trace_events_summary.main()
        self.assertEqual(printed.getvalue().count('\n'), 1)
        self.assertIn('Non-step events: 4 of 10 selected (12 total)', printed.getvalue())
        saved = json.loads(output.read_text())
        self.assertEqual(saved['after'], 2)
        self.assertEqual(saved['context_steps'], 1)
        self.assertEqual(saved['non_step_events'][0]['context'], [])


if __name__ == '__main__':
    unittest.main()
