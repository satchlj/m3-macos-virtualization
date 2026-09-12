import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from classify_xnu_map_progress import MAP_SERVICE_PC, classify_bundle
from run_manifest import atomic_json, file_identity


def map_event(va, pte, flags=0x603, root=0x10015060000):
    regs = [0] * 32
    regs[0], regs[1], regs[2], regs[16] = root, va, pte | flags, 2
    return {'kind': 'real-guarded-redirect', 'pc': MAP_SERVICE_PC, 'regs': regs}


def write_bundle(root, events, *, status='finished', complete=True):
    root.mkdir(parents=True, exist_ok=True)
    with (root / 'events.jsonl').open('w') as stream:
        for index, event in enumerate(events):
            stream.write(json.dumps({'index': index, 'event': event}, separators=(',', ':')) + '\n')
    identity = file_identity(root / 'events.jsonl')
    atomic_json(root / 'manifest.json', {
        'run_id': 'run', 'status': status, 'ended_at': 'now',
        'capture': {'complete': complete, 'event_archive': 'events.jsonl',
                    'event_archive_identity': identity}})
    atomic_json(root / 'report.json', {
        'run_id': 'run', 'trace_total_events': len(events), 'stop_reason': 'hang',
        'guest_returned': True, 'proxy_alive_after_exit': True,
        'watchdog': {'kicked': True, 'guest_returned': True},
        'xnu_pperm_guest_window': {'started_windows': 2, 'completed_windows': 2},
        'xnu_pperm_guest_window_cleanup': {'attempted': False}})
    return identity


class MapProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name) / 'run'

    def test_extracts_progress_without_calling_watchdog_a_loop(self):
        base_va, base_pte = 0xfffffe4f6a100000, 0x460010017c84000
        events = [map_event(base_va + i * 0x4000, base_pte + i * 0x4000) for i in range(5)]
        events += [map_event(base_va + 0x40000, base_pte + 0x80000),
                   map_event(base_va + 0x44000, base_pte + 0x84000),
                   {'kind': 'hang-budget', 'pc': 0xfffffe00070efc28}]
        write_bundle(self.bundle, events)
        result = classify_bundle(self.bundle)
        maps = result['maps']
        self.assertEqual((maps['total_calls'], maps['unique_tuples']), (7, 7))
        self.assertEqual(maps['events_after_last_map'], 1)
        self.assertEqual(maps['terminal_plus_page_segment']['count'], 2)
        self.assertEqual(maps['terminal_va_page_segment']['count'], 2)
        self.assertEqual(maps['fixed_delta_segments'][0]['count'], 5)
        self.assertTrue(result['interpretation']['terminal_progress_observed'])
        self.assertEqual(result['interpretation']['loop_classification'], 'not-demonstrated')
        self.assertEqual(result['outcome']['final_event']['kind'], 'hang-budget')

    def test_terminal_va_progress_survives_allocator_discontinuity(self):
        vas = [0x10000 + i * 0x4000 for i in range(5)]
        ptes = [0x50000, 0x54000, 0x58000, 0x40000, 0x44000]
        write_bundle(self.bundle, [map_event(va, pte) for va, pte in zip(vas, ptes)])
        result = classify_bundle(self.bundle)
        self.assertEqual(result['maps']['terminal_plus_page_segment']['count'], 2)
        self.assertEqual(result['maps']['terminal_va_page_segment']['count'], 5)
        self.assertEqual(result['maps']['terminal_va_page_segment']['pte_deltas'],
                         [0x4000, 0x4000, -0x18000, 0x4000])
        self.assertTrue(result['interpretation']['terminal_progress_observed'])

    def test_reports_repeated_tuples_but_does_not_infer_a_cycle(self):
        row = map_event(0x10000, 0x20000)
        write_bundle(self.bundle, [row, row, row, {'kind': 'hang-budget', 'pc': MAP_SERVICE_PC}])
        result = classify_bundle(self.bundle, minimum_segment=2)
        self.assertEqual(result['maps']['unique_tuples'], 1)
        self.assertEqual(result['maps']['repeated_tuples'], 1)
        self.assertEqual(result['maps']['maximum_tuple_repetitions'], 3)
        self.assertEqual(result['interpretation']['loop_classification'], 'not-demonstrated')

    def test_rejects_nonfinal_capture_and_bad_index(self):
        write_bundle(self.bundle, [map_event(0x10000, 0x20000)], complete=False)
        with self.assertRaisesRegex(ValueError, 'finished, complete'):
            classify_bundle(self.bundle)
        write_bundle(self.bundle, [map_event(0x10000, 0x20000)])
        text = (self.bundle / 'events.jsonl').read_text().replace('"index":0', '"index":1')
        (self.bundle / 'events.jsonl').write_text(text)
        identity = file_identity(self.bundle / 'events.jsonl')
        manifest = json.loads((self.bundle / 'manifest.json').read_text())
        manifest['capture']['event_archive_identity'] = identity
        atomic_json(self.bundle / 'manifest.json', manifest)
        with self.assertRaisesRegex(ValueError, 'noncontiguous'):
            classify_bundle(self.bundle)

    def test_rejects_invalid_segment_bound(self):
        write_bundle(self.bundle, [map_event(0x10000, 0x20000)])
        for value in (1, True, 2.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                classify_bundle(self.bundle, minimum_segment=value)


if __name__ == '__main__':
    unittest.main()
