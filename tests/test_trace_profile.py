import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from trace_profile import profile


class TraceProfileTests(unittest.TestCase):
    def test_frequency_and_discovery_without_loop_inference(self):
        result = profile(iter([
            dict(pc=4, regs=[1], kind='instruction-step'),
            dict(pc=8, regs=[2], kind='instruction-step'),
            dict(pc=4, regs=[3], kind='instruction-step'),
            dict(kind='terminal'),
        ]), window=2)
        self.assertEqual(result['total_events'], 4)
        self.assertEqual(result['unique_pcs'], 2)
        hot = result['hottest_pcs'][0]
        self.assertEqual((hot['pc'], hot['count'], hot['first_index'], hot['last_index']), (4, 2, 0, 2))
        self.assertEqual(hot['register_endpoint_changes'], [dict(register=0, first=1, last=3)])
        self.assertEqual([w['new_pcs'] for w in result['discovery_windows']], [2, 0])
    def test_refuses_silent_unique_pc_truncation(self):
        with self.assertRaises(ValueError):
            profile(iter([dict(pc=4), dict(pc=8)]), max_pcs=1)
    def test_empty_and_partial_window(self):
        self.assertEqual(profile(iter([]))['total_events'], 0)
        self.assertEqual(profile(iter([dict(pc=4)]))['discovery_windows'][0]['end_index'], 1)
