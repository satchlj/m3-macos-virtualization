from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from trace_exception_window import exception_window


class ExceptionWindowTests(unittest.TestCase):
    def test_first_vector_bounded_context_and_complete_count(self):
        pcs = [1, 2, 3, 0x4200, 7, 0x4000, 9, 10]
        result = exception_window(({'pc': pc} for pc in pcs), 0x4000, before=2, after=2)
        self.assertEqual(result['first_vector_index'], 3)
        self.assertEqual([r['index'] for r in result['context']], [1, 2, 3, 4, 5])
        self.assertEqual(result['total_events'], 8)

    def test_no_vector_and_boundary(self):
        result = exception_window(iter([{'pc': 0x4800}, {}]), 0x4000)
        self.assertIsNone(result['first_vector_index'])
        self.assertEqual(result['context'], [])
        with self.assertRaises(ValueError):
            exception_window([], 0x4001)
