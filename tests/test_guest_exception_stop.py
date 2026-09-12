import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from guest_exception_stop import GuestExceptionStop

BASE = 0xfffffe00070ad000


def step(pc, **extra):
    return dict(pc=pc, kind='instruction-step', **extra)


class GuestExceptionStopTests(unittest.TestCase):
    def test_half_open_vector_boundaries(self):
        for pc, hit in [(BASE-4, False), (BASE, True), (BASE+2044, True), (BASE+2048, False)]:
            with self.subTest(pc=pc):
                result = GuestExceptionStop().observe([step(pc)], start_index=0, vbar=BASE)
                self.assertEqual(result is not None, hit)

    def test_cross_batch_overlap_first_hit_and_context(self):
        detector = GuestExceptionStop(2)
        events = [step(0x100), step(0x104), step(BASE+0x200, regs=[17]), step(BASE+0x204)]
        self.assertIsNone(detector.observe(events[:2], start_index=0, vbar=BASE))
        hit = detector.observe(events, start_index=0, vbar=BASE)
        self.assertEqual(hit['trace_index'], 2)
        self.assertEqual(hit['event']['regs'], [17])
        self.assertEqual(hit['recorded_events_after_hit'], 1)
        events[2]['regs'][0] = 99
        hit['event']['regs'][0] = 88
        self.assertEqual(detector.observe(events, start_index=0, vbar=BASE)['event']['regs'], [17])
        self.assertEqual(detector.next_index, 4)

    def test_rolling_window_preserves_global_index(self):
        detector = GuestExceptionStop(2)
        detector.observe([step(1), step(2), step(3)], start_index=0, vbar=BASE)
        hit = detector.observe([step(3), step(4), step(BASE)], start_index=2, vbar=BASE)
        self.assertEqual(hit['trace_index'], 4)

    def test_dropped_unseen_events_fail_closed(self):
        detector = GuestExceptionStop(2)
        detector.observe([step(1)], start_index=0, vbar=BASE)
        with self.assertRaisesRegex(ValueError, 'discarded unseen'):
            detector.observe([step(BASE)], start_index=2, vbar=BASE)

    def test_stale_esr_is_not_vector_entry(self):
        detector = GuestExceptionStop()
        self.assertIsNone(detector.observe([step(0x100, esr=0x96000005)], start_index=0, vbar=BASE))

    def test_initial_synthetic_guard_and_zero_vbar(self):
        detector = GuestExceptionStop()
        self.assertIsNone(detector.observe([dict(pc=BASE, kind='entry-guard')], start_index=0, vbar=BASE))
        self.assertIsNone(detector.observe([step(0)], start_index=1, vbar=0))
        self.assertIsNotNone(detector.observe([step(BASE)], start_index=2, vbar=BASE))

    def test_latest_vbar_used_not_previous_sample(self):
        detector = GuestExceptionStop()
        detector.observe([step(1)], start_index=0, vbar=BASE)
        self.assertIsNone(detector.observe([step(BASE)], start_index=1, vbar=BASE+2048))
        self.assertIsNotNone(detector.observe([step(BASE+2048)], start_index=2, vbar=BASE+2048))

    def test_full_batch_and_callback_bound(self):
        detector = GuestExceptionStop(256)
        hit = detector.observe([step(BASE)] + [step(4)]*256, start_index=0, vbar=BASE)
        self.assertEqual(hit['recorded_events_after_hit'], 256)
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            GuestExceptionStop(256).observe([step(4)]*258, start_index=0, vbar=BASE)

    def test_stop_registers_separate_from_first_event(self):
        detector = GuestExceptionStop()
        detector.observe([step(BASE, esr=0xc8000000)], start_index=0, vbar=BASE)
        registers = {'ESR_EL12': 0x96000005, 'FAR_EL12': 123}
        hit = detector.snapshot_cause(registers)
        registers['FAR_EL12'] = 456
        self.assertEqual(hit['event']['esr'], 0xc8000000)
        self.assertEqual(hit['stop_guest_exception_registers']['FAR_EL12'], 123)
        self.assertIn('not-proven-first-entry', hit['cause_status'])

    def test_invalid_sequence_and_vbar(self):
        detector = GuestExceptionStop()
        with self.assertRaises(ValueError):
            detector.snapshot_cause({})
        with self.assertRaises(ValueError):
            detector.observe([], start_index=0, vbar=BASE+1)
        detector.observe([step(1)], start_index=0, vbar=BASE)
        with self.assertRaisesRegex(ValueError, 'backwards'):
            detector.observe([], start_index=0, vbar=BASE)
