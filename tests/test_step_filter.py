import ctypes as C
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class Filter(C.Structure):
    _fields_ = [
        ('range_start', C.c_uint64 * 2),
        ('range_end', C.c_uint64 * 2),
        ('terminal_pc', C.c_uint64),
        ('expected_first_pc', C.c_uint64),
        ('max_steps', C.c_uint64),
        ('steps', C.c_uint64),
        ('first_pc', C.c_uint64),
        ('previous_pc', C.c_uint64),
        ('last_pc', C.c_uint64),
        ('range_hits', C.c_uint64 * 2),
        ('range_switches', C.c_uint64),
        ('last_range', C.c_uint8),
        ('status', C.c_int),
    ]


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'),
                     'Requires native source checkout')
class NativeStepFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        checkout = Path(os.environ['VEL2_CHECKOUT'])
        output = Path(cls.temp.name) / 'step-filter.so'
        subprocess.run([
            shutil.which('cc'), '-shared', '-fPIC', '-Wall', '-Werror',
            '-I', str(checkout / 'src'),
            str(checkout / 'src' / 'vel2_step_filter.c'), '-o', str(output),
        ], check=True)
        cls.lib = C.CDLL(str(output))
        cls.lib.vel2_step_filter_configure.argtypes = [
            C.POINTER(Filter), *(C.c_uint64 for _ in range(6))]
        cls.lib.vel2_step_filter_handle.argtypes = [
            C.POINTER(Filter), C.c_uint64, C.c_bool]
        cls.lib.vel2_step_filter_handle.restype = C.c_int
        cls.lib.vel2_step_filter_expect.argtypes = [
            C.POINTER(Filter), C.c_uint64]
        cls.lib.vel2_step_filter_valid_context.argtypes = [
            C.c_uint32, C.c_uint64]
        cls.lib.vel2_step_filter_valid_context.restype = C.c_bool

    def configure(self, maximum=8):
        state = Filter()
        self.assertEqual(self.lib.vel2_step_filter_configure(
            C.byref(state), 0x1000, 0x1100, 0x2000, 0x2100,
            0x3000, maximum), 0)
        self.assertEqual(self.lib.vel2_step_filter_expect(
            C.byref(state), 0x1004), 0)
        return state

    def test_two_ranges_stop_exactly_at_terminal(self):
        state = self.configure()
        for pc in (0x1004, 0x1008, 0x2000, 0x2004):
            self.assertEqual(self.lib.vel2_step_filter_handle(
                C.byref(state), pc, True), 1)
        self.assertEqual(self.lib.vel2_step_filter_handle(
            C.byref(state), 0x3000, True), 2)
        self.assertEqual(state.status, 3)
        self.assertEqual(state.steps, 4)
        self.assertEqual(state.first_pc, 0x1004)
        self.assertEqual(state.previous_pc, 0x2004)
        self.assertEqual(state.last_pc, 0x3000)
        self.assertEqual(list(state.range_hits), [2, 2])
        self.assertEqual(state.range_switches, 1)

    def test_outside_limit_and_bad_context_fail_closed(self):
        state = self.configure()
        self.assertEqual(self.lib.vel2_step_filter_handle(
            C.byref(state), 0x1004, False), 2)
        self.assertEqual(state.status, 6)
        state = self.configure()
        self.assertEqual(self.lib.vel2_step_filter_handle(
            C.byref(state), 0x1004, True), 1)
        self.assertEqual(self.lib.vel2_step_filter_handle(
            C.byref(state), 0x4000, True), 2)
        self.assertEqual(state.status, 4)
        state = self.configure(maximum=1)
        self.assertEqual(self.lib.vel2_step_filter_handle(
            C.byref(state), 0x1004, True), 1)
        self.assertEqual(self.lib.vel2_step_filter_handle(
            C.byref(state), 0x1004, True), 2)
        self.assertEqual(state.status, 5)

    def test_first_pc_mismatch_fails_before_range_is_consumed(self):
        state = self.configure()
        self.assertEqual(self.lib.vel2_step_filter_handle(
            C.byref(state), 0x1008, True), 2)
        self.assertEqual(state.status, 2)
        self.assertEqual(state.steps, 0)

    def test_configuration_rejects_unbounded_or_unaligned_ranges(self):
        state = Filter()
        bad = (
            (0x1000, 0x1000, 0x2000, 0x2100, 0x3000, 1),
            (0x1001, 0x1100, 0x2000, 0x2100, 0x3000, 1),
            (0x1000, 0x1100, 0x2000, 0x2100, 0x3000, (1 << 24) + 1),
        )
        for values in bad:
            self.assertEqual(self.lib.vel2_step_filter_configure(
                C.byref(state), *values), -1)
            self.assertEqual(state.status, 0)

    def test_context_accepts_guarded_txm_and_sptm_modes_only(self):
        valid = self.lib.vel2_step_filter_valid_context
        for mode in (0, 4, 5):
            self.assertTrue(valid(0x32, 0x800013c0 | mode))
        for mode in (1, 2, 3, 6, 7, 8, 15):
            self.assertFalse(valid(0x32, mode))
        self.assertFalse(valid(0x16, 0))
