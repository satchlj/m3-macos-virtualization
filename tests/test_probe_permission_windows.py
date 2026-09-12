"""Permission windows regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from probe_control_support import ProbeControlFixture
import os
import unittest
from sptm_entry_probe import FC_XNU_PPERM_SITES
from sptm_entry_probe import restore_xnu_pperm_guest_window


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class ProbePermissionWindowTests(ProbeControlFixture, unittest.TestCase):

    def test_xnu_pperm_guest_window_full_callback_sequence(self):
        ns, runtime_entry, original, writable = self._prepare_pperm_window_replay()
        _, after = self._feed_pperm_hvc(ns, runtime_entry, 0)
        self.assertEqual(after.regs[8], original)
        self._feed_pperm_hvc(ns, runtime_entry, 1, writable)
        self.assertEqual(self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12], writable)
        _, after = self._feed_pperm_hvc(ns, runtime_entry, 2)
        self.assertEqual(after.regs[8], writable)
        self.assertTrue(ns['report']['xnu_pperm_guest_window']['memcpy_crossed'])
        self._feed_pperm_hvc(ns, runtime_entry, 3, original)
        self.assertEqual(self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12], original)
        self.assertEqual(ns['xnu_pperm_state'], {
            'previous': original, 'step': 4, 'window_type': None,
            'modified': False,
            'started': 1, 'completed': 1})
        self.assertEqual([row['index2_nibble'] for row in
                          ns['report']['xnu_pperm_guest_window']['sequence']],
                         [0xa, 0xb, 0xb, 0xa])
        self.assertTrue(all(reply == int(self.endpoint.EXC_RET.HANDLED)
                            for reply in self.endpoint.replies[-4:]))

    def test_xnu_pperm_atomic_window_full_callback_sequence(self):
        ns, runtime_entry, original, writable = self._prepare_pperm_window_replay()
        for index, value in ((4, 0), (5, writable), (6, 0), (7, original)):
            self._feed_pperm_hvc(ns, runtime_entry, index, value)
        pperm = ns['report']['xnu_pperm_guest_window']
        self.assertTrue(pperm['atomic_crossed'])
        self.assertEqual(pperm['atomic_crossed_windows'], 1)
        self.assertEqual(pperm['memcpy_crossed_windows'], 0)
        self.assertEqual([row['window_type'] for row in pperm['sequence']],
                         ['atomic'] * 4)
        self.assertEqual(ns['xnu_pperm_state']['completed'], 1)
        self.assertFalse(ns['xnu_pperm_state']['modified'])

    def test_xnu_pperm_two_window_families_are_sequential(self):
        ns, runtime_entry, original, writable = self._prepare_pperm_window_replay()
        ns['a'].xnu_pperm_guest_window_limit = 2
        for index, value in ((0, 0), (1, writable), (2, 0), (3, original),
                             (4, 0), (5, writable), (6, 0), (7, original)):
            self._feed_pperm_hvc(ns, runtime_entry, index, value)
        pperm = ns['report']['xnu_pperm_guest_window']
        self.assertEqual((pperm['started_windows'], pperm['completed_windows']),
                         (2, 2))
        self.assertEqual(pperm['memcpy_crossed_windows'], 1)
        self.assertEqual(pperm['atomic_crossed_windows'], 1)

    def test_xnu_pperm_rejects_cross_family_interleaving(self):
        ns, runtime_entry, original, writable = self._prepare_pperm_window_replay()
        self._feed_pperm_hvc(ns, runtime_entry, 0)
        self._feed_pperm_hvc(ns, runtime_entry, 1, writable)
        calls = len(self.endpoint.hardware.calls)
        self._feed_pperm_hvc(ns, runtime_entry, 6)
        self.assertEqual(len(self.endpoint.hardware.calls), calls)
        self.assertTrue(ns['xnu_pperm_state']['modified'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_xnu_pperm_postcopy_read_rejects_other_raw_bit_change(self):
        ns, runtime_entry, original, writable = self._prepare_pperm_window_replay()
        self._feed_pperm_hvc(ns, runtime_entry, 0)
        self._feed_pperm_hvc(ns, runtime_entry, 1, writable)
        self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12] = writable ^ (1 << 20)
        self._feed_pperm_hvc(ns, runtime_entry, 2)
        self.assertFalse(ns['report']['xnu_pperm_guest_window']['memcpy_crossed'])
        self.assertEqual(ns['xnu_pperm_state']['step'], 2)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_xnu_pperm_write_readback_failure_remains_cleanup_eligible(self):
        ns, runtime_entry, original, writable = self._prepare_pperm_window_replay()
        self._feed_pperm_hvc(ns, runtime_entry, 0)
        real_mrs = ns['u'].mrs
        calls = {'count': 0}
        def fail_first_readback(reg):
            calls['count'] += 1
            if calls['count'] == 1:
                raise RuntimeError('injected readback failure')
            return real_mrs(reg)
        ns['u'].mrs = fail_first_readback
        self._feed_pperm_hvc(ns, runtime_entry, 1, writable)
        self.assertTrue(ns['xnu_pperm_state']['modified'])
        self.assertEqual(ns['xnu_pperm_state']['previous'], original)
        ns['u'].mrs = real_mrs
        cleanup = restore_xnu_pperm_guest_window(
            ns['u'], self.s.SPRR_PPERM_EL12, ns['xnu_pperm_state'], True)
        self.assertTrue(cleanup['verified'])
        self.assertEqual(self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12], original)

    def test_xnu_pperm_two_complete_windows_and_limit_has_no_bank_io(self):
        ns, runtime_entry, original, writable = self._prepare_pperm_window_replay()
        ns['a'].xnu_pperm_guest_window_limit = 2
        for _ in range(2):
            self._feed_pperm_hvc(ns, runtime_entry, 0)
            self._feed_pperm_hvc(ns, runtime_entry, 1, writable)
            self._feed_pperm_hvc(ns, runtime_entry, 2)
            self._feed_pperm_hvc(ns, runtime_entry, 3, original)
        self.assertEqual((ns['xnu_pperm_state']['started'],
                          ns['xnu_pperm_state']['completed']), (2, 2))
        calls = len(self.endpoint.hardware.calls)
        self._feed_pperm_hvc(ns, runtime_entry, 0)
        self.assertEqual(len(self.endpoint.hardware.calls), calls)
        self.assertEqual(self.endpoint.report['stop_reason'], 'xnu-pperm-window-limit')
        self.assertEqual(self.endpoint.report['trace'][-1]['pc'],
                         runtime_entry + FC_XNU_PPERM_SITES[0][2]
                         - ns['FC_XNU_ENTRY_LINKED'] + 4)

    def test_xnu_pperm_second_window_rejects_baseline_drift(self):
        ns, runtime_entry, original, writable = self._prepare_pperm_window_replay()
        ns['a'].xnu_pperm_guest_window_limit = 2
        for index, value in ((0,0),(1,writable),(2,0),(3,original)):
            self._feed_pperm_hvc(ns, runtime_entry, index, value)
        self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12] = original ^ (1 << 20)
        self._feed_pperm_hvc(ns, runtime_entry, 0)
        self.assertEqual(ns['xnu_pperm_state']['started'], 1)
        self.assertEqual(ns['xnu_pperm_state']['completed'], 1)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
