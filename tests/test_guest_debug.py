"""Replay real debug exits and synthetic faults; no serial device is opened."""
import copy
import gzip
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from guest_debug import GuestDebugState, MDSCR_EL1, OSLAR_EL1, UnsupportedGuestDebug
from replay_debug_probe import CallbackReplay, DEFAULT_TRACE, replay_trace


class GuestDebugModelTests(unittest.TestCase):
    def test_initial_state_is_an_explicit_guest_profile(self):
        self.assertEqual(GuestDebugState().snapshot(),
                         {'profile': 'disabled-debug', 'mdscr': 0, 'oslock': None})

    def test_every_unsupported_bit_stops_without_state_change(self):
        state = GuestDebugState()
        for bit in range(64):
            if bit == 12:
                continue
            with self.subTest(bit=bit):
                before = state.snapshot()
                with self.assertRaises(UnsupportedGuestDebug):
                    state.access(MDSCR_EL1, False, 1 << bit)
                self.assertEqual(state.snapshot(), before)

    def test_unknown_register_does_not_change_guest_state(self):
        state = GuestDebugState()
        before = state.snapshot()
        self.assertIsNone(state.access((3, 0, 1, 0, 0), False, 1))
        self.assertEqual(state.snapshot(), before)

    def test_oslock_state_does_not_leak_between_probes(self):
        first, second = GuestDebugState(), GuestDebugState()
        first.access(OSLAR_EL1, False, 0)
        self.assertEqual(first.oslock, 0)
        self.assertIsNone(second.oslock)


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for real callback replay')
class GuestDebugCallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checkout = Path(os.environ['VEL2_CHECKOUT'])
        cls.fixtures = json.loads((Path(__file__).parent/'fixtures/debug-events.json').read_text())
        cls.observed = cls.fixtures['mdscr_read']['event']

    def setUp(self):
        self.endpoint = CallbackReplay(self.checkout)

    def event(self, reg=MDSCR_EL1, read=True, rt=12, value=0):
        event = copy.deepcopy(self.observed)
        op0, op1, crn, crm, op2 = reg
        event['esr'] = (0x18 << 26 | 1 << 25 | op0 << 20 | op2 << 17 |
                        op1 << 14 | crn << 10 | rt << 5 | crm << 1 | int(read))
        event['regs'][rt] = value
        event['spsr'] &= ~(1 << 21)  # Require the callback to re-arm host stepping.
        return event

    def assert_no_hardware(self):
        self.assertEqual(self.endpoint.hardware.attempts, [])
        self.assertNotIn('error', self.endpoint.report)

    def test_model_encodings_match_pinned_public_definitions(self):
        from m1n1 import sysreg
        self.assertEqual(sysreg.MDSCR_EL1, MDSCR_EL1)
        self.assertEqual(sysreg.OSLAR_EL1, OSLAR_EL1)

    def test_exact_recorded_failure_now_returns_disabled_guest_state(self):
        before, after = self.endpoint.feed(self.observed)
        self.assertEqual(after.regs[12], 0)
        expected = list(before.regs)
        expected[12] = 0
        self.assertEqual(list(after.regs), expected)
        self.assertEqual(after.elr, before.elr + 4)
        self.assertEqual(int(after.spsr), int(before.spsr) | (1 << 21))
        self.assertEqual(list(after.sp), list(before.sp))
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.HANDLED)])
        self.assertEqual(self.endpoint.operations, ['read-context', 'write-context', 'exit-reply'])
        self.assertEqual(self.endpoint.report['trace'][0]['sysreg']['value'], 0)
        self.assert_no_hardware()

    def test_read_destination_all_registers_including_xzr(self):
        for rt in range(32):
            with self.subTest(rt=rt):
                before, after = self.endpoint.feed(self.event(rt=rt, value=0xdeadbeef))
                expected = list(before.regs)
                if rt != 31:
                    expected[rt] = 0
                self.assertEqual(list(after.regs), expected)
                self.assertEqual(after.elr, before.elr + 4)
                self.assertEqual(after.spsr.SS, 1)
                self.assertEqual(int(before.spsr) & ~(1 << 21), int(after.spsr) & ~(1 << 21))
        self.assert_no_hardware()

    def test_zero_write_preserves_registers_and_host_stepping(self):
        for rt in range(32):
            with self.subTest(rt=rt):
                # X31 storage is deliberately nonzero: an MSR from XZR is zero.
                before, after = self.endpoint.feed(self.event(read=False, rt=rt,
                                                               value=0xfeed if rt == 31 else 0))
                self.assertEqual(list(after.regs), list(before.regs))
                self.assertEqual(after.elr, before.elr + 4)
                self.assertEqual(after.spsr.SS, 1)
                self.assertEqual(self.endpoint.debug.mdscr, 0)
        self.assert_no_hardware()

    def test_guest_debug_enables_stop_without_writing_context(self):
        # SS, KDE and MDE, plus unmodelled/reserved/high-bit requests.
        for value in (1, 1 << 13, 1 << 15, (1 << 12) | 1, 1 << 63, (1 << 64)-1):
            with self.subTest(value=value):
                self.setUp()
                before, after = self.endpoint.feed(self.event(read=False, value=value))
                self.assertEqual(self.endpoint.codec.build(after), self.endpoint.codec.build(before))
                self.assertEqual(self.endpoint.debug.mdscr, 0)
                self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-guest-debug-control')
                self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.EXIT_GUEST)])
                self.assertEqual(self.endpoint.operations, ['read-context', 'save-report', 'exit-reply'])
                self.assert_no_hardware()

    def test_observed_tdcc_write_and_readback_preserve_host_controls(self):
        observed = self.fixtures['tdcc_write']['event']
        before, after = self.endpoint.feed(observed)
        self.assertEqual(after.elr, before.elr+4)
        self.assertEqual(list(after.regs), list(before.regs))
        self.assertEqual(self.endpoint.debug.mdscr, 0x1000)
        self.assertEqual(after.spsr.SS, 1)
        _, readback = self.endpoint.feed(self.event())
        self.assertEqual(readback.regs[12], 0x1000)
        self.endpoint.feed(self.event(read=False, value=0))
        self.assertEqual(self.endpoint.debug.mdscr, 0)
        self.assert_no_hardware()

    def test_tdcc_does_not_silently_emulate_dcc_access(self):
        self.endpoint.feed(self.event(read=False, value=0x1000))
        before, after = self.endpoint.feed(self.event((2, 3, 0, 5, 0)))
        self.assertEqual(after.elr, before.elr)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-system-register')
        self.assertEqual(self.endpoint.debug.mdscr, 0x1000)
        self.assert_no_hardware()

    def test_oslock_unlock_keeps_previous_behavior(self):
        before, after = self.endpoint.feed(self.event(OSLAR_EL1, False, 31, 0xbeef))
        self.assertEqual(after.elr, before.elr + 4)
        self.assertEqual(self.endpoint.report['guest_oslock'], 0)
        self.assertEqual(self.endpoint.report['guest_debug']['oslock'], 0)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'emulated-oslock-unlock')
        self.assert_no_hardware()

    def test_oslock_reads_and_lock_requests_remain_stops(self):
        for read, value in ((True, 0), (False, 1)):
            self.setUp()
            before, after = self.endpoint.feed(self.event(OSLAR_EL1, read, 12, value))
            self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
            self.assertIsNone(self.endpoint.debug.oslock)
            self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-guest-debug-control')
            self.assert_no_hardware()

    def test_unknown_sysreg_still_stops(self):
        before, after = self.endpoint.feed(self.event((2, 0, 0, 3, 2)))
        self.assertEqual(after.elr, before.elr)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-system-register')
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.EXIT_GUEST)])
        self.assert_no_hardware()

    def test_failed_context_write_still_sends_exactly_one_exit_reply(self):
        self.endpoint.fail_write = True
        before, after = self.endpoint.feed(self.observed)
        self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
        self.assertEqual(self.endpoint.report['stop_reason'], 'probe-validation-error')
        self.assertIn('injected context write failure', self.endpoint.report['error'])
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.EXIT_GUEST)])
        self.assertEqual(self.endpoint.operations[-2:], ['save-report', 'exit-reply'])
        self.assertEqual(self.endpoint.hardware.attempts, [])

    def test_budget_overrun_exits_even_after_successful_emulation(self):
        self.endpoint = CallbackReplay(self.checkout, steps=1)
        self.endpoint.feed(self.event())
        self.endpoint.feed(self.event())
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.HANDLED),
                                                  int(self.endpoint.EXC_RET.EXIT_GUEST)])
        self.assertEqual(self.endpoint.report['stop_reason'], 'instruction-budget')
        self.assert_no_hardware()

    def test_long_trace_checkpoint_cadence_and_stop_capture(self):
        self.endpoint = CallbackReplay(self.checkout, steps=65536)
        self.endpoint.report['trace'] = [{} for _ in range(4223)]
        self.endpoint.report['trace_checkpoint_events'] = 4096
        self.endpoint.feed(self.event())
        self.assertEqual(self.endpoint.saved, [])
        self.endpoint.report['trace'] = [{} for _ in range(8191)]
        self.endpoint.report['trace_total_events'] = 8191
        self.endpoint.feed(self.event())
        self.assertEqual(len(self.endpoint.saved), 1)
        self.endpoint.feed(self.event(read=False, value=1))
        self.assertEqual(len(self.endpoint.saved), 2)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-guest-debug-control')

    def test_windowed_report_budget_counts_evicted_events(self):
        self.endpoint = CallbackReplay(self.checkout, steps=4)
        self.endpoint.report['trace_window'] = 2
        for _ in range(5): self.endpoint.feed(self.event())
        self.assertEqual(self.endpoint.report['trace_total_events'], 5)
        self.assertEqual(len(self.endpoint.report['trace']), 2)
        self.assertEqual(self.endpoint.report['stop_reason'], 'instruction-budget')
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_checksum_verified_trace_replay_is_explicitly_partial(self):
        if not DEFAULT_TRACE.is_file():
            self.skipTest('Historical trace is stored locally; see docs/artifact-storage.md')
        report = replay_trace(DEFAULT_TRACE, self.checkout)
        self.assertEqual(report['source_events'], 393)
        self.assertEqual(report['replayed_debug_traps'], 2)
        self.assertEqual(report['unreplayed_events'], 391)
        self.assertEqual([r['trace_index'] for r in report['results']], [2, 392])
        self.assertFalse(report['hardware_executed'])
        self.assertFalse(report['instruction_execution_emulated'])
        self.assertFalse(report['guest_boot_verified'])
        self.assertIsNone(report['stop_reason'])
        self.assertEqual(report['hardware_access_attempts'], [])
