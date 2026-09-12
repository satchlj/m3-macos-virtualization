"""Exception classification, entry guards, and ordered exit replies offline."""
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from guest_pt import PAGE
from probe_fixtures import Tables


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class ProbeExceptionTests(unittest.TestCase):
    def setUp(self):
        self.t = Tables()
        self.endpoint = self.t.endpoint(os.environ['VEL2_CHECKOUT'])

    def assert_exit(self, before, after, reason):
        self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], reason)
        self.assertEqual(self.endpoint.hardware.calls, [])

    def test_irq_fiq_serror_cannot_reuse_stale_synchronous_esr(self):
        for reason in (1, 2):
            for code in (1, 2, 3):
                for esr in (0x62240185, 0x5a006000, 0xca000022):
                    with self.subTest(reason=reason, code=code, esr=esr):
                        self.setUp()
                        event = dict(self.t.event(esr), reason=reason, code=code)
                        self.assert_exit(*self.endpoint.feed(event), 'asynchronous-exception')
                        self.assertNotIn('read-context', self.endpoint.operations)

    def test_host_synchronous_exception_never_emulates_guest_access(self):
        for esr in (0x62240185, 0x5a006000, 0xca000022):
            self.setUp()
            self.assert_exit(*self.endpoint.feed(dict(self.t.event(esr), reason=1)), 'unsupported-exception')

    def test_unhandled_lower_exception_classes_stop_without_resume(self):
        for ec in (0, 0x20, 0x24, 0x25, 0x30, 0x34):
            self.setUp()
            self.assert_exit(*self.endpoint.feed(self.t.event((ec << 26) | (1 << 25))),
                             'unsupported-exception')

    def test_hypervisor_event_does_not_decode_exception_context(self):
        self.assert_exit(*self.endpoint.feed(dict(self.t.event(), reason=3)), 'hypervisor-event')
        self.assertNotIn('read-context', self.endpoint.operations)

    def test_single_step_rearms_without_advancing_pc_or_other_state(self):
        before, after = self.endpoint.feed(self.t.event(0xca000022))
        self.assertEqual(after.elr, before.elr)
        self.assertEqual(list(after.regs), list(before.regs))
        self.assertEqual(int(after.spsr), int(before.spsr) | (1 << 21))
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'instruction-step')
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.HANDLED)])
        self.assertEqual(self.endpoint.hardware.calls, [])

    def prepare_guard(self):
        self.endpoint = self.t.endpoint(os.environ['VEL2_CHECKOUT'], entered=False)
        self.t.memory.add_page(self.t.pc & -PAGE)
        self.t.memory.write(self.t.pc, b'\xaa\xbb\xcc\xdd')

    def test_entry_guard_accepts_only_expected_hvc_or_step_pc(self):
        for esr, advance in ((0x5a007ffe, 4), (0xca000022, 0)):
            self.prepare_guard()
            event = dict(self.t.event(esr), pc=self.t.pc+advance, spsr=0xa0000005)
            before, after = self.endpoint.feed(event)
            self.assertEqual(after.elr, self.t.pc)
            self.assertEqual(int(after.spsr), int(before.spsr) | 0x3c0 | (1 << 21))
            self.assertEqual(self.t.memory.read(self.t.pc, 4), b'\x1f\x20\x03\xd5')
            self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'entry-guard')
            self.assertEqual(self.endpoint.operations, ['read-context', 'write-guest-memory',
                                                        'cache-maintenance', 'cache-maintenance',
                                                        'write-context', 'exit-reply'])
            self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.HANDLED)])
            # Once entered, a repeated guard HVC is no longer an entry handshake.
            event = self.t.event(0x5a007ffe)
            self.assert_exit(*self.endpoint.feed(event), 'unsupported-exception')

    def test_bad_entry_guard_pc_leaves_instruction_and_context_unchanged(self):
        for esr, advance in ((0x5a007ffe, 0), (0xca000022, 4), (0x5a007fff, 4)):
            self.prepare_guard()
            self.assert_exit(*self.endpoint.feed(dict(self.t.event(esr), pc=self.t.pc+advance)),
                             'unsupported-exception')
            self.assertEqual(self.t.memory.read(self.t.pc, 4), b'\xaa\xbb\xcc\xdd')

    def test_step_before_entry_cannot_bypass_handshake(self):
        self.endpoint = self.t.endpoint(os.environ['VEL2_CHECKOUT'], entered=False)
        self.assert_exit(*self.endpoint.feed(dict(self.t.event(0xca000022), pc=self.t.pc+8)),
                         'unsupported-exception')

    def test_report_failure_on_stop_still_replies_exactly_once(self):
        self.endpoint.fail_save = True
        self.assert_exit(*self.endpoint.feed(self.t.event(0)), 'report-write-error')
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.EXIT_GUEST)])
        self.assertIn('injected report save failure', self.endpoint.report['report_save_error'])

    def test_periodic_report_failure_converts_resume_to_exit(self):
        self.endpoint.report['trace'] = [{} for _ in range(127)]
        self.endpoint.fail_save = True
        self.endpoint.feed(self.t.event(0xca000022))
        self.assertEqual(self.endpoint.report['stop_reason'], 'report-write-error')
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.EXIT_GUEST)])
        self.assertEqual(self.endpoint.operations[-1], 'exit-reply')

    def test_context_failure_still_returns_guest_exit(self):
        self.endpoint.fail_write = True
        self.assert_exit(*self.endpoint.feed(self.t.event(0xca000022)), 'probe-validation-error')
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.EXIT_GUEST)])
