"""Handoff controls regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from probe_control_support import ProbeControlFixture
import os
import struct
import unittest
from types import SimpleNamespace


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class ProbeHandoffTests(ProbeControlFixture, unittest.TestCase):

    def test_watchdog_deadline_exits_with_pc_without_mutating_context(self):
        self.endpoint.namespace['watchdog'] = SimpleNamespace(expired=True)
        self.assert_stopped_unchanged(*self.endpoint.feed(self.tables.event()), 'hang')
        self.assertEqual(self.endpoint.report['trace'][-1]['pc'], self.tables.pc)

    def test_handoff_step_budget_preserves_single_step_and_exits(self):
        ns = self.endpoint.namespace
        ns['handoff_state']['active'] = True
        ns['a'].free_run = True
        ns['a'].handoff_steps = 2
        self.endpoint.report['handoff'] = {}
        _, after = self.endpoint.feed(self.tables.event(0x32 << 26))
        self.assertEqual(after.spsr.SS, 1)
        self.assert_handled()
        self.endpoint.feed(self.tables.event(0x32 << 26))
        self.assertEqual(self.endpoint.report['stop_reason'], 'handoff-instruction-budget')
        self.assertEqual(self.endpoint.report['handoff']['observed_events'], 2)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_handoff_fault_stops_without_emulation(self):
        self.endpoint.namespace['handoff_state']['active'] = True
        self.endpoint.report['handoff'] = {}
        self.assert_stopped_unchanged(*self.endpoint.feed(self.tables.event(0x93c98005)), 'handoff-exception')

    def test_guarded_eret_launch_target_and_zero_bank_stop(self):
        for target, stop in ((0xfffffe0017070000, 'handoff-txm-entry'), (0, 'eret-unknown-target')):
            with self.subTest(target=target):
                self.setUp()
                ns = self.endpoint.namespace
                ns['a'].free_run = ns['a'].real_guarded = True
                ns['classify_entry'] = lambda *args: dict(image='txm', target_pc=hex(target), entry_matches=True, bytes_match=True, instructions_executed=False)
                ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1:self.s.ELR_EL12,
                                                       self.s.SPSR_GL1:self.s.SPSR_EL12})
                self.endpoint.hardware.values[self.s.ELR_EL12] = target
                self.endpoint.hardware.values[self.s.SPSR_EL12] = 0x13c0
                self.assert_stopped_unchanged(*self.endpoint.feed(self.tables.event(0x5a004800)), stop)
                if target:
                    self.assertEqual(self.endpoint.report['handoff']['target_pc'], hex(target))
                    self.assertEqual(self.endpoint.report['eret_classifications'][-1]['decision'],
                                     'entry-launch')

    def test_guarded_eret_classifier_error_is_retained_and_fail_closed(self):
        ns = self.endpoint.namespace
        ns['a'].free_run = ns['a'].real_guarded = True
        ns['classify_entry'] = lambda *args: (_ for _ in ()).throw(
            ValueError('synthetic classification failure'))
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1:self.s.ELR_EL12,
                                                   self.s.SPSR_GL1:self.s.SPSR_EL12})
        self.endpoint.hardware.values[self.s.ELR_EL12] = 0xfffffe0017070000
        self.endpoint.hardware.values[self.s.SPSR_EL12] = 0x13c0
        self.endpoint.feed(self.tables.event(0x5a004800))
        self.assertEqual(self.endpoint.report['stop_reason'], 'eret-classification-error')
        record = self.endpoint.report['eret_classifications'][-1]
        self.assertEqual(record['status'], 'error')
        self.assertIn('synthetic classification failure', record['error'])

    def test_guarded_eret_native_handoff_resumes_without_single_step(self):
        ns = self.endpoint.namespace
        target = 0xfffffe0017070000
        ns['a'].free_run = ns['a'].real_guarded = ns['a'].native_handoff = True
        ns['classify_entry'] = lambda *args: dict(image='txm', segment='__TEXT_BOOT_EXEC', target_pc=hex(target),
            entry_matches=True, bytes_match=True, instructions_executed=False)
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1:self.s.ELR_EL12,
                                                   self.s.SPSR_GL1:self.s.SPSR_EL12})
        self.endpoint.hardware.values[self.s.ELR_EL12] = target
        self.endpoint.hardware.values[self.s.SPSR_EL12] = 0x13c0
        _, after = self.endpoint.feed(self.tables.event(0x5a004800))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(after.elr, target)
        self.assertEqual(after.spsr.SS, 0)
        self.assertTrue(self.endpoint.report['handoff']['native_resume'])
        self.assertNotIn('stop_reason', self.endpoint.report)

    def test_native_txm_mode_stops_at_verified_xnu_entry(self):
        ns = self.endpoint.namespace
        target = 0xfffffe002bfb0000
        ns['a'].free_run = ns['a'].real_guarded = ns['a'].native_handoff = True
        ns['classify_entry'] = lambda *args: dict(image='kernelcache', target_pc=hex(target),
            entry_matches=True, bytes_match=True, instructions_executed=False)
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1:self.s.ELR_EL12,
                                                   self.s.SPSR_GL1:self.s.SPSR_EL12})
        self.endpoint.hardware.values[self.s.ELR_EL12] = target
        self.endpoint.hardware.values[self.s.SPSR_EL12] = 0x13c0
        self.endpoint.feed(self.tables.event(0x5a004800))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], 'handoff-xnu-entry')
        self.assertNotIn('native_resume', self.endpoint.report['handoff'])

    def test_native_gexit_stops_at_verified_xnu_launch_boundary(self):
        ns = self.endpoint.namespace
        target = 0xfffffe002bfb0000
        ns['a'].free_run = ns['a'].real_guarded = ns['a'].native_handoff = True
        ns['classify_entry'] = lambda *args: dict(image='kernelcache', target_pc=hex(target),
            entry_matches=True, bytes_match=True, instructions_executed=False)
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1:self.s.ELR_EL12,
                                                   self.s.SPSR_GL1:self.s.SPSR_EL12,
                                                   self.s.ASPSR_GL1:self.s.ASPSR_GL12})
        self.endpoint.hardware.values[self.s.ELR_EL12] = target
        self.endpoint.hardware.values[self.s.SPSR_EL12] = 0x13c9
        ns['HV'].MSR_REDIRECTS.update({self.s.SPRR_PPERM_EL1: self.s.SPRR_PPERM_EL12,
                                      self.s.SPRR_UPERM_EL0: self.s.SPRR_UPERM_EL02})
        live_pperm, live_uperm = 0x5555555555555555, 0x1111111111111111
        self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12] = live_pperm
        self.endpoint.hardware.values[self.s.SPRR_UPERM_EL02] = live_uperm
        ns['permission_shadow'][self.s.SPRR_PPERM_EL1] = 0
        ns['permission_shadow'][self.s.SPRR_UPERM_EL0] = 0
        # A real walk over the fixture's three table levels, at its mapped VA.
        self.endpoint.hardware.values[self.s.TTBR0_EL12] = self.tables.low
        self.endpoint.hardware.values[self.s.TTBR1_EL12] = self.tables.high
        original_translate = ns['translate']
        ns['translate'] = lambda va, ttbr0, ttbr1, read: original_translate(
            self.tables.pc, ttbr0, ttbr1, read)
        rt = 4
        reg = self.s.ASPSR_GL1
        op0, op1, crn, crm, op2 = reg
        word = 0xd5000000 | op0 << 19 | op1 << 16 | crn << 12 | crm << 8 | op2 << 5 | rt
        patched, = struct.unpack('<I', ns['patch_probe_code'](struct.pack('<I', word)))
        imm = (patched >> 5) & 0xffff
        before, after = self.endpoint.feed(dict(self.tables.event(0x5a000000 | imm, 0, rt),
                                                pc=ns['FC_XNU_GEXIT']))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.codec.build(after), self.endpoint.codec.build(before))
        self.assertEqual(self.endpoint.report['stop_reason'], 'handoff-xnu-entry')
        self.assertEqual(self.endpoint.report['handoff']['spsr'], '0x13c9')
        self.assertEqual(self.endpoint.report['handoff']['via'], 'native GEXIT launch boundary')
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'xnu-gexit-handoff')
        self.assertTrue(self.endpoint.report['trace'][-1]['verified'])
        self.assertFalse(any(call[0] == 'msr' for call in self.endpoint.hardware.calls))
        launch = self.endpoint.report['xnu_launch_permissions']
        self.assertEqual(launch['permission_source'], 'live guest aliases')
        self.assertEqual(launch['pperm_el1'], live_pperm)
        self.assertEqual(launch['uperm_el0'], live_uperm)
        self.assertEqual(launch['saved_pstate'], 0x13c9)
        self.assertIn('sctlr', launch['controls'])
        self.assertIn('ordinary', launch)
        self.assertEqual(len(launch['table_pages']), 3)
        for page in launch['table_pages']:
            self.assertEqual(len(self.endpoint.inputs[page['input']]), 0x4000)

    def test_native_handoff_resumes_verified_txm_world_return(self):
        ns = self.endpoint.namespace
        target = 0xfffffe0017068010
        ns['a'].free_run = ns['a'].real_guarded = ns['a'].native_handoff = True
        self.endpoint.report['handoff'] = {'image':'txm', 'native_resume':True}
        ns['classify_entry'] = lambda *args: dict(image='txm', segment='__TEXT_BOOT_EXEC',
            target_pc=hex(target), entry_matches=False, bytes_match=True,
            linked_pc='0xfffffff017068010', bytes_hex='ff0f5fd6' + '00' * 28,
            instructions_executed=False)
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1:self.s.ELR_EL12,
                                                   self.s.SPSR_GL1:self.s.SPSR_EL12})
        self.endpoint.hardware.values[self.s.ELR_EL12] = target
        self.endpoint.hardware.values[self.s.SPSR_EL12] = 0x600013c0
        _, after = self.endpoint.feed(dict(self.tables.event(0x5a004800),
                                           pc=0xfffffe00070a4edc))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(after.elr, target)
        self.assertEqual(int(after.spsr), 0x600013c0)
        self.assertTrue(self.endpoint.report['txm_world_returns'][-1]['native_resume'])
        self.assertNotIn('stop_reason', self.endpoint.report)

    def test_native_handoff_bounds_repeated_txm_service_return(self):
        ns = self.endpoint.namespace
        target = 0xfffffe00170532d8
        linked = '0xfffffff0170532d8'
        ns['a'].free_run = ns['a'].real_guarded = ns['a'].native_handoff = True
        self.endpoint.report['handoff'] = {'image':'txm', 'native_resume':True}
        self.endpoint.report['txm_world_returns'] = [{'linked_pc':linked}] * 64
        ns['classify_entry'] = lambda *args: dict(image='txm', segment='__TEXT_EXEC',
            target_pc=hex(target), entry_matches=False, bytes_match=True,
            linked_pc=linked, bytes_hex='ff0f5fd6' + '00' * 28,
            instructions_executed=False)
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1:self.s.ELR_EL12,
                                                   self.s.SPSR_GL1:self.s.SPSR_EL12})
        self.endpoint.hardware.values[self.s.ELR_EL12] = target
        self.endpoint.hardware.values[self.s.SPSR_EL12] = 0x200013c0
        self.endpoint.feed(dict(self.tables.event(0x5a004800), pc=0xfffffe00070a4edc))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], 'eret-unclassified-target')
