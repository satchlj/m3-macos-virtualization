"""Controls regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from probe_control_support import ProbeControlFixture
import os
import unittest
from probe_fixtures import ENABLED_SCTLR, VHE_HCR


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class ProbeControlTests(ProbeControlFixture, unittest.TestCase):

    def test_el1_and_el2_translation_aliases_use_only_guest_banks(self):
        for alias, bank in self.endpoint.namespace['translation_banks'].items():
            with self.subTest(alias=alias):
                before, after = self.access(alias, value=0x1234567890abcdef, rt=7)
                self.assert_handled()
                self.assertEqual(self.endpoint.hardware.values[bank], 0x1234567890abcdef)
                self.assertEqual(after.elr, before.elr)  # HVC return PC is already advanced.
                self.assertEqual(after.spsr.SS, 1)
                _, after = self.access(alias, read=True, rt=12)
                self.assertEqual(after.regs[12], 0x1234567890abcdef)
                self.assert_handled()

    def test_translation_aliases_honor_xzr(self):
        for alias, bank in self.endpoint.namespace['translation_banks'].items():
            with self.subTest(alias=alias):
                self.access(alias, value=0xbeef, rt=31)
                self.assert_handled()
                self.assertEqual(self.endpoint.hardware.values[bank], 0)
                before, after = self.access(alias, read=True, value=0xbeef, rt=31)
                self.assertEqual(after.regs[31], before.regs[31])

    def test_real_guarded_vbar_redirects_gl1_access_to_gl12(self):
        endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'],
                                        real_guarded=True, real_guarded_vbar=True)
        self.assertEqual(endpoint.namespace['HV'].MSR_REDIRECTS[self.s.VBAR_GL1],
                         self.s.VBAR_GL12)
        value = 0xfffffe00070ac000
        before, after = self.tables.access(endpoint, self.s.VBAR_GL1, value=value, rt=7)
        self.assertEqual(endpoint.replies[-1], int(endpoint.EXC_RET.HANDLED))
        self.assertEqual((after.elr, after.spsr.SS), (before.elr, 1))
        self.assertEqual(endpoint.hardware.calls, [('msr', self.s.VBAR_GL12, value),
                                                   ('mrs', self.s.VBAR_GL12)])
        self.assertEqual(endpoint.hardware.values[self.s.VBAR_GL12], value)
        self.assertEqual(endpoint.hardware.values[self.s.VBAR_EL12], 0)
        self.assertEqual(endpoint.report['trace'][-1]['kind'], 'real-guarded-redirect')
        self.assertEqual(endpoint.report['trace'][-1]['readback'], value)
        self.assertEqual(endpoint.report['real_guarded_vbar'][-1]['readback'], value)
        endpoint.hardware.calls.clear()
        _, after = self.tables.access(endpoint, self.s.VBAR_GL1, read=True, rt=9)
        self.assertEqual(after.regs[9], value)
        self.assertEqual(endpoint.hardware.calls, [('mrs', self.s.VBAR_GL12)])

    def test_real_guarded_vbar_remains_staged_without_explicit_flag(self):
        endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], real_guarded=True)
        value = 0xfffffe00070ac000
        self.tables.access(endpoint, self.s.VBAR_GL1, value=value, rt=7)
        self.assertEqual(endpoint.replies[-1], int(endpoint.EXC_RET.HANDLED))
        self.assertEqual(endpoint.hardware.calls, [])
        self.assertEqual(endpoint.hardware.values[self.s.VBAR_GL12], 0)
        self.assertEqual(endpoint.report['trace'][-1]['kind'], 'staged-apple-register')
        self.assertEqual(endpoint.report['staged_apple_registers']['VBAR_GL1'], value)

    def test_valid_enable_checks_tables_then_orders_guest_control_and_barriers(self):
        self.tables.configure(self.endpoint)
        self.endpoint.hardware.calls.clear()
        before, after = self.access(self.s.SCTLR_EL2, value=ENABLED_SCTLR)
        self.assert_handled()
        self.assertEqual(after.elr, before.elr)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'monitor-mmu-enabled')
        self.assertEqual(self.endpoint.hardware.calls[-3:], [
            ('barrier', 'dsb ishst; tlbi vmalle1is; dsb ish; isb'),
            ('msr', self.s.SCTLR_EL12, ENABLED_SCTLR), ('barrier', 'isb')])
        checked = self.endpoint.report['monitor_mmu_address_checks']
        self.assertEqual(checked['pc']['pa'], self.tables.pc)
        self.assertNotEqual(checked['stack']['pa'], checked['stack']['va'])
        self.assertIn('unmapped', checked['bootargs'])
        self.assertEqual(len(self.tables.memory.reads), len(set(self.tables.memory.reads)))

    def test_sctlr_el1_alias_uses_same_enable_path(self):
        self.tables.configure(self.endpoint)
        self.access(self.s.SCTLR_EL1, value=ENABLED_SCTLR)
        self.assert_handled()
        self.assertEqual(self.endpoint.hardware.values[self.s.SCTLR_EL12], ENABLED_SCTLR)

    def test_missing_opt_in_cannot_enable_mmu(self):
        self.endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'])
        self.tables.configure(self.endpoint)
        self.endpoint.hardware.calls.clear()
        self.assert_stopped_unchanged(*self.access(self.s.SCTLR_EL2, value=ENABLED_SCTLR),
                                      'monitor-translation-contract')
        self.assertEqual(self.tables.memory.reads, [])

    def test_missing_vhe_and_staged_sprr_enable_block_translation(self):
        for sprr in (False, True):
            with self.subTest(sprr=sprr):
                self.setUp()
                if sprr:
                    self.tables.configure(self.endpoint)
                    self.access(self.s.SPRR_CONFIG_EL1, value=1)
                self.endpoint.hardware.calls.clear()
                self.assert_stopped_unchanged(*self.access(self.s.SCTLR_EL2, value=ENABLED_SCTLR),
                                              'monitor-translation-contract')

    def test_profile_mismatch_stops_before_table_reads_or_control_write(self):
        for alias in (self.s.TCR_EL1, self.s.MAIR_EL1):
            with self.subTest(alias=alias):
                self.setUp()
                self.tables.configure(self.endpoint)
                self.access(alias, value=0)
                self.endpoint.hardware.calls.clear()
                self.assert_stopped_unchanged(*self.access(self.s.SCTLR_EL2, value=ENABLED_SCTLR),
                                              'probe-validation-error')
                self.assertEqual(self.tables.memory.reads, [])

    def test_bad_root_cannot_be_masked_into_guest_memory(self):
        self.tables.configure(self.endpoint)
        self.access(self.s.TTBR0_EL1, value=self.tables.low | (1 << 42))
        self.endpoint.hardware.calls.clear()
        self.assert_stopped_unchanged(*self.access(self.s.SCTLR_EL2, value=ENABLED_SCTLR),
                                      'probe-validation-error')
        self.assertEqual(self.tables.memory.reads, [])

    def test_parent_execute_never_prevents_enable(self):
        location = self.tables.pc_path[0]
        self.tables.put(location, self.tables.get(location) | (1 << 59))
        self.tables.configure(self.endpoint)
        self.endpoint.hardware.calls.clear()
        self.assert_stopped_unchanged(*self.access(self.s.SCTLR_EL2, value=ENABLED_SCTLR),
                                      'probe-validation-error')
        self.assertIn('execute-never', self.endpoint.report['error'])
        self.assertEqual(self.endpoint.report['monitor_mmu_check_pending'],
                         {'name': 'pc', 'va': self.tables.pc})

    def test_live_translation_changes_rejected_for_every_alias(self):
        self.tables.enable(self.endpoint)
        self.assert_handled()
        for alias, bank in self.endpoint.namespace['translation_banks'].items():
            with self.subTest(alias=alias):
                old = self.endpoint.hardware.values[bank]
                self.endpoint.hardware.calls.clear()
                self.assert_stopped_unchanged(*self.access(alias, value=old ^ 0x4000),
                                              'live-translation-control-change')
                self.assertEqual(self.endpoint.hardware.values[bank], old)

    def test_identical_live_writes_do_not_reprogram_hardware(self):
        self.tables.enable(self.endpoint)
        for alias, bank in self.endpoint.namespace['translation_banks'].items():
            with self.subTest(alias=alias):
                self.endpoint.hardware.calls.clear()
                self.access(alias, value=self.endpoint.hardware.values[bank])
                self.assert_handled()
                self.assertEqual(self.endpoint.hardware.calls, [('mrs', bank)])

    def test_live_hcr_change_is_rejected_and_shadow_preserved(self):
        self.tables.enable(self.endpoint)
        self.endpoint.hardware.calls.clear()
        self.assert_stopped_unchanged(*self.access(self.s.HCR_EL2, value=0),
                                      'monitor-translation-contract')
        _, after = self.access(self.s.HCR_EL2, read=True)
        self.assertEqual(after.regs[0], VHE_HCR)

    def test_disable_synchronizes_before_tlbi_and_allows_new_roots(self):
        self.tables.enable(self.endpoint)
        self.endpoint.hardware.calls.clear()
        self.access(self.s.SCTLR_EL1, value=0)
        self.assert_handled()
        self.assertEqual(self.endpoint.hardware.calls, [
            ('msr', self.s.SCTLR_EL12, 0x30d00800),
            ('barrier', 'isb; dsb ishst; tlbi vmalle1is; dsb ish; isb')])
        _, after = self.access(self.s.SCTLR_EL2, read=True)
        self.assertEqual(after.regs[0], 0)
        self.access(self.s.TTBR0_EL2, value=self.tables.high)
        self.assert_handled()
        self.assertEqual(self.endpoint.hardware.values[self.s.TTBR0_EL12], self.tables.high)

    def test_translated_sprr_activation_and_gxf_remain_stops(self):
        self.tables.enable(self.endpoint)
        for register in (self.s.SPRR_CONFIG_EL1, self.s.GXF_CONFIG_EL1):
            self.endpoint.hardware.calls.clear()
            self.assert_stopped_unchanged(*self.access(register, value=1), 'unsupported-el2-register')

    def test_virtual_eret_and_gxf_instructions_remain_stops(self):
        self.tables.enable(self.endpoint)
        for imm in (0x4800, 0x6080, 0x6090, 0x60a0):
            self.endpoint.hardware.calls.clear()
            self.assert_stopped_unchanged(*self.endpoint.feed(self.tables.event(0x5a000000 | imm)),
                                          'unsupported-exception')

    def test_malformed_extra_register_hvc_exits_without_side_effects(self):
        self.assertLess(len(self.endpoint.namespace['extra_regs']), 256)
        self.assert_stopped_unchanged(*self.endpoint.feed(self.tables.event(0x5a00bfff)),
                                      'probe-validation-error')

    def test_budget_exhaustion_stops_before_translation_side_effects(self):
        self.endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], steps=1)
        self.access(self.s.HCR_EL2, value=VHE_HCR)
        self.endpoint.hardware.calls.clear()
        self.assert_stopped_unchanged(*self.access(self.s.TTBR0_EL1, value=self.tables.low),
                                      'instruction-budget')
        self.assertEqual(self.endpoint.hardware.calls, [])
