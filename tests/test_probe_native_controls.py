"""Native controls regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from probe_control_support import ProbeControlFixture
import os
import struct
import unittest
from sptm_entry_probe import (
    FC_XNU_CNTP_CTL_ESR,
    FC_XNU_CNTP_CTL_LINKED,
    FC_XNU_CNTP_CTL_WORD,
    FC_XNU_APPLE_PHYS_TIMER_ESR,
    FC_XNU_APPLE_PHYS_TIMER_LINKED,
    FC_XNU_APPLE_PHYS_TIMER_WORD,
    FC_XNU_APPLE_PHYS_TIMER_EL02,
    FC_XNU_DOCKCHANNEL_UART_IPA,
    FC_XNU_DOCKCHANNEL_UART_FAR,
    FC_XNU_DOCKCHANNEL_CONFIG_IPA,
    FC_XNU_DOCKCHANNEL_RX8_IPA,
    xnu_dockchannel_uart_catalog,
    FC_XNU_PANIC_CARVEOUT_IPA,
    FC_XNU_PANIC_CARVEOUT_SIZE,
    xnu_panic_carveout_contract,
    FC_XNU_SOCD_IPA,
    FC_XNU_SOCD_SIZE,
    FC_XNU_SOCD_FAR,
    FC_XNU_SOCD_ESR,
    xnu_socd_trace_contract,
)


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class ProbeNativeControlsTests(ProbeControlFixture, unittest.TestCase):

    def test_xnu_steps_normalizes_mode_and_arms_bounded_capture(self):
        before, after = self.feed_xnu_launch()
        ns = self.endpoint.namespace
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(after.elr, ns['FC_XNU_GEXIT'])
        self.assertEqual(after.spsr.SS, 1)
        self.assertEqual(self.endpoint.hardware.values[self.s.SPSR_EL12], 0x2013c5)
        self.assertEqual(self.endpoint.hardware.values[self.s.ASPSR_GL12], 0)
        self.assertTrue(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)
        self.assertTrue(ns['handoff_state']['active'])
        self.assertEqual(ns['handoff_state']['budget'], 2)
        self.assertFalse(self.endpoint.report['handoff']['instructions_executed'])
        self.assertNotIn('stop_reason', self.endpoint.report)
        target = 0xfffffe002bfb0000
        self.endpoint.feed(dict(self.tables.event(0x32 << 26), pc=target))
        self.assertFalse(self.endpoint.report['handoff']['instructions_executed'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.endpoint.feed(dict(self.tables.event(0x32 << 26), pc=target + 4))
        self.assertTrue(self.endpoint.report['handoff']['instructions_executed'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], 'handoff-instruction-budget')

    def test_xnu_steps_capture_failure_and_nonexecute_stop_without_mutation(self):
        for options in ({'broken_walk': True}, {'pperm': 0}):
            with self.subTest(options=options):
                self.setUp()
                before, after = self.feed_xnu_launch(**options)
                self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
                self.assertEqual(self.endpoint.report['stop_reason'], 'xnu-launch-permission-unverified')
                self.assertFalse(any(call[0] == 'msr' for call in self.endpoint.hardware.calls))
                self.assertFalse(self.endpoint.namespace['handoff_state']['active'])

    def test_xnu_steps_wrong_saved_mode_is_rejected_without_mutation(self):
        before, after = self.feed_xnu_launch(state=0x13c5)
        self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
        self.assertEqual(self.endpoint.report['stop_reason'], 'xnu-gexit-unverified')
        self.assertFalse(any(call[0] == 'msr' for call in self.endpoint.hardware.calls))

    def test_xnu_native_after_prefix_stops_first_exception(self):
        self.feed_xnu_launch()
        ns = self.endpoint.namespace
        ns['a'].xnu_run = True
        target = 0xfffffe002bfb0000
        self.endpoint.feed(dict(self.tables.event(0x32 << 26), pc=target))
        _, after = self.endpoint.feed(dict(self.tables.event(0x32 << 26), pc=target+4))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(after.spsr.SS, 0)
        self.assertFalse(ns['handoff_state']['active'])
        self.assertTrue(ns['handoff_state']['native'])
        self.assertEqual(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1, 0)
        self.endpoint.hardware.calls.clear()
        before, after = self.endpoint.feed(dict(self.tables.event(0x96000005), pc=target+0x100))
        self.assertEqual(self.endpoint.report['stop_reason'], 'xnu-native-exception')
        self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
        self.assertFalse(self.endpoint.hardware.calls)

    def test_tpidr_gl2_fast_shadow_enables_only_at_verified_native_gate(self):
        self.feed_xnu_launch()
        ns = self.endpoint.namespace
        ns['a'].xnu_run = ns['a'].xnu_tpidr_gl2_fast_shadow = True
        register = ns['tpidr_gl2_register']
        initial = 0xfffffe0007106200
        ns['apple_shadow'][register] = initial
        calls = []
        class GateAdapter:
            def enable(_self, tag_base, initial_value):
                calls.append((tag_base, initial_value,
                              ns['report']['handoff']['instructions_executed']))
                return dict(enabled=True, tag_base=tag_base, shadow=initial_value,
                            reads=0, writes=0, forwarded=0)
        ns['tpidr_gl2_fast_shadow'] = GateAdapter()
        ns['report']['xnu_tpidr_gl2_fast_shadow'] = {'activated': False}
        target = 0xfffffe002bfb0000
        self.endpoint.feed(dict(self.tables.event(0x32 << 26), pc=target))
        self.assertEqual(calls, [])
        _, after = self.endpoint.feed(dict(self.tables.event(0x32 << 26), pc=target+4))
        self.assertEqual(calls, [(ns['tpidr_gl2_shadow_tag_base'], initial, True)])
        self.assertTrue(ns['report']['xnu_tpidr_gl2_fast_shadow']['activated'])
        self.assertTrue(ns['handoff_state']['native'])
        self.assertEqual(after.spsr.SS, 0)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))

    def test_tpidr_gl2_fast_shadow_enable_failure_does_not_release_xnu(self):
        self.feed_xnu_launch()
        ns = self.endpoint.namespace
        ns['a'].xnu_run = ns['a'].xnu_tpidr_gl2_fast_shadow = True
        class FailingAdapter:
            def enable(_self, *_args):
                raise RuntimeError('injected proxy failure')
        ns['tpidr_gl2_fast_shadow'] = FailingAdapter()
        ns['report']['xnu_tpidr_gl2_fast_shadow'] = {'activated': False}
        target = 0xfffffe002bfb0000
        self.endpoint.feed(dict(self.tables.event(0x32 << 26), pc=target))
        self.endpoint.hardware.calls.clear()
        before, after = self.endpoint.feed(dict(
            self.tables.event(0x32 << 26), pc=target+4))
        self.assertEqual(self.endpoint.codec.build(before),
                         self.endpoint.codec.build(after))
        self.assertEqual(ns['report']['stop_reason'],
                         'xnu-tpidr-gl2-fast-shadow-enable-failed')
        self.assertFalse(ns['handoff_state'].get('native', False))
        self.assertFalse(any(call[0] == 'msr' and call[1] == self.s.MDSCR_EL1
                             for call in self.endpoint.hardware.calls))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_xnu_native_mdscr_read_uses_existing_disabled_debug_model(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        ns['report']['handoff'] = {'target_pc': '0xfffffe002bfb0000'}
        ns['guest_debug'].mdscr = 1 << 12
        pc = 0xfffffe00070a4094
        before, after = self.endpoint.feed(dict(
            self.tables.event(0x62240145), pc=pc))
        self.assertNotEqual(before.regs[10], 1 << 12)
        self.assertEqual(after.regs[10], 1 << 12)
        self.assertEqual(after.elr, pc + 4)
        self.assertFalse(int(after.spsr) & (1 << 21))
        self.assertEqual(ns['report']['trace'][-1]['kind'],
                         'emulated-guest-mdscr')
        self.assertTrue(ns['report']['trace'][-1]['native_handoff'])
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.endpoint.hardware.calls.clear()
        _, after_write = self.endpoint.feed(self.tables.event(
            0x62240144, value=1 << 12, rt=10))
        self.assertEqual(ns['report']['trace'][-1]['kind'],
                         'emulated-guest-mdscr')
        self.assertEqual(after_write.elr, self.tables.pc + 4)
        self.assertFalse(self.endpoint.hardware.calls)

    def test_xnu_native_mdscr_unsupported_bits_remain_fail_closed(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        ns['report']['handoff'] = {'target_pc': '0xfffffe002bfb0000'}
        ns['guest_debug'].mdscr = 1 << 12
        self.endpoint.hardware.calls.clear()
        before, after = self.endpoint.feed(self.tables.event(
            0x62240144, value=(1 << 12) | 1, rt=10))
        self.assertEqual(self.endpoint.codec.build(before),
                         self.endpoint.codec.build(after))
        self.assertEqual(ns['guest_debug'].mdscr, 1 << 12)
        self.assertEqual(ns['report']['stop_reason'],
                         'unsupported-guest-debug-control')
        self.assertFalse(self.endpoint.hardware.calls)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_xnu_native_maps_only_verified_dockchannel_uart_fault(self):
        cases = [('irq', 0xfffffe002b6b6fac, 0x93960006,
                  FC_XNU_DOCKCHANNEL_UART_FAR, FC_XNU_DOCKCHANNEL_UART_IPA),
                 ('config-first-page', 0xfffffe002b6b740c, 0x93810047,
                  0xfffffe003a000008, FC_XNU_DOCKCHANNEL_CONFIG_IPA + 8),
                 ('data-rx8-final-page', 0xfffffe002b6b6fac, 0x93960007,
                  0xfffffe003a00c01c, FC_XNU_DOCKCHANNEL_RX8_IPA)]
        for name, pc, esr, far, ipa in cases:
            with self.subTest(name=name):
                self.setUp()
                ns = self.endpoint.namespace
                ns['handoff_state'].update(active=False, native=True)
                ns['report']['handoff'] = {'target_pc': '0xfffffe002bfb0000'}
                ns['a'].on_demand_stage2 = 4
                ns['dockchannel_mmio'] = xnu_dockchannel_uart_catalog(
                    (FC_XNU_DOCKCHANNEL_CONFIG_IPA, 0x10000),
                    (FC_XNU_DOCKCHANNEL_UART_IPA, 0x1000), ['aapl,dock-channels'])
                ns['report']['xnu_dockchannel_uart_mmio'] = {
                    'mappings': [dict(site, mapped=False) for site in ns['dockchannel_mmio']]}
                ns['p'].hv_translate = lambda *_args, result=ipa: result
                event = self.tables.event(esr)
                event.update(pc=pc, far=far)
                self.endpoint.feed(event)
                self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
                self.assertEqual(self.endpoint.report['trace'][-1]['site'], name)
                self.assertTrue(any(isinstance(op, tuple) and op[0] == 'hv_map'
                                    for op in self.endpoint.operations))
                self.assertIn(('barrier', 'dsb ishst; tlbi vmalls12e1is; dsb ish; isb'),
                              self.endpoint.hardware.calls)

    def test_xnu_native_rejects_nonmatching_mmio_fault(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        ns['report']['handoff'] = {'target_pc': '0xfffffe002bfb0000'}
        ns['a'].on_demand_stage2 = 4
        ns['dockchannel_mmio'] = xnu_dockchannel_uart_catalog(
            (FC_XNU_DOCKCHANNEL_CONFIG_IPA, 0x10000),
            (FC_XNU_DOCKCHANNEL_UART_IPA, 0x1000), ['aapl,dock-channels'])
        ns['p'].hv_translate = lambda *_: FC_XNU_DOCKCHANNEL_CONFIG_IPA + 0x4000
        event = self.tables.event(0x93810047)
        event.update(pc=0xfffffe002b6b740c, far=0xfffffe003a000008)
        self.endpoint.feed(event)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], 'xnu-native-exception')
        self.assertFalse(any(isinstance(op, tuple) and op[0] == 'hv_map'
                             for op in self.endpoint.operations))

    def test_xnu_native_maps_verified_panic_carveout_to_private_copy(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        ns['report']['handoff'] = {'target_pc': '0xfffffe002bfb0000'}
        ns['a'].on_demand_stage2 = 256
        ns['panic_carveout'] = xnu_panic_carveout_contract(
            (FC_XNU_PANIC_CARVEOUT_IPA, FC_XNU_PANIC_CARVEOUT_SIZE),
            FC_XNU_PANIC_CARVEOUT_SIZE)
        ns['panic_carveout']['private_host'] = 0x30000000
        ns['report']['xnu_private_panic_carveout'] = {
            'enabled': True, 'copied': True, 'mapped': False, 'original_writes': False}
        ns['p'].hv_translate = lambda *_: FC_XNU_PANIC_CARVEOUT_IPA
        order = []
        original_map, original_exec = ns['p'].hv_map, ns['u'].exec
        ns['p'].hv_map = lambda *args: order.append('map') or original_map(*args)
        ns['u'].exec = lambda code: order.append(code) or original_exec(code)
        event = self.tables.event(0x93890006)
        event.update(pc=0xfffffe002bf3f3f4, far=0xfffffe003a014000)
        self.endpoint.feed(event)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        mapping = next(op for op in self.endpoint.operations
                       if isinstance(op, tuple) and op[0] == 'hv_map')
        self.assertEqual((mapping[1], mapping[3]),
                         (FC_XNU_PANIC_CARVEOUT_IPA, FC_XNU_PANIC_CARVEOUT_SIZE))
        self.assertEqual(mapping[2] & -0x4000, ns['panic_carveout']['private_host'])
        self.assertNotEqual(mapping[2] & -0x4000, FC_XNU_PANIC_CARVEOUT_IPA)
        self.assertEqual(order, ['map', 'dsb ishst; tlbi vmalls12e1is; dsb ish; isb'])
        self.assertEqual(self.endpoint.report['on_demand_stage2']['count'], 98)
        self.assertTrue(self.endpoint.report['xnu_private_panic_carveout']['mapped'])
        self.assertFalse(self.endpoint.report['xnu_private_panic_carveout']['original_writes'])

    def test_xnu_native_panic_carveout_rejects_translated_ipa_mismatch(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        ns['report']['handoff'] = {'target_pc': '0xfffffe002bfb0000'}
        ns['a'].on_demand_stage2 = 256
        ns['panic_carveout'] = xnu_panic_carveout_contract(
            (FC_XNU_PANIC_CARVEOUT_IPA, FC_XNU_PANIC_CARVEOUT_SIZE),
            FC_XNU_PANIC_CARVEOUT_SIZE)
        ns['panic_carveout']['private_host'] = 0x30000000
        ns['p'].hv_translate = lambda *_: FC_XNU_PANIC_CARVEOUT_IPA + 0x4000
        event = self.tables.event(0x93890006)
        event.update(pc=0xfffffe002bf3f3f4, far=0xfffffe003a014000)
        self.endpoint.feed(event)
        self.assertEqual(self.endpoint.report['stop_reason'], 'xnu-native-exception')
        self.assertFalse(any(isinstance(op, tuple) and op[0] == 'hv_map'
                             for op in self.endpoint.operations))

    def test_xnu_native_maps_verified_socd_trace_to_private_page(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        ns['report']['handoff'] = {'target_pc': '0xfffffe002bfb0000'}
        ns['a'].on_demand_stage2 = 1
        ns['socd_trace'] = xnu_socd_trace_contract(
            (FC_XNU_SOCD_IPA, FC_XNU_SOCD_SIZE), 'socd-trace-ram')
        ns['socd_trace']['private_host'] = 0x30000000
        ns['report']['xnu_private_socd_trace'] = {
            'enabled': True, 'copied': True, 'mapped': False, 'original_writes': False}
        ns['p'].hv_translate = lambda *_: FC_XNU_SOCD_IPA
        order = []
        original_map, original_exec = ns['p'].hv_map, ns['u'].exec
        ns['p'].hv_map = lambda *args: order.append('map') or original_map(*args)
        ns['u'].exec = lambda code: order.append(code) or original_exec(code)
        event = self.tables.event(FC_XNU_SOCD_ESR)
        event.update(pc=0xfffffe002b72118c, far=FC_XNU_SOCD_FAR)
        event['regs'][9] = 2
        event['regs'][11] = FC_XNU_SOCD_FAR
        self.endpoint.feed(event)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        mapping = next(op for op in self.endpoint.operations
                       if isinstance(op, tuple) and op[0] == 'hv_map')
        self.assertEqual((mapping[1], mapping[3]), (FC_XNU_SOCD_IPA & -0x4000, 0x4000))
        self.assertEqual(mapping[2] & -0x4000, 0x30000000)
        self.assertEqual(order, ['map', 'dsb ishst; tlbi vmalls12e1is; dsb ish; isb'])
        self.assertTrue(ns['report']['xnu_private_socd_trace']['mapped'])
        self.assertFalse(ns['report']['xnu_private_socd_trace']['original_writes'])

    def test_xnu_native_socd_trace_rejects_same_site_tuple_mismatch(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        ns['report']['handoff'] = {'target_pc': '0xfffffe002bfb0000'}
        ns['a'].on_demand_stage2 = 1
        ns['socd_trace'] = xnu_socd_trace_contract(
            (FC_XNU_SOCD_IPA, FC_XNU_SOCD_SIZE), 'socd-trace-ram')
        ns['socd_trace']['private_host'] = 0x30000000
        ns['report']['xnu_private_socd_trace'] = {'mapped': False}
        ns['p'].hv_translate = lambda *_: FC_XNU_SOCD_IPA
        event = self.tables.event(FC_XNU_SOCD_ESR)
        event.update(pc=0xfffffe002b72118c, far=FC_XNU_SOCD_FAR)
        event['regs'][9] = 3
        event['regs'][11] = FC_XNU_SOCD_FAR
        self.endpoint.feed(event)
        self.assertEqual(self.endpoint.report['stop_reason'], 'xnu-native-exception')
        self.assertFalse(any(isinstance(op, tuple) and op[0] == 'hv_map'
                             for op in self.endpoint.operations))

    def test_xnu_native_rejects_changed_continuation_bytes(self):
        self.feed_xnu_launch()
        ns = self.endpoint.namespace
        ns['a'].xnu_run = True
        target = 0xfffffe002bfb0000
        self.endpoint.feed(dict(self.tables.event(0x32 << 26), pc=target))
        ns['classify_entry'] = lambda *args: dict(image='kernelcache', bytes_match=False)
        self.endpoint.hardware.calls.clear()
        before, after = self.endpoint.feed(dict(self.tables.event(0x32 << 26), pc=target+4))
        self.assertEqual(self.endpoint.report['stop_reason'], 'xnu-native-unverified')
        self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
        self.assertFalse(any(c[0] == 'msr' for c in self.endpoint.hardware.calls))

    def test_xnu_native_admits_only_original_sptm_callback_tag(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        ns['a'].free_run = ns['a'].real_guarded = True
        reg = self.s.TPIDR_GL2
        op0, op1, crn, crm, op2 = reg
        word = 0xd5200000 | op0 << 19 | op1 << 16 | crn << 12 | crm << 8 | op2 << 5
        original = struct.pack('<I', word)
        ns['sources'] = {'sptm': original}
        ns['layout'] = {'images': {'sptm': {'segments': {'__TEXT_EXEC': {'fileoff':0, 'filesize':4}}}}}
        patched, = struct.unpack('<I', ns['patch_probe_code'](original))
        event = dict(self.tables.event(0x5a000000 | ((patched >> 5) & 0xffff)), pc=ns['FC_IMAGE_BASE']+4)
        self.endpoint.feed(event)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(self.endpoint.report['xnu_sptm_callbacks'], 1)
        ns['sources']['sptm'] = b'\x1f\x20\x03\xd5'
        self.endpoint.report['handoff'] = {}
        self.endpoint.feed(event)
        self.assertEqual(self.endpoint.report['stop_reason'], 'xnu-native-exception')

    def test_xnu_native_services_exact_agtcnt_rdir_el12_write_in_guest_bank(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        target = 0xfffffe002bfb0000
        ns['report']['handoff'] = {'target_pc': hex(target)}
        ns['sources'] = {'kernelcache': struct.pack('<I', ns['FC_XNU_AGT_WORD'])}
        ns['layout'] = {'images': {'kernelcache': {'segments': {'__TEXT_EXEC': {
            'va': ns['FC_XNU_AGT_LINKED'], 'fileoff': 0, 'filesize': 4}}}}}
        self.endpoint.hardware.values[self.s.AGTCNTRDIR_EL12] = 1
        pc = target + ns['FC_XNU_AGT_LINKED'] - ns['FC_XNU_ENTRY_LINKED'] + 4
        before, after = self.endpoint.feed(dict(
            self.tables.event(ns['FC_XNU_AGT_ESR'], 3, 8), pc=pc))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
        self.assertEqual(self.endpoint.hardware.calls, [
            ('mrs', self.s.AGTCNTRDIR_EL12), ('msr', self.s.AGTCNTRDIR_EL12, 3)])
        self.assertEqual(self.endpoint.hardware.values[self.s.AGTCNTRDIR_EL12], 3)
        self.assertEqual(self.endpoint.report['xnu_guest_registers'], [{
            'register': 'AGTCNTRDIR_EL12', 'previous': 1, 'value': 3,
            'source_pc': hex(pc - 4), 'bank': 'guest-el12'}])
        self.assertEqual(ns['xnu_agt_state'], {'previous': 1, 'writes': 1})
        self.endpoint.hardware.calls.clear()
        self.endpoint.feed(dict(
            self.tables.event(ns['FC_XNU_AGT_ESR'], 3, 8), pc=pc))
        self.assertEqual(ns['xnu_agt_state'], {'previous': 1, 'writes': 2})
        self.assertEqual(self.endpoint.hardware.calls, [
            ('mrs', self.s.AGTCNTRDIR_EL12), ('msr', self.s.AGTCNTRDIR_EL12, 3)])

    def test_xnu_native_agtcnt_rdir_fails_closed_on_value_or_source_mismatch(self):
        for mismatch in ('value', 'source', 'pc', 'esr-il'):
            with self.subTest(mismatch=mismatch):
                self.setUp()
                ns = self.endpoint.namespace
                ns['handoff_state'].update(active=False, native=True)
                target = 0xfffffe002bfb0000
                ns['report']['handoff'] = {'target_pc': hex(target)}
                word = ns['FC_XNU_AGT_WORD'] if mismatch != 'source' else 0xd503201f
                ns['sources'] = {'kernelcache': struct.pack('<I', word)}
                ns['layout'] = {'images': {'kernelcache': {'segments': {'__TEXT_EXEC': {
                    'va': ns['FC_XNU_AGT_LINKED'], 'fileoff': 0, 'filesize': 4}}}}}
                pc = target + ns['FC_XNU_AGT_LINKED'] - ns['FC_XNU_ENTRY_LINKED'] + 4
                if mismatch == 'pc':
                    pc += 4
                value = 2 if mismatch == 'value' else 3
                esr = ns['FC_XNU_AGT_ESR']
                if mismatch == 'esr-il':
                    esr &= ~(1 << 25)
                before, after = self.endpoint.feed(dict(
                    self.tables.event(esr, value, 8), pc=pc))
                self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
                self.assertFalse(any(call[0] == 'msr' for call in self.endpoint.hardware.calls))
                expected = 'xnu-agtcnt-rdir-contract' if mismatch == 'value' else 'xnu-native-exception'
                self.assertEqual(self.endpoint.report['stop_reason'], expected)

    def test_xnu_native_services_exact_cntp_ctl_write_in_guest_el02_bank(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        target = 0xfffffe002bfb0000
        ns['report']['handoff'] = {'target_pc': hex(target)}
        ns['sources'] = {'kernelcache': struct.pack('<I', FC_XNU_CNTP_CTL_WORD)}
        ns['layout'] = {'images': {'kernelcache': {'segments': {'__TEXT_EXEC': {
            'va': FC_XNU_CNTP_CTL_LINKED, 'fileoff': 0, 'filesize': 4}}}}}
        self.endpoint.hardware.values[self.s.CNTP_CTL_EL02] = 5
        pc = target + FC_XNU_CNTP_CTL_LINKED - ns['FC_XNU_ENTRY_LINKED']
        before, after = self.endpoint.feed(dict(
            self.tables.event(FC_XNU_CNTP_CTL_ESR, 2, 8), pc=pc))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(after.elr, before.elr + 4)
        self.assertEqual(self.endpoint.hardware.calls, [
            ('mrs', self.s.CNTP_CTL_EL02), ('msr', self.s.CNTP_CTL_EL02, 2)])
        self.assertEqual(self.endpoint.hardware.values[self.s.CNTP_CTL_EL02], 2)
        self.assertEqual(self.endpoint.report['xnu_guest_registers'], [{
            'register': 'CNTP_CTL_EL02', 'previous': 5, 'value': 2,
            'source_pc': hex(pc), 'bank': 'guest-el02',
            'host_timer_bank_touched': False}])
        self.assertEqual(ns['xnu_cntp_ctl_state'], {'previous': 5, 'writes': 1})

    def test_xnu_native_cntp_ctl_rejects_mismatched_contract_without_bank_io(self):
        for mismatch in ('value', 'source', 'pc', 'esr'):
            with self.subTest(mismatch=mismatch):
                self.setUp()
                ns = self.endpoint.namespace
                ns['handoff_state'].update(active=False, native=True)
                target = 0xfffffe002bfb0000
                ns['report']['handoff'] = {'target_pc': hex(target)}
                word = FC_XNU_CNTP_CTL_WORD if mismatch != 'source' else 0xd503201f
                ns['sources'] = {'kernelcache': struct.pack('<I', word)}
                ns['layout'] = {'images': {'kernelcache': {'segments': {'__TEXT_EXEC': {
                    'va': FC_XNU_CNTP_CTL_LINKED, 'fileoff': 0, 'filesize': 4}}}}}
                pc = target + FC_XNU_CNTP_CTL_LINKED - ns['FC_XNU_ENTRY_LINKED']
                if mismatch == 'pc':
                    pc += 4
                esr = FC_XNU_CNTP_CTL_ESR ^ (1 if mismatch == 'esr' else 0)
                value = 3 if mismatch == 'value' else 2
                before, after = self.endpoint.feed(dict(
                    self.tables.event(esr, value, 8), pc=pc))
                self.assertEqual(self.endpoint.codec.build(before),
                                 self.endpoint.codec.build(after))
                self.assertFalse(any(call[0] in ('mrs', 'msr') and
                                     call[1] == self.s.CNTP_CTL_EL02
                                     for call in self.endpoint.hardware.calls))
                expected = ('xnu-cntp-ctl-contract' if mismatch == 'value'
                            else 'xnu-native-exception')
                self.assertEqual(self.endpoint.report['stop_reason'], expected)

    def test_xnu_apple_timer_hypothesis_services_only_candidate_bank(self):
        ns = self.endpoint.namespace
        ns['a'].xnu_apple_physical_timer_hypothesis = True
        ns['handoff_state'].update(active=False, native=True)
        target = 0xfffffe002bfb0000
        ns['report']['handoff'] = {'target_pc': hex(target)}
        ns['sources'] = {'kernelcache': struct.pack('<I', FC_XNU_APPLE_PHYS_TIMER_WORD)}
        ns['layout'] = {'images': {'kernelcache': {'segments': {'__TEXT_EXEC': {
            'va': FC_XNU_APPLE_PHYS_TIMER_LINKED, 'fileoff': 0, 'filesize': 4}}}}}
        self.endpoint.hardware.values[FC_XNU_APPLE_PHYS_TIMER_EL02] = 6
        pc = target + FC_XNU_APPLE_PHYS_TIMER_LINKED - ns['FC_XNU_ENTRY_LINKED']
        before, after = self.endpoint.feed(dict(
            self.tables.event(FC_XNU_APPLE_PHYS_TIMER_ESR, 2, 8), pc=pc))
        self.assertEqual(after.elr, before.elr + 4)
        self.assertEqual(self.endpoint.hardware.calls, [
            ('mrs', FC_XNU_APPLE_PHYS_TIMER_EL02),
            ('msr', FC_XNU_APPLE_PHYS_TIMER_EL02, 2),
            ('mrs', FC_XNU_APPLE_PHYS_TIMER_EL02)])
        result = self.endpoint.report['xnu_apple_physical_timer_hypothesis']
        self.assertEqual((result['observed_prior_raw'], result['requested_raw'],
                          result['readback_raw']), (6, 2, 2))
        self.assertFalse(result['routing_established'])
        self.assertFalse(result['bit_semantics_established'])
        self.assertFalse(result['physical_s3_1_bank_touched'])
        self.assertEqual(ns['xnu_apple_timer_state'], {'previous': 6, 'writes': 1})

    def test_xnu_apple_timer_hypothesis_rejects_all_contract_mismatches(self):
        for mismatch in ('disabled', 'value', 'source', 'pc', 'esr', 'prior'):
            with self.subTest(mismatch=mismatch):
                self.setUp()
                ns = self.endpoint.namespace
                ns['a'].xnu_apple_physical_timer_hypothesis = mismatch != 'disabled'
                ns['handoff_state'].update(active=False, native=True)
                target = 0xfffffe002bfb0000
                ns['report']['handoff'] = {'target_pc': hex(target)}
                word = (FC_XNU_APPLE_PHYS_TIMER_WORD if mismatch != 'source'
                        else 0xd503201f)
                ns['sources'] = {'kernelcache': struct.pack('<I', word)}
                ns['layout'] = {'images': {'kernelcache': {'segments': {'__TEXT_EXEC': {
                    'va': FC_XNU_APPLE_PHYS_TIMER_LINKED,
                    'fileoff': 0, 'filesize': 4}}}}}
                self.endpoint.hardware.values[FC_XNU_APPLE_PHYS_TIMER_EL02] = (
                    7 if mismatch == 'prior' else 6)
                pc = target + FC_XNU_APPLE_PHYS_TIMER_LINKED - ns['FC_XNU_ENTRY_LINKED']
                if mismatch == 'pc':
                    pc += 4
                esr = FC_XNU_APPLE_PHYS_TIMER_ESR ^ (1 if mismatch == 'esr' else 0)
                value = 3 if mismatch == 'value' else 2
                before, after = self.endpoint.feed(dict(
                    self.tables.event(esr, value, 8), pc=pc))
                self.assertEqual(self.endpoint.codec.build(before),
                                 self.endpoint.codec.build(after))
                self.assertFalse(any(call[0] == 'msr' and
                                     call[1] == FC_XNU_APPLE_PHYS_TIMER_EL02
                                     for call in self.endpoint.hardware.calls))
                self.assertEqual(ns['xnu_apple_timer_state'],
                                 {'previous': None, 'writes': 0})
