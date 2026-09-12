"""Actual instruction rewriting and probe callbacks against synthetic guest RAM."""
import os
from pathlib import Path
import struct
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from probe_fixtures import Tables, ENABLED_SCTLR, VHE_HCR
from sptm_entry_probe import (FC_XNU_AGT_ESR, FC_XNU_AGT_HVC, FC_XNU_AGT_LINKED,
                              FC_XNU_AGT_WORD, patch_xnu_agtcnt_rdir,
                              restore_xnu_agtcnt_rdir, FC_XNU_AHCR_NOP_SITES,
                              FC_XNU_CNTP_CTL_ESR, FC_XNU_CNTP_CTL_LINKED,
                              FC_XNU_CNTP_CTL_WORD, restore_xnu_cntp_ctl,
                              FC_XNU_APPLE_PHYS_TIMER_ESR,
                              FC_XNU_APPLE_PHYS_TIMER_LINKED,
                              FC_XNU_APPLE_PHYS_TIMER_WORD,
                              FC_XNU_APPLE_PHYS_TIMER_EL02,
                              restore_xnu_apple_physical_timer,
                              FC_XNU_M3_COMPAT_CHIPS, patch_xnu_m3_ahcr_nops,
                              FC_XNU_PMCR1_EL12_LINKED, FC_XNU_PMCR1_EL1_WORD,
                              FC_XNU_PMCR1_EL12_WORD, patch_xnu_pmcr1_bank_collapse,
                              ABSENT_REGION, emit_memory_map_regions,
                              FC_XNU_DOCKCHANNEL_UART_IPA,
                              FC_XNU_DOCKCHANNEL_UART_FAR,
                              FC_XNU_DOCKCHANNEL_CONFIG_IPA,
                              FC_XNU_DOCKCHANNEL_RX8_IPA,
                              xnu_dockchannel_uart_mapping,
                              xnu_dockchannel_uart_catalog,
                              match_xnu_dockchannel_uart,
                              FC_XNU_PANIC_CARVEOUT_IPA,
                              FC_XNU_PANIC_CARVEOUT_SIZE,
                              xnu_panic_carveout_contract,
                              FC_XNU_SOCD_IPA, FC_XNU_SOCD_SIZE,
                              FC_XNU_SOCD_FAR, FC_XNU_SOCD_ESR,
                              xnu_socd_trace_contract)
from sptm_entry_probe import FC_XNU_PPERM_SITES, patch_xnu_pperm_guest_window
from sptm_entry_probe import restore_xnu_pperm_guest_window
from sptm_entry_probe import (TpidrGl2FastShadow,
                              audit_and_disable_tpidr_gl2_fast_shadow,
                              Vel2StepFilter)


class FastShadowProxy:
    def __init__(self):
        self.state = dict(enabled=False, tag_base=0, shadow=0,
                          reads=0, writes=0, forwarded=0)
        self.calls = []

    def hv_vel2_tpidr_gl2_shadow_enable(self, tag_base, initial_value):
        self.calls.append(('enable', tag_base, initial_value))
        self.state.update(enabled=True, tag_base=tag_base, shadow=initial_value,
                          reads=0, writes=0, forwarded=0)

    def hv_vel2_tpidr_gl2_shadow_status(self):
        self.calls.append(('status',))
        return dict(self.state)

    def hv_vel2_tpidr_gl2_shadow_disable(self):
        self.calls.append(('disable',))
        self.state['enabled'] = False


class TpidrGl2FastShadowTests(unittest.TestCase):
    def test_strict_adapter_preflight_enable_audit_and_disable(self):
        proxy = FastShadowProxy()
        adapter = TpidrGl2FastShadow(proxy)
        preflight = adapter.prepare()
        self.assertFalse(preflight['after']['enabled'])
        enabled = adapter.enable(0x9140, 0xfffffe0007106200)
        self.assertEqual((enabled['tag_base'], enabled['shadow']),
                         (0x9140, 0xfffffe0007106200))
        proxy.state.update(shadow=0x1234, reads=248, writes=1)
        host_shadow = {'tpidr': 0}
        result, errors = audit_and_disable_tpidr_gl2_fast_shadow(
            adapter, host_shadow, 'tpidr')
        self.assertEqual(errors, [])
        self.assertEqual(host_shadow['tpidr'], 0x1234)
        self.assertEqual(result['stop_audit']['reads'], 248)
        self.assertEqual(result['stop_audit']['writes'], 1)
        self.assertTrue(result['disabled_at_teardown'])
        self.assertFalse(result['disable_status']['enabled'])


class StepFilterProxy:
    def __init__(self):
        self.calls = []
        self.state = dict(
            active=False, status=0, steps=0, first_pc=0, last_pc=0,
            previous_pc=0, range0_hits=0, range1_hits=0,
            range_switches=0, terminal_pc=0, max_steps=0,
            range0_start=0, range0_end=0, range1_start=0, range1_end=0,
            expected_first_pc=0)

    def hv_vel2_step_filter_enable(self, range0_start, range0_end,
                                   range1_start, range1_end, terminal_pc,
                                   max_steps, expected_first_pc):
        self.calls.append(('enable', range0_start, range0_end,
                           range1_start, range1_end, terminal_pc,
                           max_steps, expected_first_pc))
        self.state.update(
            active=True, status=1, steps=0, first_pc=0, last_pc=0,
            previous_pc=0, range0_hits=0, range1_hits=0,
            range_switches=0, terminal_pc=terminal_pc,
            max_steps=max_steps, range0_start=range0_start,
            range0_end=range0_end, range1_start=range1_start,
            range1_end=range1_end, expected_first_pc=expected_first_pc)

    def hv_vel2_step_filter_status(self):
        self.calls.append(('status',))
        return dict(self.state)

    def hv_vel2_step_filter_disable(self):
        self.calls.append(('disable',))
        self.state.update(active=False, status=0)


class Vel2StepFilterTests(unittest.TestCase):
    def test_preflight_enable_terminal_audit_and_disable(self):
        proxy = StepFilterProxy()
        adapter = Vel2StepFilter(proxy)
        self.assertFalse(adapter.prepare()['after']['active'])
        enabled = adapter.enable((0x1000, 0x1100), (0x2000, 0x2100),
                                 0x3000, 4096, 0x1004)
        self.assertTrue(enabled['active'])
        proxy.state.update(active=False, status=Vel2StepFilter.TERMINAL,
                           steps=123, first_pc=0x1004, last_pc=0x3000,
                           previous_pc=0x2004, range0_hits=100,
                           range1_hits=23, range_switches=2)
        teardown = adapter.disable()
        self.assertEqual(teardown['before']['status'],
                         Vel2StepFilter.TERMINAL)
        self.assertEqual(teardown['before']['steps'], 123)
        self.assertEqual(teardown['after']['status'], 0)

    def test_missing_schema_or_readback_mismatch_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'proxy API unavailable'):
            Vel2StepFilter(SimpleNamespace())
        proxy = StepFilterProxy()
        adapter = Vel2StepFilter(proxy)
        proxy.hv_vel2_step_filter_status = lambda: {'active': False}
        with self.assertRaisesRegex(RuntimeError, 'status missing'):
            adapter.prepare()
        proxy = StepFilterProxy()
        adapter = Vel2StepFilter(proxy)
        original = proxy.hv_vel2_step_filter_status
        def wrong_range():
            status = original()
            status['range1_end'] ^= 4
            return status
        proxy.hv_vel2_step_filter_status = wrong_range
        with self.assertRaisesRegex(RuntimeError, 'readback mismatch'):
            adapter.enable((0x1000, 0x1100), (0x2000, 0x2100),
                           0x3000, 4096, 0x1004)
        self.assertIn(('disable',), proxy.calls)
        self.assertFalse(proxy.state['active'])

class TpidrGl2FastShadowFailureTests(unittest.TestCase):
    def test_missing_or_malformed_proxy_api_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'proxy API unavailable'):
            TpidrGl2FastShadow(SimpleNamespace())
        proxy = FastShadowProxy()
        adapter = TpidrGl2FastShadow(proxy)
        proxy.hv_vel2_tpidr_gl2_shadow_status = lambda: {'enabled': False}
        with self.assertRaisesRegex(RuntimeError, 'status missing'):
            adapter.prepare()

    def test_enable_readback_mismatch_forces_disable(self):
        proxy = FastShadowProxy()
        adapter = TpidrGl2FastShadow(proxy)
        original_status = proxy.hv_vel2_tpidr_gl2_shadow_status
        calls = 0
        def mismatched_status():
            nonlocal calls
            calls += 1
            result = original_status()
            if calls == 1:
                result['shadow'] ^= 1
            return result
        proxy.hv_vel2_tpidr_gl2_shadow_status = mismatched_status
        with self.assertRaisesRegex(RuntimeError, 'readback mismatch'):
            adapter.enable(0x9140, 0x1234)
        self.assertIn(('disable',), proxy.calls)
        self.assertFalse(proxy.state['enabled'])

    def test_teardown_attempts_disable_when_stop_audit_fails(self):
        proxy = FastShadowProxy()
        adapter = TpidrGl2FastShadow(proxy)
        adapter.enable(0x9140, 0x1234)
        calls = 0
        original_status = proxy.hv_vel2_tpidr_gl2_shadow_status
        def one_failed_status():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError('audit unavailable')
            return original_status()
        proxy.hv_vel2_tpidr_gl2_shadow_status = one_failed_status
        result, errors = audit_and_disable_tpidr_gl2_fast_shadow(
            adapter, {}, 'tpidr')
        self.assertIn('stop audit failed', errors[0])
        self.assertTrue(result['disabled_at_teardown'])
        self.assertFalse(proxy.state['enabled'])

    def test_teardown_before_activation_does_not_replace_host_shadow(self):
        proxy = FastShadowProxy()
        adapter = TpidrGl2FastShadow(proxy)
        host_shadow = {'tpidr': 0xfeed}
        result, errors = audit_and_disable_tpidr_gl2_fast_shadow(
            adapter, host_shadow, 'tpidr', synchronize=False)
        self.assertEqual(errors, [])
        self.assertEqual(host_shadow['tpidr'], 0xfeed)
        self.assertFalse(result['host_shadow_synchronized'])
        self.assertTrue(result['disabled_at_teardown'])


class MemoryMapFixture:
    def __init__(self, names=()):
        object.__setattr__(self, '_types', {})
        object.__setattr__(self, '_properties', {name: (99, 99) for name in names})

    def __setattr__(self, name, value):
        if name.startswith('_'):
            object.__setattr__(self, name, value)
        else:
            self._properties[name] = value


class MemoryMapEmissionTests(unittest.TestCase):
    def test_panic_carveout_contract_is_exact_and_page_aligned(self):
        result = xnu_panic_carveout_contract(
            (FC_XNU_PANIC_CARVEOUT_IPA, FC_XNU_PANIC_CARVEOUT_SIZE),
            FC_XNU_PANIC_CARVEOUT_SIZE)
        self.assertEqual(result['pages'], 98)
        for region, size in (((FC_XNU_PANIC_CARVEOUT_IPA + 0x4000,
                               FC_XNU_PANIC_CARVEOUT_SIZE), FC_XNU_PANIC_CARVEOUT_SIZE),
                             ((FC_XNU_PANIC_CARVEOUT_IPA,
                               FC_XNU_PANIC_CARVEOUT_SIZE), 0x4000)):
            with self.assertRaises(ValueError):
                xnu_panic_carveout_contract(region, size)

    def test_exact_dockchannel_uart_mapping_records_page_granularity(self):
        result = xnu_dockchannel_uart_mapping(
            FC_XNU_DOCKCHANNEL_UART_IPA, 0x1000, ['aapl,dock-channels'])
        self.assertEqual(result['ipa'], 0x2e410c000)
        self.assertEqual(result['size'], 0x4000)
        self.assertEqual(result['device_size'], 0x1000)
        self.assertEqual(result['extra_after'], 0x3000)

    def test_dockchannel_uart_mapping_rejects_nonmatching_inputs(self):
        for args in ((0x2e4108000, 0x1000, ['aapl,dock-channels']),
                     (FC_XNU_DOCKCHANNEL_UART_IPA, 0x4000, ['aapl,dock-channels']),
                     (FC_XNU_DOCKCHANNEL_UART_IPA, 0x1000, ['not-uart'])):
            with self.assertRaises(ValueError):
                xnu_dockchannel_uart_mapping(*args)

    def test_dockchannel_catalog_discriminates_same_pc_by_esr_and_far(self):
        catalog = xnu_dockchannel_uart_catalog(
            (FC_XNU_DOCKCHANNEL_CONFIG_IPA, 0x10000),
            (FC_XNU_DOCKCHANNEL_UART_IPA, 0x1000), ['aapl,dock-channels'])
        runtime_entry = 0xfffffe002bfb0000
        pc = 0xfffffe002b6b6fac
        irq = SimpleNamespace(elr=pc, esr=0x93960006, far=FC_XNU_DOCKCHANNEL_UART_FAR)
        rx8 = SimpleNamespace(elr=pc, esr=0x93960007, far=0xfffffe003a00c01c)
        crossed = SimpleNamespace(elr=pc, esr=irq.esr, far=rx8.far)
        self.assertEqual(match_xnu_dockchannel_uart(irq, runtime_entry, catalog)['name'], 'irq')
        self.assertEqual(match_xnu_dockchannel_uart(rx8, runtime_entry, catalog)['name'],
                         'data-rx8-final-page')
        self.assertIsNone(match_xnu_dockchannel_uart(crossed, runtime_entry, catalog))

    def test_absent_auxkc_retains_sentinel_without_changing_other_markers(self):
        stale_aux = ('AuxKC', 'AuxKC-bx', 'AuxKC-entry', 'AuxKC-rm',
                     'AuxKC-rs', 'AuxKC-virt')
        mmap = MemoryMapFixture(stale_aux + ('CL4-bx',))
        layout = {'regions': {
            'AuxKC-ro': [0x4000, 0],
            'AuxKC-rx': [0x4000, 0],
            'AuxKC-rw': [0x4000, 0],
            'AuxKC-le': [0x4000, 0],
            'CL4-rx': [0x9000, 0],
            'BootKC-rx': [0x4000, 0x8000],
        }}
        report = emit_memory_map_regions(mmap, layout, 0x100000, tuple_type=object)
        for name in stale_aux + ('AuxKC-ro', 'AuxKC-rx', 'AuxKC-rw', 'AuxKC-le'):
            self.assertEqual(mmap._properties[name], ABSENT_REGION)
            self.assertEqual(report['entries'][name], list(ABSENT_REGION))
        self.assertEqual(mmap._properties['BootKC-rx'], (0x104000, 0x8000))
        self.assertEqual(mmap._properties['CL4-rx'], (0x109000, 0))
        self.assertEqual(mmap._properties['CL4-bx'], (0x100000, 0))

    def test_populated_auxkc_keeps_planned_physical_range(self):
        mmap = MemoryMapFixture()
        layout = {'regions': {'AuxKC-ro': [0x4000, 0x8000]}}
        emit_memory_map_regions(mmap, layout, 0x100000, tuple_type=object)
        self.assertEqual(mmap._properties['AuxKC-ro'], (0x104000, 0x8000))


class XnuCompatibilityPatchTests(unittest.TestCase):
    def test_pperm_interrupted_cleanup_restores_full_guest_raw_only(self):
        class Access:
            def __init__(self): self.value=0; self.calls=[]
            def msr(self, reg, value): self.calls.append(('msr',reg,value)); self.value=value
            def mrs(self, reg): self.calls.append(('mrs',reg)); return self.value
        access=Access(); prior=0x2020a52a302abae6
        result=restore_xnu_pperm_guest_window(
            access, 'PPERM_EL12', {'previous':prior,'modified':True}, True)
        self.assertTrue(result['verified']); self.assertEqual(result['readback'],prior)
        self.assertEqual(access.calls,[('msr','PPERM_EL12',prior),('mrs','PPERM_EL12')])
        class Forbidden:
            def __getattr__(self,name): raise AssertionError('unexpected bank I/O')
        result=restore_xnu_pperm_guest_window(
            Forbidden(),'PPERM_EL12',{'previous':prior,'modified':True},False)
        self.assertFalse(result['attempted'])
    def test_pperm_window_rewrites_only_four_exact_sites_to_distinct_hvcs(self):
        lo = min(site[0] for site in FC_XNU_PPERM_SITES)
        hi = max(site[0] for site in FC_XNU_PPERM_SITES) + 4
        segment = {'va': lo, 'filesize': hi-lo}
        chunk = bytearray(hi-lo)
        for pc, word, _, _ in FC_XNU_PPERM_SITES:
            struct.pack_into('<I', chunk, pc-lo, word)
        patched, records = patch_xnu_pperm_guest_window(bytes(chunk), segment, True)
        self.assertEqual(len(records), 4)
        for pc, _, tag, _ in FC_XNU_PPERM_SITES:
            self.assertEqual(struct.unpack_from('<I', patched, pc-lo)[0],
                             0xd4000002 | (tag << 5))
        changed = bytearray(chunk); changed[0] ^= 1
        with self.assertRaises(ValueError):
            patch_xnu_pperm_guest_window(bytes(changed), segment, True)

    def test_attempt66_archived_adt_drives_production_socd_contract(self):
        root = Path(__file__).resolve().parents[1]
        archived = root/'artifacts/runs/observe-sprr/attempt-66/runs/1755ffa6-2b38-4d70-9db0-7716b2838a26/inputs/host-device-tree.adt'
        if not archived.exists():
            self.skipTest('attempt-66 archived ADT unavailable')
        checkout = Path(os.environ['VEL2_CHECKOUT'])/'proxyclient'
        sys.path.insert(0, str(checkout))
        try:
            from m1n1.adt import load_adt
            node = load_adt(archived.read_bytes())['socd-trace-ram']
            result = xnu_socd_trace_contract(
                node.get_reg(0), node._properties.get('device_type'))
        finally:
            sys.path.remove(str(checkout))
        self.assertEqual(result['source'], FC_XNU_SOCD_IPA)
        self.assertEqual(result['source_size'], FC_XNU_SOCD_SIZE)
        self.assertEqual((result['zero_prefix'], result['zero_suffix']),
                         (0x1014, 0x2c50))

    def test_exact_pinned_instruction_is_replaced_and_reported(self):
        self.assertEqual(FC_XNU_AGT_ESR, 0x5a0060b8)  # attempt-55 hardware syndrome
        chunk = struct.pack('<3I', 0xd503201f, FC_XNU_AGT_WORD, 0xd5033fdf)
        segment = {'va': FC_XNU_AGT_LINKED - 4}
        patched, record = patch_xnu_agtcnt_rdir(chunk, segment, True)
        self.assertEqual(struct.unpack_from('<I', patched, 4)[0],
                         0xd4000002 | (FC_XNU_AGT_HVC << 5))
        self.assertEqual(patched[:4] + patched[8:], chunk[:4] + chunk[8:])
        self.assertEqual(record['allowed_value'], 3)

    def test_disabled_or_changed_source_never_patches(self):
        chunk = struct.pack('<I', FC_XNU_AGT_WORD)
        self.assertEqual(patch_xnu_agtcnt_rdir(
            chunk, {'va': FC_XNU_AGT_LINKED}, False), (chunk, None))
        with self.assertRaises(ValueError):
            patch_xnu_agtcnt_rdir(struct.pack('<I', 0xd503201f),
                                  {'va': FC_XNU_AGT_LINKED}, True)

    def test_restore_writes_saved_value_and_verifies_readback(self):
        class Registers:
            def __init__(self):
                self.value = 3
                self.calls = []
            def msr(self, register, value):
                self.calls.append(('msr', register, value))
                self.value = value
            def mrs(self, register):
                self.calls.append(('mrs', register))
                return self.value
        registers = Registers()
        result = restore_xnu_agtcnt_rdir(registers, 'reg', 1, True)
        self.assertEqual(registers.calls, [('msr', 'reg', 1), ('mrs', 'reg')])
        self.assertEqual(result, {'register': 'AGTCNTRDIR_EL12', 'attempted': True,
                                  'restored_value': 1, 'readback': 1, 'verified': True})

    def test_restore_does_no_io_when_guest_did_not_return(self):
        class Forbidden:
            def __getattr__(self, name):
                raise AssertionError('register I/O attempted: ' + name)
        self.assertEqual(restore_xnu_agtcnt_rdir(Forbidden(), 'reg', 1, False), {
            'register': 'AGTCNTRDIR_EL12', 'attempted': False,
            'reason': 'guest-did-not-return'})

    def test_restore_cntp_ctl_writes_only_saved_guest_bank_and_verifies(self):
        class Registers:
            def __init__(self):
                self.value = 2
                self.calls = []
            def msr(self, register, value):
                self.calls.append(('msr', register, value))
                self.value = value
            def mrs(self, register):
                self.calls.append(('mrs', register))
                return self.value
        registers = Registers()
        result = restore_xnu_cntp_ctl(registers, 'guest-el02', 5, True)
        self.assertEqual(registers.calls,
                         [('msr', 'guest-el02', 1), ('mrs', 'guest-el02')])
        self.assertEqual(result, {'register': 'CNTP_CTL_EL02', 'attempted': True,
                                  'observed_previous': 5, 'restored_value': 1, 'readback_raw': 1,
                                  'readback': 1, 'verified': True,
                                  'host_timer_bank_touched': False})
        class Forbidden:
            def __getattr__(self, name):
                raise AssertionError('register I/O attempted: ' + name)
        self.assertEqual(restore_xnu_cntp_ctl(Forbidden(), 'guest-el02', 5, False), {
            'register': 'CNTP_CTL_EL02', 'attempted': False,
            'reason': 'guest-did-not-return'})

    def test_restore_apple_timer_preserves_and_verifies_full_raw_value(self):
        class Registers:
            def __init__(self):
                self.value = 2
                self.calls = []
            def msr(self, register, value):
                self.calls.append(('msr', register, value))
                self.value = value
            def mrs(self, register):
                self.calls.append(('mrs', register))
                return self.value
        registers = Registers()
        result = restore_xnu_apple_physical_timer(registers, 'candidate', 6, True)
        self.assertEqual(registers.calls,
                         [('msr', 'candidate', 6), ('mrs', 'candidate')])
        self.assertEqual((result['restored_value_raw'], result['readback_raw']), (6, 6))
        self.assertTrue(result['verified_exact'])
        self.assertFalse(result['routing_established'])
        self.assertFalse(result['physical_s3_1_bank_touched'])

    def test_explicit_m3_ahcr_compat_nops_only_exact_pinned_pair(self):
        base = FC_XNU_AHCR_NOP_SITES[0][0]
        chunk = bytearray(12)
        for linked, word in FC_XNU_AHCR_NOP_SITES:
            struct.pack_into('<I', chunk, linked-base, word)
        patched, record = patch_xnu_m3_ahcr_nops(
            bytes(chunk), {'va': base}, True, FC_XNU_M3_COMPAT_CHIPS[0])
        self.assertEqual(patched[4:8], bytes(chunk[4:8]))
        for linked, word in FC_XNU_AHCR_NOP_SITES:
            self.assertEqual(struct.unpack_from('<I', patched, linked-base)[0], 0xd503201f)
        self.assertFalse(record['hardware_effects_emulated'])
        self.assertEqual(record['mode'], 'diagnostic-upstream-nop')

    def test_m3_ahcr_compat_rejects_source_drift_and_other_chips(self):
        base = FC_XNU_AHCR_NOP_SITES[0][0]
        with self.assertRaises(ValueError):
            patch_xnu_m3_ahcr_nops(bytes(12), {'va': base}, True,
                                   FC_XNU_M3_COMPAT_CHIPS[0])
        with self.assertRaises(ValueError):
            patch_xnu_m3_ahcr_nops(bytes(12), {'va': base}, True, 0xdead)

    def test_pmcr1_el12_rewrite_requires_identical_preceding_el1_write(self):
        base = FC_XNU_PMCR1_EL12_LINKED - 4
        chunk = struct.pack('<3I', FC_XNU_PMCR1_EL1_WORD,
                            FC_XNU_PMCR1_EL12_WORD, 0xd5033fdf)
        patched, record = patch_xnu_pmcr1_bank_collapse(chunk, {'va': base}, True)
        self.assertEqual(struct.unpack_from('<I', patched, 0)[0], FC_XNU_PMCR1_EL1_WORD)
        self.assertEqual(struct.unpack_from('<I', patched, 4)[0], FC_XNU_PMCR1_EL1_WORD)
        self.assertEqual(patched[8:], chunk[8:])
        self.assertFalse(record['nested_guest_pmu_supported'])
        self.assertFalse(record['host_register_io'])
        for changed in (struct.pack('<3I', 0xd503201f, FC_XNU_PMCR1_EL12_WORD, 0),
                        struct.pack('<3I', FC_XNU_PMCR1_EL1_WORD, 0xd503201f, 0)):
            with self.assertRaises(ValueError):
                patch_xnu_pmcr1_bank_collapse(changed, {'va': base}, True)



@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class ProbeControlTests(unittest.TestCase):
    def setUp(self):
        self.tables = Tables()
        self.endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True)
        self.s = self.endpoint.sysreg

    def access(self, register, **kwargs):
        return self.tables.access(self.endpoint, register, **kwargs)

    def assert_handled(self):
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertNotIn('error', self.endpoint.report)
        self.assertEqual(self.endpoint.hardware.attempts, [])

    def assert_stopped_unchanged(self, before, after, reason):
        self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], reason)
        self.assertFalse(any(c[0] in ('msr', 'barrier') for c in self.endpoint.hardware.calls))
        self.assertEqual(self.endpoint.hardware.attempts, [])

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

    def _txm_context_entry_gate(self, prefix=False, claim=False, metadata=False,
                                x18_branch=False, outbound=False, handler=None, **changes):
        ns = self.endpoint.namespace
        ns['a'].free_run = ns['a'].real_guarded = ns['a'].native_handoff = True
        ns['a'].xnu_run = True
        ns['a'].xnu_txm_context_entry_one_step = not (
            prefix or claim or metadata or x18_branch or outbound or handler)
        ns['a'].xnu_txm_context_entry_register_prefix = prefix
        ns['a'].xnu_txm_context_stack_claim_one_step = claim
        ns['a'].xnu_txm_context_stack_metadata_init = metadata
        ns['a'].xnu_txm_context_x18_branch_one_step = x18_branch
        ns['a'].xnu_txm_context_outbound_branch_one_step = outbound
        ns['a'].xnu_txm_handler_boundary = handler
        ns['handoff_state'].update(active=False, native=True)
        ns['report']['handoff'] = dict(image='kernelcache', target_pc='0xfffffe002bfb0000',
            instructions_executed=True)
        target = ns['FC_XNU_TXM_CONTEXT_TARGET']
        stack = ns['FC_XNU_TXM_CONTEXT_STACK']
        source_offset = ns['FC_XNU_TXM_CONTEXT_ERET_PC'] - 4 - ns['FC_IMAGE_BASE']
        sptm_source = bytearray(source_offset + 4)
        struct.pack_into('<I', sptm_source, source_offset, 0xd69f03e0)
        txm_fileoff = 0x80
        post_claim_source = changes.get(
            'post_claim_source', ns['FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES'])
        x18_tail_source = changes.get(
            'x18_tail_source', ns['FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES'][4:])
        context_source = (b'\x1f\x00\x00\x91'
            + ns['FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES']
            + struct.pack('<I', ns['FC_XNU_TXM_CONTEXT_CASB_WORD'])
            + post_claim_source + x18_tail_source)
        txm_segment_va = ns['FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED']
        context_source_offset = (txm_fileoff
            + int(ns['FC_XNU_TXM_CONTEXT_LINKED'], 16) - txm_segment_va)
        handler_source = (ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES']
            + bytes.fromhex('e80f00f93a0200d0'))
        validator_source = handler_source + bytes.fromhex(
            '5a431a9148034039c8000035e963009128c572f2c10000540008805202000014'
            '0014805201008052a4faff973f1140b16300005440088052fbffff17f30300aa'
            'e80300f908008852000d084ee083803ce0030091a105805236070094')
        helper_source_offset = (txm_fileoff + ns['FC_XNU_TXM_HANDLER_HELPER_LINKED']
            - txm_segment_va)
        txm_source = bytearray(max(context_source_offset + len(context_source),
            helper_source_offset + len(ns['FC_XNU_TXM_HANDLER_HELPER_BYTES'])))
        supplied_handler_source = changes.get('outbound_target_source',
            validator_source if handler in (
                'validator-entry', 'validator-trace', 'response-trace',
                'cmd1-completion-trace')
            else handler_source if handler == 'local-setup'
            else ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES'])
        txm_source[txm_fileoff:txm_fileoff + len(supplied_handler_source)] = (
            supplied_handler_source)
        txm_source[helper_source_offset:helper_source_offset
                   + len(ns['FC_XNU_TXM_HANDLER_HELPER_BYTES'])] = changes.get(
            'handler_helper_source', ns['FC_XNU_TXM_HANDLER_HELPER_BYTES'])
        txm_source[context_source_offset:context_source_offset
                   + len(context_source)] = context_source
        txm_source = bytes(txm_source)
        ns['sources'] = {'sptm': bytes(sptm_source), 'txm': txm_source}
        ns['layout'] = {'images': {
            'sptm': {'segments': {'__TEXT_EXEC': {
                'fileoff': 0x4000, 'filesize': len(sptm_source) - 0x4000}}},
            'txm': {'segments': {'__TEXT_EXEC': {
                'fileoff': txm_fileoff,
                'va': txm_segment_va,
                'filesize': len(txm_source) - txm_fileoff}}}}}
        target_descriptor = 0x20000080 | 3
        stack_descriptor = 0x20004000 | 0x40 | 3
        outbound_page_pa = 0x22000000
        helper_page_pa = 0x22004000
        global_page_pa = 0x22008000
        response_page_pa = 0x2200c000
        for page_pa in (outbound_page_pa, helper_page_pa, global_page_pa,
                        response_page_pa):
            if page_pa not in self.tables.memory.pages:
                self.tables.memory.add_page(page_pa)
        outbound_pa = (outbound_page_pa
            + (ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET'] & (ns['PAGE'] - 1)))
        self.tables.memory.write(outbound_pa, changes.get('outbound_live_source',
            validator_source if handler in (
                'validator-entry', 'validator-trace', 'response-trace',
                'cmd1-completion-trace')
            else handler_source if handler == 'local-setup'
            else ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES']))
        helper_pa = (helper_page_pa
            + (ns['FC_XNU_TXM_HANDLER_HELPER'] & (ns['PAGE'] - 1)))
        self.tables.memory.write(helper_pa, changes.get('handler_helper_live_source',
            ns['FC_XNU_TXM_HANDLER_HELPER_BYTES']))
        global_pa = (global_page_pa
            + (ns['FC_XNU_TXM_HANDLER_GLOBAL'] & (ns['PAGE'] - 1)))
        self.tables.memory.write(global_pa, changes.get('handler_global_source', b'\x00'))
        response_pa = (response_page_pa
            + (ns['FC_XNU_TXM_HANDLER_RESPONSE_POINTER'] & (ns['PAGE'] - 1)))
        self.tables.memory.write(response_pa, struct.pack('<Q', 0x123456789abcdef0))
        ns['classify_entry'] = lambda *args: dict(image='txm', segment='__TEXT_EXEC',
            target_pc=hex(target), pa=hex(0x20000000),
            linked_pc=ns['FC_XNU_TXM_CONTEXT_LINKED'], entry_matches=False,
            bytes_match=True, bytes_hex=ns['FC_XNU_TXM_CONTEXT_BYTES'].hex(),
            instructions_executed=False)
        stack_pa = changes.get('stack_pa', 0x20004000)
        def fake_translate(va, *_):
            if va == target:
                return dict(pa=0x20000000, level=3, descriptor=target_descriptor,
                    access_flag=True, read_only=True, user_access=False,
                    pxn=False, uxn=False)
            if va == ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET']:
                return dict(pa=outbound_pa, level=3, descriptor=target_descriptor,
                    access_flag=True, read_only=True, user_access=False,
                    pxn=False, uxn=False)
            if va == ns['FC_XNU_TXM_HANDLER_HELPER']:
                return dict(pa=helper_pa, level=3, descriptor=target_descriptor,
                    access_flag=True, read_only=True, user_access=False,
                    pxn=False, uxn=False)
            if va == ns['FC_XNU_TXM_HANDLER_GLOBAL']:
                return dict(pa=global_pa, level=3, descriptor=stack_descriptor,
                    access_flag=True, read_only=False, user_access=True,
                    pxn=True, uxn=True)
            if va == ns['FC_XNU_TXM_HANDLER_RESPONSE_POINTER']:
                return dict(pa=response_pa, level=3, descriptor=stack_descriptor,
                    access_flag=True, read_only=False, user_access=True,
                    pxn=True, uxn=True)
            return dict(pa=stack_pa + va - stack, level=3,
                descriptor=stack_descriptor, access_flag=True, read_only=False,
                user_access=True, pxn=False, uxn=False)
        ns['translate'] = fake_translate
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1:self.s.ELR_EL12,
            self.s.SPSR_GL1:self.s.SPSR_EL12,
            self.s.SPRR_PPERM_EL1:self.s.SPRR_PPERM_EL12,
            self.s.SPRR_UPERM_EL0:self.s.SPRR_UPERM_EL02})
        self.endpoint.hardware.values[self.s.ELR_EL12] = changes.get('target', target)
        self.endpoint.hardware.values[self.s.SPSR_EL12] = changes.get('target_spsr', 0x13c0)
        self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12] = 0x2020a52a302abae6
        self.endpoint.hardware.values[self.s.SPRR_UPERM_EL02] = 0x8004000c8080
        self.endpoint.hardware.values[self.s.MAIR_EL12] = 0xff
        self.endpoint.hardware.values[self.s.TTBR0_EL12] = self.tables.low
        self.endpoint.hardware.values[self.s.TTBR1_EL12] = self.tables.high
        event = self.tables.event(0x5a004800)
        event['pc'] = changes.get('pc', ns['FC_XNU_TXM_CONTEXT_ERET_PC'])
        event['spsr'] = changes.get('caller_spsr', 0x800013c5)
        event['regs'][0] = changes.get('x0', stack)
        event['regs'][3] = changes.get('x3', 0)
        event['regs'][16] = changes.get('x16', ns['FC_XNU_TXM_CONTEXT_SELECTOR'])
        event['regs'][18] = changes.get('x18', ns['FC_XNU_TXM_CONTEXT_X18'])
        return self.endpoint.feed(event)

    def test_txm_context_entry_gate_executes_exactly_one_mov_sp(self):
        ns = self.endpoint.namespace
        _, armed = self._txm_context_entry_gate()
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(armed.elr, ns['FC_XNU_TXM_CONTEXT_TARGET'])
        self.assertEqual(armed.spsr.SS, 1)
        self.assertTrue(ns['txm_context_step_state']['active'])
        self.assertTrue(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)
        self.assertNotIn('stop_reason', self.endpoint.report)
        self.assertTrue(all(self.endpoint.report['xnu_txm_context_entry_one_step']
                            ['checks'].values()))
        step = self.tables.event(0xcb000022)
        step['pc'] = ns['FC_XNU_TXM_CONTEXT_TARGET'] + 4
        step['spsr'] = 0x13c0
        step['regs'][0] = ns['FC_XNU_TXM_CONTEXT_STACK']
        step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
        step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
        step['sp'][0] = ns['FC_XNU_TXM_CONTEXT_STACK']
        self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-one-step-complete')
        result = self.endpoint.report['xnu_txm_context_entry_one_step']['result']
        self.assertTrue(result['exactly_one_instruction'])
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)

    def test_txm_context_entry_gate_rejects_caller_mismatch_without_mutation(self):
        before, after = self._txm_context_entry_gate(x16=0)
        self.assertEqual(self.endpoint.codec.build(after), self.endpoint.codec.build(before))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        self.assertFalse(self.endpoint.namespace['txm_context_step_state']['active'])
        self.assertFalse(any(call[0] == 'msr' and call[1] == self.s.MDSCR_EL1
                             for call in self.endpoint.hardware.calls))
        self.assertFalse(self.endpoint.report['xnu_txm_context_entry_one_step']
                         ['checks']['caller_selector_x16'])

    def test_txm_context_entry_one_step_mismatch_stops_without_second_resume(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate()
        step = self.tables.event(0xcb000022)
        step['pc'] = ns['FC_XNU_TXM_CONTEXT_TARGET'] + 8
        step['spsr'] = 0x13c0
        step['regs'][0] = ns['FC_XNU_TXM_CONTEXT_STACK']
        step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
        step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
        step['sp'][0] = ns['FC_XNU_TXM_CONTEXT_STACK']
        self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-one-step-mismatch')
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_txm_context_entry_register_prefix_stops_before_casb(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(prefix=True)
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 15)
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            self.endpoint.feed(step)
            expected_reply = (self.endpoint.EXC_RET.EXIT_GUEST if index == len(states) - 1
                              else self.endpoint.EXC_RET.HANDLED)
            self.assertEqual(self.endpoint.replies[-1], int(expected_reply))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-register-prefix-complete')
        prefix = self.endpoint.report['xnu_txm_context_entry_register_prefix']
        self.assertTrue(prefix['complete'])
        self.assertEqual(len(prefix['steps']), 15)
        self.assertEqual(prefix['result']['observed_pc'], '0xfffffe0017031084')

    def test_txm_context_stack_claim_verifies_single_zero_to_one_casb(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(claim=True)
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 16)
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == len(states) - 1:
                self.tables.memory.write(ns['txm_context_step_state']['first_touch_pa'], b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-stack-claim-one-step-complete')
        claim = self.endpoint.report['xnu_txm_context_stack_claim_one_step']
        self.assertEqual(claim['claim_before_hex'], '00')
        self.assertEqual(claim['result']['claim_after_hex'], '01')
        self.assertTrue(claim['result']['checks']['stack_claimed_zero_to_one'])

    def test_txm_context_stack_metadata_init_stops_before_x18_branch(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(metadata=True)
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 21)
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-stack-metadata-init-complete')
        metadata = self.endpoint.report['xnu_txm_context_stack_metadata_init']
        self.assertTrue(metadata['complete'])
        self.assertEqual(metadata['metadata_before_hex'], {
            'state': '00', 'zero_word': '00000000',
            'claim': '00', 'zero_byte': '00'})
        self.assertEqual(metadata['result']['observed_pc'], '0xfffffe00170310a8')
        self.assertEqual(metadata['result']['claim_after_hex'], '01')
        self.assertEqual(metadata['result']['metadata_page_diff_offsets'],
                         ['0x3c00', '0x3c58'])
        self.assertTrue(metadata['result']['checks']['metadata_final_values'])
        self.assertTrue(metadata['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_context_stack_metadata_init_rejects_unexpected_page_write(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(metadata=True)
        states = ns['txm_context_step_state']['expected_states']
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
                self.tables.memory.write(frame_pa + 0x20, b'\xff')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-stack-metadata-init-mismatch')
        self.assertFalse(self.endpoint.report['xnu_txm_context_stack_metadata_init']
                         ['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_context_stack_metadata_init_never_reads_unowned_stack_leaf(self):
        ns = self.endpoint.namespace
        outside = self.tables.memory.base + self.tables.memory.size
        self._txm_context_entry_gate(metadata=True, stack_pa=outside)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        gate = self.endpoint.report['xnu_txm_context_stack_metadata_init']
        self.assertFalse(gate['checks']['stack_mapping'])
        self.assertIsNone(gate['metadata_page_before_sha256'])
        self.assertFalse(any(address == outside and size == ns['PAGE']
                             for address, size in self.tables.memory.reads))

    def test_txm_context_stack_metadata_init_rejects_changed_source_before_resume(self):
        ns = self.endpoint.namespace
        changed = bytearray(ns['FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES'])
        changed[-1] ^= 1
        self._txm_context_entry_gate(metadata=True,
                                     post_claim_source=bytes(changed))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        gate = self.endpoint.report['xnu_txm_context_stack_metadata_init']
        self.assertFalse(gate['checks']['post_claim_source'])
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)

    def test_txm_context_stack_metadata_init_rejects_wrong_cbz_path(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(metadata=True)
        states = ns['txm_context_step_state']['expected_states']
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states[:17]):
            step = self.tables.event(0xcb000022)
            step['pc'] = (ns['FC_XNU_TXM_CONTEXT_TARGET'] + 0x50
                          if index == 16 else expected['pc'])
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-stack-metadata-init-mismatch')
        self.assertFalse(self.endpoint.report['xnu_txm_context_stack_metadata_init']
                         ['result']['checks']['expected_pc'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_txm_context_stack_metadata_init_stops_if_claim_did_not_store(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(metadata=True)
        states = ns['txm_context_step_state']['expected_states']
        for expected in states[:16]:
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-stack-metadata-init-mismatch')
        result = self.endpoint.report['xnu_txm_context_stack_metadata_init']['result']
        self.assertFalse(result['checks']['memory_claim'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_txm_context_x18_branch_one_step_stops_before_target_branch(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(x18_branch=True)
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 22)
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-x18-branch-one-step-complete')
        branch = self.endpoint.report['xnu_txm_context_x18_branch_one_step']
        self.assertTrue(branch['complete'])
        self.assertTrue(branch['checks']['x18_branch_source'])
        self.assertEqual(branch['result']['observed_pc'], '0xfffffe00170310b8')
        self.assertEqual(branch['result']['extension_instructions'], 1)
        self.assertTrue(branch['result']['branch_taken'])
        self.assertTrue(branch['result']['fallthrough_svc_not_executed'])
        self.assertFalse(branch['result']['outbound_branch_executed'])
        self.assertEqual(branch['result']['metadata_page_diff_offsets'],
                         ['0x3c00', '0x3c58'])
        self.assertTrue(branch['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_context_x18_branch_rejects_changed_landing_word_before_resume(self):
        ns = self.endpoint.namespace
        changed = bytearray(ns['FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES'][4:])
        changed[-1] ^= 1
        self._txm_context_entry_gate(x18_branch=True,
                                     x18_tail_source=bytes(changed))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        branch = self.endpoint.report['xnu_txm_context_x18_branch_one_step']
        self.assertFalse(branch['checks']['x18_branch_source'])
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)

    def test_txm_context_x18_branch_rejects_svc_fallthrough(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(x18_branch=True)
        states = ns['txm_context_step_state']['expected_states']
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = (ns['FC_XNU_TXM_CONTEXT_TARGET'] + 0x70
                          if index == len(states) - 1 else expected['pc'])
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = (0 if index == len(states) - 1
                                else ns['FC_XNU_TXM_CONTEXT_X18'])
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-x18-branch-one-step-mismatch')
        result = self.endpoint.report['xnu_txm_context_x18_branch_one_step']['result']
        self.assertFalse(result['checks']['expected_pc'])
        self.assertFalse(result['checks']['x18_unchanged'])
        self.assertFalse(result['branch_taken'])
        self.assertIsNone(result['extension_instructions'])
        self.assertIsNone(result['outbound_branch_executed'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_txm_context_outbound_branch_stops_before_pacibsp(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(outbound=True)
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 23)
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-outbound-branch-one-step-complete')
        outbound = self.endpoint.report['xnu_txm_context_outbound_branch_one_step']
        self.assertTrue(outbound['complete'])
        self.assertTrue(outbound['checks']['outbound_target_source'])
        self.assertTrue(outbound['checks']['outbound_target_guarded_gl0_rx'])
        self.assertEqual(outbound['result']['observed_pc'], '0xfffffe001702edec')
        self.assertEqual(outbound['result']['extension_instructions'], 1)
        self.assertTrue(outbound['result']['outbound_branch_taken'])
        self.assertFalse(outbound['result']['pacibsp_executed'])
        self.assertTrue(outbound['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_context_outbound_branch_rejects_changed_target_source(self):
        ns = self.endpoint.namespace
        changed = bytearray(ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES'])
        changed[0] ^= 1
        self._txm_context_entry_gate(outbound=True,
                                     outbound_target_source=bytes(changed))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        outbound = self.endpoint.report['xnu_txm_context_outbound_branch_one_step']
        self.assertFalse(outbound['checks']['outbound_target_source'])
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)

    def test_txm_context_outbound_branch_rejects_changed_live_target(self):
        ns = self.endpoint.namespace
        changed = bytearray(ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES'])
        changed[4] ^= 1
        self._txm_context_entry_gate(outbound=True,
                                     outbound_live_source=bytes(changed))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        outbound = self.endpoint.report['xnu_txm_context_outbound_branch_one_step']
        self.assertFalse(outbound['checks']['outbound_target_live_bytes'])
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)

    def test_txm_handler_prologue_stops_before_first_stp(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(handler='prologue')
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 25)
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        signed_x30 = 0xa5a5a5a5a5a5a5a5
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index >= 23:
                step['regs'][30] = signed_x30
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-prologue-complete')
        prologue = self.endpoint.report['xnu_txm_handler_boundary']
        self.assertTrue(prologue['complete'])
        self.assertEqual(prologue['steps'][23]['captured_regs'],
                         {'x30': hex(signed_x30)})
        self.assertTrue(prologue['result']['checks']['captured_x30_unchanged'])
        self.assertEqual(prologue['result']['observed_pc'], '0xfffffe001702edf4')
        self.assertEqual(prologue['result']['observed_sp_el0'],
                         '0xfffffdf00018bb90')
        self.assertEqual(prologue['result']['extension_instructions'], 2)
        self.assertTrue(prologue['result']['pacibsp_executed'])
        self.assertEqual(prologue['result']['stack_allocation_bytes'], 0x70)
        self.assertFalse(prologue['result']['first_stp_executed'])
        self.assertTrue(prologue['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_handler_prologue_rejects_post_pac_x30_drift(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(handler='prologue')
        states = ns['txm_context_step_state']['expected_states']
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index >= 23:
                step['regs'][30] = 0x1111 + index
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-prologue-mismatch')
        result = self.endpoint.report['xnu_txm_handler_boundary']['result']
        self.assertFalse(result['checks']['captured_x30_unchanged'])
        self.assertIsNone(result['extension_instructions'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def _complete_txm_handler_boundary(self, boundary):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(handler=boundary)
        states = ns['txm_context_step_state']['expected_states']
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        entry_regs = [0x1000 + register for register in range(32)]
        entry_regs[0] = entry_regs[8] = entry_regs[10] = 1
        entry_regs[9] = 0
        entry_regs[16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
        entry_regs[18] = ns['FC_XNU_TXM_CONTEXT_X18']
        signed_x30 = 0xa5a5a5a5a5a5a5a5
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][:] = entry_regs
            if index >= 23:
                step['regs'][30] = signed_x30
            for register, source in expected.get('captured_reg_values', {}).items():
                step['regs'][register] = entry_regs[source]
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            memory = expected.get('memory', {})
            offsets = ns['txm_context_step_state']['metadata_offsets']
            for name, value_hex in memory.items():
                offset, _ = offsets[name]
                self.tables.memory.write(frame_pa + offset, bytes.fromhex(value_hex))
            save_pairs = ((26, 25), (24, 23), (22, 21), (20, 19), (29, 30))
            for pair_index, registers in enumerate(
                    save_pairs[:expected.get('saved_pairs', 0)]):
                values = [signed_x30 if register == 30 else entry_regs[register]
                          for register in registers]
                self.tables.memory.write(frame_pa - 0x70 + 0x20 + pair_index * 0x10,
                                         struct.pack('<QQ', *values))
            self.endpoint.feed(step)
        return states, self.endpoint.report['xnu_txm_handler_boundary']

    def test_txm_handler_register_saves_verify_exact_owned_page_writes(self):
        states, probe = self._complete_txm_handler_boundary('register-saves')
        self.assertEqual(len(states), 31)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-register-saves-complete')
        self.assertTrue(probe['complete'])
        self.assertEqual(probe['result']['extension_instructions'], 8)
        self.assertEqual(probe['result']['saved_register_pairs'], 5)
        self.assertTrue(probe['result']['first_stp_executed'])
        self.assertTrue(probe['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_handler_local_setup_roundtrips_helper_and_stores_marker(self):
        states, probe = self._complete_txm_handler_boundary('local-setup')
        self.assertEqual(len(states), 46)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-local-setup-complete')
        self.assertTrue(probe['complete'])
        self.assertEqual(probe['result']['extension_instructions'], 23)
        self.assertTrue(probe['result']['helper_roundtrip_executed'])
        self.assertTrue(probe['result']['local_marker_stored'])
        self.assertTrue(probe['result']['checks']['memory_local_marker'])
        self.assertTrue(probe['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_handler_validator_entry_gates_global_and_builds_tuple(self):
        states, probe = self._complete_txm_handler_boundary('validator-entry')
        self.assertEqual(len(states), 62)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-validator-entry-complete')
        self.assertTrue(probe['complete'])
        self.assertTrue(probe['checks']['handler_global_initial_zero'])
        self.assertEqual(probe['result']['extension_instructions'], 39)
        self.assertTrue(probe['result']['global_guard_zero'])
        self.assertTrue(probe['result']['validator_tuple_stored'])
        self.assertTrue(probe['result']['checks']['memory_validator_base'])
        self.assertTrue(probe['result']['checks']['memory_validator_sizes'])
        self.assertTrue(probe['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_handler_validator_trace_returns_expected_result(self):
        states, probe = self._complete_txm_handler_boundary('validator-trace')
        self.assertEqual(len(states), 63)
        ns = self.endpoint.namespace
        self.assertTrue(ns['txm_validator_trace_state']['active'])
        returned = self.tables.event(0xcb000022)
        returned['pc'] = ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET'] + 0xa4
        returned['spsr'] = 0x800013c0
        returned['sp'][0] = ns['FC_XNU_TXM_CONTEXT_STACK'] + ns['PAGE'] - 0x470
        returned['regs'][0] = 0x2d
        self.endpoint.feed(returned)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-validator-trace-complete')
        self.assertTrue(probe['complete'])
        self.assertTrue(probe['result']['validator_returned'])
        self.assertTrue(probe['result']['checks']['caller_frame_preserved'])
        self.assertEqual(probe['result']['validator_trace_steps'], 1)

    def test_txm_handler_response_trace_builds_descriptor_before_completion(self):
        _, probe = self._complete_txm_handler_boundary('response-trace')
        ns = self.endpoint.namespace
        state = ns['txm_validator_trace_state']
        returned = self.tables.event(0xcb000022)
        returned['pc'] = ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET'] + 0xa4
        returned['spsr'] = 0x600013c0
        returned['sp'][0] = state['expected_sp']
        returned['regs'][0] = 0x2d
        self.endpoint.feed(returned)
        self.assertEqual(state['phase'], 'response')
        frame_pa = state['metadata_frame_pa']
        self.tables.memory.write(frame_pa + 8, b'\x00' * 8)
        self.tables.memory.write(frame_pa + 0x18, struct.pack('<Q', 3))
        self.tables.memory.write(frame_pa + 0x20,
            struct.pack('<Q', state['response_pointer']))
        self.tables.memory.write(frame_pa + 0x28,
            struct.pack('<Q', ns['FC_XNU_TXM_HANDLER_GLOBAL'] + 4))
        self.tables.memory.write(frame_pa + 0x30,
            struct.pack('<Q', ns['FC_XNU_TXM_HANDLER_GLOBAL'] + 8))
        self.tables.memory.write(state['protected_pa'] + 0x18, b'\x00' * 8)
        stopped = self.tables.event(0xcb000022)
        stopped['pc'] = ns['FC_XNU_TXM_HANDLER_RESPONSE_STOP']
        stopped['spsr'] = 0x600013c0
        stopped['sp'][0] = state['expected_sp']
        self.endpoint.feed(stopped)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-response-trace-complete')
        self.assertTrue(probe['complete'])
        self.assertTrue(probe['result']['response_completed'])
        self.assertTrue(probe['result']['checks']['response_type_three'])
        self.assertTrue(probe['result']['checks']['completion_slot_zero'])

    def test_txm_handler_cmd1_completion_releases_claim_and_returns_to_xnu(self):
        _, probe = self._complete_txm_handler_boundary('cmd1-completion-trace')
        ns = self.endpoint.namespace
        state = ns['txm_validator_trace_state']
        returned = self.tables.event(0xcb000022)
        returned['pc'] = ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET'] + 0xa4
        returned['sp'][0] = state['expected_sp']
        returned['regs'][0] = 0x2d
        self.endpoint.feed(returned)
        frame_pa = state['metadata_frame_pa']
        self.tables.memory.write(frame_pa + 8, b'\x00' * 8)
        self.tables.memory.write(frame_pa + 0x18, struct.pack('<Q', 3))
        self.tables.memory.write(frame_pa + 0x20,
            struct.pack('<Q', state['response_pointer']))
        self.tables.memory.write(frame_pa + 0x28,
            struct.pack('<Q', ns['FC_XNU_TXM_HANDLER_GLOBAL'] + 4))
        self.tables.memory.write(frame_pa + 0x30,
            struct.pack('<Q', ns['FC_XNU_TXM_HANDLER_GLOBAL'] + 8))
        self.tables.memory.write(state['protected_pa'] + 0x18, b'\x00' * 8)
        response = self.tables.event(0xcb000022)
        response['pc'] = ns['FC_XNU_TXM_HANDLER_RESPONSE_STOP']
        response['sp'][0] = state['expected_sp']
        self.endpoint.feed(response)
        self.assertEqual(state['phase'], 'completion')
        self.tables.memory.write(frame_pa + 0x58, b'\x00')
        completion = self.tables.event(0xcb000022)
        completion['pc'] = ns['FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN']
        completion['sp'][0] = state['expected_sp']
        self.endpoint.feed(completion)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-cmd1-completion-trace-complete')
        self.assertTrue(probe['complete'])
        self.assertTrue(probe['result']['cmd1_xnu_return'])
        self.assertTrue(probe['result']['checks']['claim_released'])

    def test_txm_handler_cmd1_firmware_fast_path_gates_svc_and_terminal(self):
        _, probe = self._complete_txm_handler_boundary('cmd1-completion-trace')
        ns = self.endpoint.namespace
        state = ns['txm_validator_trace_state']
        ns['a'].xnu_txm_sstep_fast_path = True
        fast_proxy = StepFilterProxy()
        ns['txm_sstep_fast_path'] = Vel2StepFilter(fast_proxy)
        self.endpoint.report['xnu_txm_sstep_fast_path'] = dict(
            requested=True, activated=False)

        returned = self.tables.event(0xcb000022)
        returned['pc'] = ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET'] + 0xa4
        returned['sp'][0] = state['expected_sp']
        returned['regs'][0] = 0x2d
        self.endpoint.feed(returned)
        frame_pa = state['metadata_frame_pa']
        self.tables.memory.write(frame_pa + 8, b'\x00' * 8)
        self.tables.memory.write(frame_pa + 0x18, struct.pack('<Q', 3))
        self.tables.memory.write(frame_pa + 0x20,
            struct.pack('<Q', state['response_pointer']))
        self.tables.memory.write(frame_pa + 0x28,
            struct.pack('<Q', ns['FC_XNU_TXM_HANDLER_GLOBAL'] + 4))
        self.tables.memory.write(frame_pa + 0x30,
            struct.pack('<Q', ns['FC_XNU_TXM_HANDLER_GLOBAL'] + 8))
        self.tables.memory.write(state['protected_pa'] + 0x18, b'\x00' * 8)
        response = self.tables.event(0xcb000022)
        response['pc'] = ns['FC_XNU_TXM_HANDLER_RESPONSE_STOP']
        response['sp'][0] = state['expected_sp']
        self.endpoint.feed(response)

        svc_pc = ns['FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC']
        svc_word = struct.pack(
            '<I', ns['FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC_WORD'])
        segment = ns['layout']['images']['txm']['segments']['__TEXT_EXEC']
        linked = (ns['FC_XNU_TXM_HANDLER_HELPER_LINKED'] + svc_pc -
                  ns['FC_XNU_TXM_HANDLER_HELPER'])
        source_offset = segment['fileoff'] + linked - segment['va']
        source = bytearray(ns['sources']['txm'])
        source.extend(b'\x00' * max(0, source_offset + 4 - len(source)))
        source[source_offset:source_offset + 4] = svc_word
        ns['sources']['txm'] = bytes(source)
        segment['filesize'] = len(source) - segment['fileoff']
        svc_page = 0x22010000
        self.tables.memory.add_page(svc_page)
        svc_pa = svc_page + (svc_pc & (ns['PAGE'] - 1))
        self.tables.memory.write(svc_pa, svc_word)
        previous_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=svc_pa, level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va == svc_pc else previous_translate(va, *args))

        svc = self.tables.event(0xcb000022)
        svc['pc'] = svc_pc
        svc['sp'][0] = state['expected_sp']
        self.endpoint.feed(svc)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['fast_path_armed'])
        self.assertTrue(fast_proxy.state['active'])
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR'])

        fast_proxy.state.update(
            steps=23, first_pc=ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR'],
            previous_pc=ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET'] - 16,
            last_pc=ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET'] - 8,
            range0_hits=0, range1_hits=23, range_switches=0)
        completion_return = ns['FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC'] + 4
        previous_classify = ns['classify_entry']
        ns['classify_entry'] = lambda target, *args: (
            dict(image='txm', segment='__TEXT_EXEC', target_pc=hex(target),
                 pa=hex(svc_pa + 4),
                 linked_pc=hex(ns['FC_XNU_TXM_HANDLER_CMD1_RETURN_LINKED']),
                 entry_matches=False, bytes_match=True,
                 bytes_hex=(ns['FC_XNU_TXM_HANDLER_CMD1_RETURN_BYTES'] +
                            b'\x00' * 16).hex(), instructions_executed=False)
            if target == completion_return else previous_classify(target, *args))
        ns['HV'].MSR_REDIRECTS.update({
            self.s.ELR_GL1: self.s.ELR_GL12,
            self.s.SPSR_GL1: self.s.SPSR_GL12,
            self.s.ESR_GL1: self.s.ESR_GL12,
            self.s.ASPSR_GL1: self.s.ASPSR_GL12,
        })
        self.endpoint.hardware.values.update({
            self.s.ELR_GL12: completion_return,
            self.s.SPSR_GL12: 0x800013c0,
            self.s.ESR_GL12: ns['FC_XNU_TXM_HANDLER_CMD1_GUARDED_ESR'],
            self.s.ASPSR_GL12: ns['FC_XNU_TXM_HANDLER_CMD1_GUARDED_ASPSR'],
        })
        eret_source_offset = (ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET'] - 4 -
                              ns['FC_IMAGE_BASE'])
        sptm_source = bytearray(ns['sources']['sptm'])
        sptm_source.extend(b'\x00' * max(
            0, eret_source_offset + 4 - len(sptm_source)))
        struct.pack_into('<I', sptm_source, eret_source_offset, 0xd69f03e0)
        mdscr_pc = ns['FC_XNU_TXM_HANDLER_CMD1_MDSCR_PC']
        mdscr_source_offset = mdscr_pc - ns['FC_IMAGE_BASE']
        sptm_source.extend(b'\x00' * max(
            0, mdscr_source_offset + 4 - len(sptm_source)))
        struct.pack_into('<I', sptm_source, mdscr_source_offset,
                         ns['FC_XNU_TXM_HANDLER_CMD1_MDSCR_WORD'])
        ns['sources']['sptm'] = bytes(sptm_source)
        ns['layout']['images']['sptm']['segments']['__TEXT_EXEC'][
            'filesize'] = len(sptm_source) - 0x4000
        eret = self.tables.event(0x5a004800)
        eret['pc'] = ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET']
        _, after_eret = self.endpoint.feed(eret)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(after_eret.elr, completion_return)
        self.assertEqual(after_eret.spsr.SS, 1)
        self.assertEqual(self.endpoint.report['eret_classifications'][-1]
                         ['decision'], 'cmd1-completion-eret')

        # Attempt 89 reached an unpatched MDSCR_EL1 write while the firmware
        # filter was still armed.  It must bypass the TXM SSTEP validator,
        # remain guest-only, and resume stepping after the trapped instruction.
        mdscr_page = 0x22014000
        self.tables.memory.add_page(mdscr_page)
        mdscr_pa = mdscr_page + (mdscr_pc & (ns['PAGE'] - 1))
        self.tables.memory.write(mdscr_pa, struct.pack(
            '<I', ns['FC_XNU_TXM_HANDLER_CMD1_MDSCR_WORD']))
        prior_gate_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=mdscr_pa, level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va == mdscr_pc else prior_gate_translate(va, *args))
        fast_proxy.state.update(
            steps=71, last_pc=mdscr_pc, previous_pc=mdscr_pc - 8,
            range0_hits=8, range1_hits=63, range_switches=2)
        mdscr = self.tables.event(
            ns['FC_XNU_TXM_HANDLER_CMD1_MDSCR_ESR'],
            value=ns['FC_XNU_TXM_HANDLER_CMD1_MDSCR_VALUE'], rt=9, mode=5)
        mdscr['pc'] = mdscr_pc
        _, after_mdscr = self.endpoint.feed(mdscr)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(after_mdscr.elr, mdscr['pc'] + 4)
        self.assertEqual(after_mdscr.spsr.SS, 1)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'],
                         'emulated-guest-mdscr')
        self.assertTrue(self.endpoint.report['trace'][-1]
                        ['firmware_step_filter_rearmed'])
        self.assertTrue(state['active'])

        retab_pc = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB']
        ns['layout']['images']['kernelcache'] = {
            'segments': {'__TEXT_EXEC': {
                'va': ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_LINKED'],
                'fileoff': 0, 'filesize': 4}}}
        ns['sources']['kernelcache'] = struct.pack(
            '<I', ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD'])
        kernel_segment = ns['layout']['images']['kernelcache'][
            'segments']['__TEXT_EXEC']
        retab_source_offset = (kernel_segment['fileoff'] +
            ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_LINKED'] -
            kernel_segment['va'])
        kernel_source = bytearray(ns['sources']['kernelcache'])
        kernel_source.extend(b'\x00' * max(
            0, retab_source_offset + 4 - len(kernel_source)))
        struct.pack_into('<I', kernel_source, retab_source_offset,
                         ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD'])
        ns['sources']['kernelcache'] = bytes(kernel_source)
        retab_page = 0x22018000
        self.tables.memory.add_page(retab_page)
        retab_pa = retab_page + (retab_pc & (ns['PAGE'] - 1))
        self.tables.memory.write(retab_pa, struct.pack(
            '<I', ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD']))
        prior_retab_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=retab_pa, level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va == retab_pc else prior_retab_translate(va, *args))
        fast_proxy.state.update(
            active=False, status=Vel2StepFilter.TERMINAL, steps=1000,
            first_pc=ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR'],
            previous_pc=ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS'],
            last_pc=retab_pc,
            range0_hits=400, range1_hits=600, range_switches=3)
        retab = self.tables.event(0xca000022, mode=4)
        retab['pc'] = retab_pc
        retab['spsr'] = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_SPSR']
        retab['regs'][30] = 0x5bc17e002bc5fb88
        self.endpoint.feed(retab)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['retab_crossed'])
        self.assertTrue(fast_proxy.state['active'])
        self.assertEqual(fast_proxy.state['terminal_pc'],
                         ns['FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN'])

        fast_proxy.state.update(
            active=False, status=Vel2StepFilter.TERMINAL, steps=0,
            first_pc=0, previous_pc=0,
            last_pc=ns['FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN'],
            range0_hits=0, range1_hits=0, range_switches=0)
        ns['a'].xnu_phase53_allocation_trace = True
        self.tables.memory.write(frame_pa + 0x58, b'\x00')
        completion = self.tables.event(0xca000022)
        completion['pc'] = ns['FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN']
        completion['sp'][0] = state['expected_sp']
        self.endpoint.feed(completion)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertNotIn('stop_reason', self.endpoint.report)
        self.assertTrue(probe['complete'])
        self.assertTrue(probe['result']['checks']['fast_path_contract'])
        self.assertTrue(probe['result']['checks']['fast_path_crossed_both_worlds'])
        self.assertEqual(probe['result']['extension_instructions'], 1044)
        allocation_state = ns['phase53_allocation_trace_state']
        self.assertTrue(allocation_state['active'])
        self.assertEqual(fast_proxy.state['terminal_pc'],
                         ns['FC_XNU_PHASE53_ALLOC_CALL'])
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         ns['FC_XNU_PHASE53_AFTER_CMD1_FIRST'])

        phase53_eret_pc = ns['FC_XNU_TXM_CONTEXT_ERET_PC']
        txm_target = ns['FC_XNU_TXM_CONTEXT_TARGET']
        ns['classify_entry'] = lambda target, *args: (
            dict(image='txm', segment='__TEXT_EXEC', target_pc=hex(target),
                 linked_pc=ns['FC_XNU_TXM_CONTEXT_LINKED'],
                 entry_matches=False, bytes_match=True, bytes_hex='00' * 32,
                 instructions_executed=False)
            if target == txm_target else
            dict(image='kernelcache', segment='__TEXT_EXEC',
                 target_pc=hex(target), linked_pc=hex(target - 0x20000000),
                 entry_matches=False, bytes_match=True, bytes_hex='00' * 32,
                 instructions_executed=False))
        self.endpoint.hardware.values.update({
            self.s.ELR_GL12: txm_target,
            self.s.SPSR_GL12: 0x13c0,
        })
        fast_proxy.state.update(
            active=True, status=Vel2StepFilter.RUNNING, steps=11,
            first_pc=ns['FC_XNU_PHASE53_AFTER_CMD1_FIRST'],
            previous_pc=phase53_eret_pc - 8, last_pc=phase53_eret_pc - 4,
            range0_hits=9, range1_hits=2, range_switches=1)
        to_txm = self.tables.event(0x5a004800, mode=5)
        to_txm['pc'] = phase53_eret_pc
        self.endpoint.feed(to_txm)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(fast_proxy.state['range0_start'],
                         ns['FC_TXM_RUNTIME_TEXT'][0])
        self.assertEqual(fast_proxy.state['expected_first_pc'], txm_target)

        xnu_target = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB']
        fast_proxy.state.update(
            active=False, status=4, steps=159,
            first_pc=txm_target, previous_pc=phase53_eret_pc - 8,
            last_pc=ns['FC_XNU_TXM_HANDLER_CMD1_RETAB'],
            range0_hits=9, range1_hits=150, range_switches=1)
        fast_proxy.state['previous_pc'] = (
            ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS'])
        to_xnu = self.tables.event(0xcb000022, mode=4)
        to_xnu['pc'] = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB']
        to_xnu['spsr'] = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_SPSR']
        to_xnu['regs'][30] = 0x5bc17e002bc5fb88
        self.endpoint.feed(to_xnu)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(fast_proxy.state['range0_start'],
                         ns['FC_XNU_RUNTIME_TEXT'][0])
        self.assertEqual(fast_proxy.state['expected_first_pc'], xnu_target)
        self.assertEqual(len(self.endpoint.report[
            'xnu_phase53_allocation_trace']['world_transitions']), 2)

        fast_proxy.state.update(
            active=True, status=Vel2StepFilter.RUNNING, steps=77,
            first_pc=xnu_target, previous_pc=phase53_eret_pc - 8,
            last_pc=phase53_eret_pc - 4, range0_hits=70, range1_hits=7,
            range_switches=1)
        guarded_to_txm = self.tables.event(0x5a004800, mode=5)
        guarded_to_txm['pc'] = phase53_eret_pc
        self.endpoint.feed(guarded_to_txm)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(fast_proxy.state['range0_start'],
                         ns['FC_TXM_RUNTIME_TEXT'][0])
        self.assertEqual(fast_proxy.state['expected_first_pc'], txm_target)

        gexit_pc = ns['FC_XNU_PHASE53_GEXIT']
        guarded_return_pc = ns['FC_XNU_PHASE53_GENTER_RETURN']
        ns['layout']['images']['sptm']['segments']['__TEXT_EXEC'] = {
            'va': ns['FC_XNU_PHASE53_GEXIT_LINKED'],
            'fileoff': 0, 'filesize': 4}
        ns['sources']['sptm'] = struct.pack(
            '<I', ns['FC_XNU_PHASE53_GEXIT_WORD'])
        ns['layout']['images']['kernelcache']['segments']['__TEXT_EXEC'] = {
            'va': ns['FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED'],
            'fileoff': 0, 'filesize': 12}
        ns['sources']['kernelcache'] = struct.pack(
            '<III', ns['FC_XNU_PHASE53_GENTER_PREVIOUS_WORD'],
            ns['FC_XNU_PHASE53_GENTER_WORD'],
            ns['FC_XNU_PHASE53_GENTER_RETURN_WORD'])
        gexit_page = 0x22014000
        guarded_return_page = 0x22018000
        self.tables.memory.add_page(gexit_page)
        self.tables.memory.add_page(guarded_return_page)
        gexit_pa = gexit_page + (gexit_pc & (ns['PAGE'] - 1))
        selector_pa = (guarded_return_page +
                       (ns['FC_XNU_PHASE53_GENTER_PREVIOUS'] &
                        (ns['PAGE'] - 1)))
        genter_pa = (guarded_return_page +
                     (ns['FC_XNU_PHASE53_GENTER'] & (ns['PAGE'] - 1)))
        guarded_return_pa = (guarded_return_page +
                             (guarded_return_pc & (ns['PAGE'] - 1)))
        self.tables.memory.write(gexit_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_GEXIT_WORD']))
        self.tables.memory.write(selector_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_GENTER_PREVIOUS_WORD']))
        self.tables.memory.write(genter_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_GENTER_WORD']))
        self.tables.memory.write(guarded_return_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_GENTER_RETURN_WORD']))
        prior_guarded_return_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=gexit_pa, level=3, descriptor=0x403, access_flag=True,
                 read_only=True, user_access=False, pxn=False, uxn=False)
            if va == gexit_pc else
            (dict(pa=selector_pa, level=3, descriptor=0x403,
                  access_flag=True, read_only=True, user_access=False,
                  pxn=False, uxn=False)
             if va == ns['FC_XNU_PHASE53_GENTER_PREVIOUS'] else
             (dict(pa=genter_pa, level=3, descriptor=0x403,
                   access_flag=True, read_only=True, user_access=False,
                   pxn=False, uxn=False)
              if va == ns['FC_XNU_PHASE53_GENTER'] else
              (dict(pa=guarded_return_pa, level=3, descriptor=0x403,
                  access_flag=True, read_only=True, user_access=False,
                  pxn=False, uxn=False)
               if va == guarded_return_pc else
               prior_guarded_return_translate(va, *args)))))
        fast_proxy.state.update(
            active=False, status=4, steps=2396,
            first_pc=txm_target,
            previous_pc=ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS'],
            last_pc=guarded_return_pc, range0_hits=123, range1_hits=2273,
            range_switches=1)
        guarded_return = self.tables.event(0xcb000022, mode=4)
        guarded_return['pc'] = guarded_return_pc
        guarded_return['spsr'] = ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR']
        guarded_return['regs'][30] = 0xcfbbfe002bf7a4c0
        self.endpoint.feed(guarded_return)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertNotIn('stop_reason', self.endpoint.report)
        self.assertEqual(allocation_state['stage'], 'allocation-call')
        self.assertEqual(fast_proxy.state['range0_start'],
                         ns['FC_XNU_RUNTIME_TEXT'][0])
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         guarded_return_pc)
        self.assertEqual(len(self.endpoint.report[
            'xnu_phase53_allocation_trace']['world_transitions']), 4)

        allocation_pc = ns['FC_XNU_PHASE53_ALLOC_CALL']
        ns['layout']['images']['kernelcache']['segments']['__TEXT_EXEC'] = {
            'va': ns['FC_XNU_PHASE53_ALLOC_CALL_LINKED'],
            'fileoff': 0, 'filesize': 4}
        ns['sources']['kernelcache'] = struct.pack(
            '<I', ns['FC_XNU_PHASE53_ALLOC_CALL_WORD'])
        allocation_page = 0x2201c000
        self.tables.memory.add_page(allocation_page)
        allocation_pa = allocation_page + (allocation_pc & (ns['PAGE'] - 1))
        self.tables.memory.write(allocation_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_ALLOC_CALL_WORD']))
        prior_allocation_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=allocation_pa, level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va == allocation_pc else prior_allocation_translate(va, *args))
        fast_proxy.state.update(
            active=False, status=Vel2StepFilter.TERMINAL, steps=123,
            first_pc=guarded_return_pc,
            previous_pc=allocation_pc - 4, last_pc=allocation_pc,
            range0_hits=123, range1_hits=0, range_switches=0)
        allocation = self.tables.event(0xca000022, mode=4)
        allocation['pc'] = allocation_pc
        self.endpoint.feed(allocation)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertNotIn('stop_reason', self.endpoint.report)

        stage_page = 0x22020000
        def feed_stage(pc_name, linked_name, word_name, regs=None,
                       previous_pc=None):
            nonlocal stage_page
            pc = ns[pc_name]
            linked = ns[linked_name]
            word = ns[word_name]
            ns['layout']['images']['kernelcache']['segments']['__TEXT_EXEC'] = {
                'va': linked, 'fileoff': 0, 'filesize': 4}
            ns['sources']['kernelcache'] = struct.pack('<I', word)
            self.tables.memory.add_page(stage_page)
            pa = stage_page + (pc & (ns['PAGE'] - 1))
            self.tables.memory.write(pa, struct.pack('<I', word))
            prior_translate = ns['translate']
            ns['translate'] = lambda va, *args, _pc=pc, _pa=pa, _prior=prior_translate: (
                dict(pa=_pa, level=3, descriptor=0x403, access_flag=True,
                     read_only=True, user_access=False, pxn=False, uxn=False)
                if va == _pc else _prior(va, *args))
            segment_start = fast_proxy.state['expected_first_pc']
            fast_proxy.state.update(
                active=False, status=Vel2StepFilter.TERMINAL, steps=23,
                first_pc=segment_start,
                previous_pc=(pc - 4 if previous_pc is None else previous_pc),
                last_pc=pc, range0_hits=23, range1_hits=0,
                range_switches=0)
            callback = self.tables.event(0xca000022, mode=4)
            callback['pc'] = pc
            for register, value in (regs or {}).items():
                callback['regs'][register] = value
            self.endpoint.feed(callback)
            stage_page += ns['PAGE']

        feed_stage('FC_XNU_PHASE53_ALLOC_INTERNAL_CALL',
                   'FC_XNU_PHASE53_ALLOC_INTERNAL_CALL_LINKED',
                   'FC_XNU_PHASE53_ALLOC_INTERNAL_CALL_WORD')
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        allocated_pa = 0x22000000
        feed_stage('FC_XNU_PHASE53_ALLOC_RETURN',
                   'FC_XNU_PHASE53_ALLOC_RETURN_LINKED',
                   'FC_XNU_PHASE53_ALLOC_RETURN_WORD', {0: allocated_pa})
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))

        fte_pointer_pa = 0x22100000
        fte_record_pa = 0x22104000
        self.tables.memory.add_page(fte_pointer_pa)
        self.tables.memory.add_page(fte_record_pa)
        fte_base = 0xfffffe0027100000
        fte_va = fte_base + (
            ((allocated_pa - ns['base']) >> 10) & 0x3ffffffffffff0)
        fte_before = bytes([0, 0, 0xb, *range(3, 16)])
        self.tables.memory.write(fte_pointer_pa, struct.pack('<Q', fte_base))
        self.tables.memory.write(fte_record_pa, fte_before)
        prior_fte_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=fte_pointer_pa, level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va == ns['FC_SPTM_PHASE53_FTE_BASE_POINTER'] else
            (dict(pa=fte_record_pa, level=3, descriptor=0x403,
                  access_flag=True, read_only=True, user_access=False,
                  pxn=False, uxn=False)
             if va == fte_va else prior_fte_translate(va, *args)))
        feed_stage('FC_XNU_PHASE53_POST_UBFIZ',
                   'FC_XNU_PHASE53_POST_UBFIZ_LINKED',
                   'FC_XNU_PHASE53_POST_UBFIZ_WORD', {21: allocated_pa},
                   ns['FC_XNU_PHASE53_UBFIZ_PC'])
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        feed_stage('FC_XNU_PHASE53_RETYPE_CALL',
                   'FC_XNU_PHASE53_RETYPE_CALL_LINKED',
                   'FC_XNU_PHASE53_RETYPE_CALL_WORD',
                   {0: allocated_pa, 1: 0xb, 2: 0x29, 3: 0})
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        feed_stage('FC_XNU_PHASE53_GENTER',
                   'FC_XNU_PHASE53_GENTER_LINKED',
                   'FC_XNU_PHASE53_GENTER_WORD', {16: 1},
                   ns['FC_XNU_PHASE53_GENTER_PREVIOUS'])
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        fte_after = fte_before[:2] + bytes([0x29]) + fte_before[3:]
        self.tables.memory.write(fte_record_pa, fte_after)
        feed_stage('FC_XNU_PHASE53_RETYPE_RETURN',
                   'FC_XNU_PHASE53_RETYPE_RETURN_LINKED',
                   'FC_XNU_PHASE53_RETYPE_RETURN_WORD',
                   {0: fte_va, 21: allocated_pa})
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-return-reached')
        self.assertTrue(self.endpoint.report['xnu_phase53_allocation_trace']
                        ['complete'])
        stages = self.endpoint.report['xnu_phase53_allocation_trace']['stages']
        self.assertEqual(len(stages), 7)
        self.assertEqual(stages[-1]['frame_table_after']['changed_bytes'][0],
                         {'offset': 2, 'before': 11, 'after': 41, 'xor': 34})

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

    def _run_phase53_retype_survey_call(self, target_type=0x14, limit=4,
                                        after_type=None, lock_before=False,
                                        stop_before_return=False):
        ns = self.endpoint.namespace
        ns['a'].xnu_phase53_retype_survey = True
        ns['a'].xnu_phase53_retype_survey_limit = limit
        ns['handoff_state'].update(native=True)
        self.endpoint.report['handoff'] = dict(
            image='txm', target_pc=hex(ns['FC_XNU_TXM_CONTEXT_TARGET']))
        fast_proxy = StepFilterProxy()
        ns['txm_sstep_fast_path'] = Vel2StepFilter(fast_proxy)

        caller_pc = ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'] - 0x30
        caller_linked = ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED'] - 0x30
        caller_return = caller_pc + 4
        caller_word = 0x9400000c
        kernel_start = caller_linked
        kernel_end = ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED'] + 4
        kernel_source = bytearray(kernel_end - kernel_start)
        code = (
            (caller_pc, caller_linked, caller_word),
            (ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'],
             ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED'],
             ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_WORD']),
            (ns['FC_XNU_PHASE53_GENTER_PREVIOUS'],
             ns['FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED'],
             ns['FC_XNU_PHASE53_GENTER_PREVIOUS_WORD']),
            (ns['FC_XNU_PHASE53_GENTER'],
             ns['FC_XNU_PHASE53_GENTER_LINKED'],
             ns['FC_XNU_PHASE53_GENTER_WORD']),
            (ns['FC_XNU_PHASE53_GENTER_RETURN'],
             ns['FC_XNU_PHASE53_GENTER_RETURN_LINKED'],
             ns['FC_XNU_PHASE53_GENTER_RETURN_WORD']),
            (ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'],
             ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED'],
             ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_WORD']),
        )
        kernel_page = 0x22200000
        sptm_page = 0x22204000
        pointer_page = 0x22208000
        fte_page = 0x2220c000
        for page in (kernel_page, sptm_page, pointer_page, fte_page):
            self.tables.memory.add_page(page)
        translations = {}
        for runtime, linked, word in code:
            struct.pack_into('<I', kernel_source, linked - kernel_start, word)
            pa = kernel_page + (runtime & (ns['PAGE'] - 1))
            self.tables.memory.write(pa, struct.pack('<I', word))
            translations[runtime] = pa
        gexit_pc = ns['FC_XNU_PHASE53_GEXIT']
        gexit_pa = sptm_page + (gexit_pc & (ns['PAGE'] - 1))
        self.tables.memory.write(gexit_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_GEXIT_WORD']))
        translations[gexit_pc] = gexit_pa
        ns['layout'] = {'images': {
            'kernelcache': {'segments': {'__TEXT_EXEC': {
                'va': kernel_start, 'fileoff': 0,
                'filesize': len(kernel_source)}}},
            'sptm': {'segments': {'__TEXT_EXEC': {
                'va': ns['FC_XNU_PHASE53_GEXIT_LINKED'], 'fileoff': 0,
                'filesize': 4}}}}}
        ns['sources'] = {
            'kernelcache': bytes(kernel_source),
            'sptm': struct.pack('<I', ns['FC_XNU_PHASE53_GEXIT_WORD'])}

        allocated_pa = 0x22000000
        fte_base = 0xfffffe0027100000
        fte_va = fte_base + (
            ((allocated_pa - ns['base']) >> 10) & 0x3ffffffffffff0)
        self.tables.memory.write(pointer_page, struct.pack('<Q', fte_base))
        for delta, record_type in ((-16, 0x12), (0, 0xb), (16, 0x15)):
            pa = fte_page + 0x100 + delta
            self.tables.memory.write(pa, bytes([0, 0, record_type]) +
                                     bytes(range(3, 16)))
            translations[fte_va + delta] = pa
        translations[ns['FC_SPTM_PHASE53_FTE_BASE_POINTER']] = pointer_page
        prior_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=translations[va], level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va in translations else prior_translate(va, *args))

        state = ns['phase53_retype_survey_state']
        state.update(
            active=True, roots={'ttbr0': 0, 'ttbr1': 0},
            range0=ns['FC_XNU_RUNTIME_TEXT'],
            segment_start=ns['FC_XNU_PHASE53_RETYPE_RETURN'],
            terminal_pc=ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'],
            stage='seek-entry', completed_calls=0, aggregate_steps=0,
            rearms=1, calls=[], limit=limit, world_transitions=[])
        self.endpoint.report['xnu_phase53_retype_survey'] = dict(
            requested=True, activated=True, calls=[])

        def feed(pc, regs, previous_pc, status=Vel2StepFilter.TERMINAL,
                 spsr=0):
            segment_start = state['segment_start']
            fast_proxy.state.update(
                active=False, status=status, steps=19,
                first_pc=segment_start, previous_pc=previous_pc, last_pc=pc,
                range0_hits=19, range1_hits=0, range_switches=0,
                terminal_pc=state['terminal_pc'],
                max_steps=ns['FC_XNU_PHASE53_FAST_STEPS'],
                range0_start=state['range0'][0],
                range0_end=state['range0'][1],
                range1_start=ns['FC_SPTM_RUNTIME_TEXT'][0],
                range1_end=ns['FC_SPTM_RUNTIME_TEXT'][1],
                expected_first_pc=segment_start)
            callback = self.tables.event(0xca000022, mode=4)
            callback['pc'] = pc
            callback['spsr'] = spsr
            for register, value in regs.items():
                callback['regs'][register] = value
            self.endpoint.feed(callback)

        args = {0: allocated_pa, 1: 0xb, 2: target_type, 3: 0}
        center_pa = translations[fte_va]
        if lock_before:
            before = self.tables.memory.read(center_pa, 16)
            self.tables.memory.write(center_pa, b'\x01\x00' + before[2:])
        feed(ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'],
             {**args, 30: caller_return},
             caller_pc - 4)
        if lock_before:
            return ns, state, fast_proxy, feed, caller_return, center_pa
        self.assertEqual(state['stage'], 'seek-genter')
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'])
        feed(ns['FC_XNU_PHASE53_GENTER'],
             {**args, 16: 1, 30: caller_return},
             ns['FC_XNU_PHASE53_GENTER_PREVIOUS'])
        self.assertEqual(state['stage'], 'seek-genter-return')
        if stop_before_return:
            return ns, state, fast_proxy, feed, caller_return, center_pa
        feed(ns['FC_XNU_PHASE53_GENTER_RETURN'],
             {30: ns['FC_XNU_PHASE53_GENTER_PREVIOUS']},
             ns['FC_XNU_PHASE53_GEXIT'],
             spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        self.assertEqual(state['stage'], 'seek-wrapper-retab')
        before = self.tables.memory.read(center_pa, 16)
        self.tables.memory.write(center_pa,
                                 before[:2] + bytes([
                                     target_type if after_type is None else
                                     after_type]) + before[3:])
        feed(ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'],
             {30: caller_return},
             ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_PREVIOUS'])
        return ns, state, fast_proxy, feed, caller_return, center_pa

    def test_phase53_retype_survey_stops_on_page_table_target(self):
        self._run_phase53_retype_survey_call()
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-target-reached')
        survey = self.endpoint.report['xnu_phase53_retype_survey']
        self.assertTrue(survey['complete'])
        self.assertTrue(survey['target_found'])
        self.assertTrue(survey['primary_target_found'])
        self.assertEqual(survey['completed_calls'], 1)
        self.assertEqual(survey['calls'][0]['frame_table_before'][
            'records'][1]['type'], 0xb)
        self.assertEqual(survey['calls'][0]['frame_table_after'][
            'records'][1]['type'], 0x14)

    def test_phase53_retype_survey_non_target_rearms_with_callback_echo(self):
        ns, state, fast_proxy, _, _, _ = (
            self._run_phase53_retype_survey_call(target_type=0x29, limit=2))
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['active'])
        self.assertEqual(state['stage'], 'seek-entry')
        self.assertEqual(state['completed_calls'], 1)
        self.assertEqual(fast_proxy.state['terminal_pc'],
                         ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'])
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'])

    def _prepare_phase53_unrelated_gexit_return(self):
        ns, state, fast_proxy, feed, caller_return, _ = (
            self._run_phase53_retype_survey_call(target_type=0x29, limit=2))
        state.update(range0=ns['FC_TXM_RUNTIME_TEXT'],
                     segment_start=ns['FC_XNU_TXM_CONTEXT_TARGET'])
        return ns, state, fast_proxy, feed, caller_return - 4

    def test_phase53_retype_survey_relays_verified_unrelated_gexit_return(self):
        ns, state, fast_proxy, feed, return_pc = (
            self._prepare_phase53_unrelated_gexit_return())
        prior_aggregate = state['aggregate_steps']
        prior_rearms = state['rearms']
        feed(return_pc, {}, ns['FC_XNU_PHASE53_GEXIT'],
             status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'],
             spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['active'])
        self.assertEqual(state['stage'], 'seek-entry')
        self.assertEqual(state['range0'], ns['FC_XNU_RUNTIME_TEXT'])
        self.assertEqual(state['aggregate_steps'], prior_aggregate + 19)
        self.assertEqual(state['rearms'], prior_rearms + 1)
        self.assertEqual(fast_proxy.state['terminal_pc'],
                         ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], return_pc)
        transition = self.endpoint.report['xnu_phase53_retype_survey'][
            'world_transitions'][-1]
        self.assertEqual(transition['kind'],
                         'survey-unrelated-gexit-return')
        self.assertTrue(transition['complete'])

    def test_phase53_retype_survey_rejects_unrelated_return_flow_or_budget(self):
        ns, state, _, feed, return_pc = (
            self._prepare_phase53_unrelated_gexit_return())
        feed(return_pc, {}, ns['FC_XNU_PHASE53_GEXIT'] + 4,
             status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'],
             spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        rejection = self.endpoint.report['xnu_phase53_retype_survey'][
            'unrelated_return_rejection']
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-unrelated-return-gate-rejected')
        self.assertFalse(rejection['checks']['filter_previous_pc'])

        self.setUp()
        ns, state, _, feed, return_pc = (
            self._prepare_phase53_unrelated_gexit_return())
        state['aggregate_steps'] = ns[
            'FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS']
        feed(return_pc, {}, ns['FC_XNU_PHASE53_GEXIT'],
             status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'],
             spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        rejection = self.endpoint.report['xnu_phase53_retype_survey'][
            'unrelated_return_rejection']
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-unrelated-return-gate-rejected')
        self.assertFalse(rejection['checks']['aggregate_budget'])

    def test_phase53_retype_survey_eret_switch_and_gexit_return_relay(self):
        ns, state, fast_proxy, feed, _, _ = (
            self._run_phase53_retype_survey_call(stop_before_return=True))
        ns['a'].free_run = ns['a'].real_guarded = True
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={
            self.s.ELR_GL1: self.s.ELR_GL12,
            self.s.SPSR_GL1: self.s.SPSR_GL12,
            self.s.ESR_GL1: self.s.ESR_EL12,
            self.s.ASPSR_GL1: self.s.AFSR1_EL12})
        txm_target = ns['FC_XNU_TXM_CONTEXT_TARGET']
        ns['classify_entry'] = lambda target, *args: dict(
            image='txm', segment='__TEXT_EXEC', target_pc=hex(target),
            linked_pc=ns['FC_XNU_TXM_CONTEXT_LINKED'], entry_matches=False,
            bytes_match=True, bytes_hex='00' * 32,
            instructions_executed=False)
        self.endpoint.hardware.values.update({
            self.s.ELR_GL12: txm_target,
            self.s.SPSR_GL12: 0x13c0,
        })
        eret_pc = ns['FC_XNU_TXM_CONTEXT_ERET_PC']
        eret_offset = eret_pc - 4 - ns['FC_IMAGE_BASE']
        sptm_source = bytearray(ns['sources']['sptm'])
        sptm_source.extend(b'\0' * max(
            0, eret_offset + 4 - len(sptm_source)))
        struct.pack_into('<I', sptm_source, eret_offset,
                         ns['FC_XNU_TXM_CONTEXT_ERET_WORD'])
        ns['sources']['sptm'] = bytes(sptm_source)
        sptm_segment = ns['layout']['images']['sptm']['segments'][
            '__TEXT_EXEC']
        sptm_segment.update(fileoff=eret_offset, filesize=4)
        fast_proxy.state.update(
            active=True, status=Vel2StepFilter.RUNNING, steps=11,
            first_pc=ns['FC_XNU_PHASE53_GENTER'],
            previous_pc=eret_pc - 8, last_pc=eret_pc - 4,
            range0_hits=9, range1_hits=2, range_switches=1)
        eret = self.tables.event(0x5a004800, mode=5)
        eret['pc'] = eret_pc
        self.endpoint.feed(eret)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED),
                         self.endpoint.report)
        self.assertEqual(state['range0'], ns['FC_TXM_RUNTIME_TEXT'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], txm_target)
        self.assertEqual(state['stage'], 'seek-genter-return')

        sptm_segment.update(fileoff=0, filesize=4)
        feed(ns['FC_XNU_PHASE53_GENTER_RETURN'],
             {30: ns['FC_XNU_PHASE53_GENTER_PREVIOUS']},
             ns['FC_XNU_PHASE53_GEXIT'],
             status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'],
             spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(state['stage'], 'seek-wrapper-retab')
        self.assertEqual(state['range0'], ns['FC_XNU_RUNTIME_TEXT'])
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         ns['FC_XNU_PHASE53_GENTER_RETURN'])
        self.assertEqual(len(self.endpoint.report[
            'xnu_phase53_retype_survey']['world_transitions']), 1)

    def test_phase53_retype_survey_stops_at_call_limit(self):
        self._run_phase53_retype_survey_call(target_type=0x29, limit=1)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-call-limit-reached')
        self.assertTrue(self.endpoint.report['xnu_phase53_retype_survey'][
            'limit_reached'])

    def test_phase53_retype_survey_rejects_locked_or_mismatched_fte(self):
        self._run_phase53_retype_survey_call(lock_before=True)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-seek-entry-gate-rejected')
        self.assertFalse(self.endpoint.report['xnu_phase53_retype_survey'][
            'rejection']['checks']['fte_center_unlocked'])

        self.setUp()
        self._run_phase53_retype_survey_call(
            target_type=0x29, limit=2, after_type=0x28)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-seek-wrapper-retab-gate-rejected')
        self.assertFalse(self.endpoint.report['xnu_phase53_retype_survey'][
            'rejection']['checks']['fte_center_type'])

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

    def feed_xnu_launch(self, steps=2, pperm=0x5555555555555555, broken_walk=False, state=0x13c9):
        ns = self.endpoint.namespace
        target = 0xfffffe002bfb0000
        ns['a'].xnu_steps = steps
        self.endpoint.hardware.values[self.s.ASPSR_GL12] = 0x1234
        ns['a'].free_run = ns['a'].real_guarded = ns['a'].native_handoff = True
        ns['classify_entry'] = lambda *args: dict(image='kernelcache', target_pc=hex(target),
            entry_matches=True, bytes_match=True, instructions_executed=False)
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1:self.s.ELR_EL12,
                                                   self.s.SPSR_GL1:self.s.SPSR_EL12,
                                                   self.s.ASPSR_GL1:self.s.ASPSR_GL12})
        self.endpoint.hardware.values[self.s.ELR_EL12] = target
        self.endpoint.hardware.values[self.s.SPSR_EL12] = state
        ns['HV'].MSR_REDIRECTS.update({self.s.SPRR_PPERM_EL1: self.s.SPRR_PPERM_EL12,
                                      self.s.SPRR_UPERM_EL0: self.s.SPRR_UPERM_EL02})
        live_pperm, live_uperm = pperm, 0x1111111111111111
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
        if broken_walk:
            def fail_walk(*args):
                raise ValueError('synthetic table capture failed')
            ns['translate'] = fail_walk
        rt = 4
        reg = self.s.ASPSR_GL1
        op0, op1, crn, crm, op2 = reg
        word = 0xd5000000 | op0 << 19 | op1 << 16 | crn << 12 | crm << 8 | op2 << 5 | rt
        patched, = struct.unpack('<I', ns['patch_probe_code'](struct.pack('<I', word)))
        imm = (patched >> 5) & 0xffff
        before, after = self.endpoint.feed(dict(self.tables.event(0x5a000000 | imm, 0, rt),
                                                pc=ns['FC_XNU_GEXIT']))
        return before, after

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

    def _prepare_pperm_window_replay(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        ns['a'].xnu_pperm_guest_window = True
        ns['a'].xnu_pperm_guest_window_limit = 1
        runtime_entry = 0xfffffe002bfb0000
        ns['report']['handoff'] = {'target_pc': hex(runtime_entry)}
        lo = min(site[0] for site in FC_XNU_PPERM_SITES)
        hi = max(site[0] for site in FC_XNU_PPERM_SITES) + 4
        source = bytearray(hi-lo)
        for pc, word, _, _ in FC_XNU_PPERM_SITES:
            struct.pack_into('<I', source, pc-lo, word)
        ns['layout'] = {'images': {'kernelcache': {'segments': {'__TEXT_EXEC': {
            'va': lo, 'fileoff': 0, 'filesize': len(source)}}}}}
        ns['sources'] = {'kernelcache': bytes(source)}
        ns['report']['xnu_pperm_guest_window'] = {
            'enabled': True, 'sequence': [], 'memcpy_crossed': False,
            'physical_pperm_el1_touched': False, 'started_windows': 0,
            'completed_windows': 0, 'memcpy_crossed_windows': 0}
        ns['HV'].MSR_REDIRECTS[ns['SPRR_PPERM_EL1']] = self.s.SPRR_PPERM_EL12
        original = 0x2020a52a302abae6
        writable = (original & ~(0xf << 8)) | (0xb << 8)
        self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12] = original
        return ns, runtime_entry, original, writable

    def _feed_pperm_hvc(self, ns, runtime_entry, site_index, x8=0):
        pc, _, tag, _ = FC_XNU_PPERM_SITES[site_index]
        event = self.tables.event((0x16 << 26) | (1 << 25) | tag)
        event.update(pc=runtime_entry + pc - ns['FC_XNU_ENTRY_LINKED'] + 4)
        event['regs'][8] = x8
        return self.endpoint.feed(event)

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
            'previous': original, 'step': 4, 'modified': False,
            'started': 1, 'completed': 1})
        self.assertEqual([row['index2_nibble'] for row in
                          ns['report']['xnu_pperm_guest_window']['sequence']],
                         [0xa, 0xb, 0xb, 0xa])
        self.assertTrue(all(reply == int(self.endpoint.EXC_RET.HANDLED)
                            for reply in self.endpoint.replies[-4:]))

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
                         runtime_entry + FC_XNU_PPERM_SITES[0][0]
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


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class SprrObservationTests(unittest.TestCase):
    """Observation-only staging after translation is live; nothing is enforced."""
    def setUp(self):
        self.tables = Tables()
        self.endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True, observe_sprr=True)
        self.s = self.endpoint.sysreg
        self.tables.enable(self.endpoint)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.endpoint.hardware.calls.clear()

    def access(self, register, **kwargs):
        return self.tables.access(self.endpoint, register, **kwargs)

    def assert_staged(self, kind):
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], kind)
        self.assertEqual(self.endpoint.hardware.calls, [])
        self.assertEqual(self.endpoint.hardware.attempts, [])

    def test_translated_config_write_is_recorded_not_enforced(self):
        self.access(self.s.SPRR_PPERM_EL1, value=0x2020a52a302abaf5)
        self.assert_staged('staged-sprr-permission')
        before, after = self.access(self.s.SPRR_CONFIG_EL1, value=1)
        self.assert_staged('observed-sprr-config')
        self.assertEqual(after.elr, before.elr)
        observation = self.endpoint.report['sprr_observation']
        self.assertFalse(observation['enforced'])
        self.assertEqual(observation['events'][-1]['value'], 1)
        self.assertEqual(observation['events'][-1]['permissions']['SPRR_PPERM_EL1'], 0x2020a52a302abaf5)
        _, after = self.access(self.s.SPRR_CONFIG_EL1, read=True, rt=3)
        self.assertEqual(after.regs[3], 1)
        self.assert_staged('staged-sprr-config')
        # SPTM then locks the configuration; observation records the bits instead of stopping.
        self.access(self.s.SPRR_CONFIG_EL1, value=0xfb)
        self.assert_staged('observed-sprr-config')
        last = observation['events'][-1]
        self.assertEqual((last['enable'], last['lock_config'], last['lock_perm'], last['lock_kernel_perm'], last['unknown_bits']),
                         (True, True, True, True, 0xc8))
        _, after = self.access(self.s.SPRR_CONFIG_EL1, read=True, rt=4)
        self.assertEqual(after.regs[4], 0xfb)

    def test_full_sprr_permission_family_stages_without_hardware(self):
        # SPTM programmed SPRR_PMPRR_EL1 (S3_6_C15_C3_1) and shareable perm mirrors;
        # every one must stage rather than fault natively into the monitor's vector.
        for name in ('SPRR_PMPRR_EL1', 'SPRR_UPERM_SH1_EL1', 'SPRR_UPERM_SH2_EL1', 'SPRR_UPERM_SH3_EL1',
                     'SPRR_PPERM_SH1_EL1', 'SPRR_PPERM_SH2_EL1', 'SPRR_PPERM_SH3_EL1'):
            with self.subTest(register=name):
                reg = getattr(self.s, name)
                self.access(reg, value=0x2020a52a302abaf5, rt=9)
                self.assert_staged('staged-sprr-permission')
                _, after = self.access(reg, read=True, rt=10)
                self.assertEqual(after.regs[10], 0x2020a52a302abaf5)
                self.assert_staged('staged-sprr-permission')

    def test_every_apple_register_in_the_monitor_image_is_intercepted_or_allowlisted(self):
        import struct
        payload = Path(__file__).resolve().parents[1]/'local/payload/sptm.macho'
        if not payload.is_file():
            self.skipTest('Retained SPTM payload not present')
        data = payload.read_bytes()
        native = {(3, 6, 15, 2, 5), (3, 6, 15, 12, 4)}  # AFPCR_EL0, APSTS_EL1: executed natively before, without incident
        covered = set(self.endpoint.namespace['extra_regs'])
        gaps = set()
        for off in range(0, len(data)-3, 4):
            w = struct.unpack_from('<I', data, off)[0]
            if w & 0xffd00000 == 0xd5100000:
                enc = (2+((w >> 19) & 1), (w >> 16) & 7, (w >> 12) & 15, (w >> 8) & 15, (w >> 5) & 7)
                if enc[:3] in ((3, 6, 15), (3, 4, 15)) and enc not in covered and enc not in native:
                    gaps.add(enc)
        self.assertEqual(gaps, set())
        self.assertLess(len(covered), 256)

    def test_virtual_el2_aliases_and_guarded_level_stage_without_hardware(self):
        for name in ('TPIDR_GL2', 'SPRR_CONFIG_EL12', 'GXF_CONFIG_EL12', 'VBAR_GL12', 'SP_GL12', 'APIAKeyLo_EL12'):
            with self.subTest(register=name):
                reg = getattr(self.s, name)
                self.access(reg, value=0xabc, rt=3)
                self.assert_staged('staged-apple-register')
                _, after = self.access(reg, read=True, rt=4)
                self.assertEqual(after.regs[4], 0xabc)
        self.access((3, 6, 15, 0, 5), value=7, rt=1)
        self.assert_staged('staged-apple-register')
        self.assertEqual(self.endpoint.report['trace'][-1]['register'], 'S3_6_C15_C0_5')
        self.assertEqual(self.endpoint.report['staged_apple_registers']['S3_6_C15_C0_5'], 7)

    def test_guarded_world_registers_stage_without_hardware(self):
        for register in (self.s.SPRR_AMRANGE_EL1, self.s.SPRR_UMPRR_EL1, self.s.GXF_ENTRY_EL1, self.s.GXF_PABENTRY_EL1,
                         self.s.VBAR_GL1, self.s.TPIDR_GL1, self.s.ASPSR_GL1, self.s.SPSR_GL1, self.s.ELR_GL1,
                         self.s.ESR_GL1, self.s.FAR_GL1, self.s.AFSR1_GL1, self.s.ASPSR_EL1):
            with self.subTest(register=register):
                self.access(register, value=0x1234, rt=5)
                self.assert_staged('staged-apple-register')
                _, after = self.access(register, read=True, rt=6)
                self.assertEqual(after.regs[6], 0x1234)
                self.assert_staged('staged-apple-register')
        self.assertEqual(self.endpoint.report['staged_apple_registers']['VBAR_GL1'], 0x1234)
        _, after = self.access(self.s.GXF_STATUS_EL1, read=True, rt=7)
        self.assertEqual(after.regs[7], 0)
        self.assert_staged('staged-apple-register')
        self.access(self.s.GXF_STATUS_EL1, value=1)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-el2-register')

    def test_gxf_activation_still_stops_and_default_stays_strict(self):
        self.access(self.s.SPRR_CONFIG_EL1, value=1)
        self.assert_staged('observed-sprr-config')
        self.access(self.s.GXF_CONFIG_EL1, value=1)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-el2-register')
        strict = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True)
        self.tables.enable(strict)
        self.tables.access(strict, self.s.SPRR_CONFIG_EL1, value=1)
        self.assertEqual(strict.report['stop_reason'], 'unsupported-el2-register')
        untranslated = self.tables.endpoint(os.environ['VEL2_CHECKOUT'])
        self.tables.access(untranslated, self.s.SPRR_CONFIG_EL1, value=0xfb)
        self.assertEqual(untranslated.report['stop_reason'], 'unsupported-el2-register')
        self.assertNotIn('sprr_observation', strict.report)



@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class VirtualGuardedWorldTests(unittest.TestCase):
    """Architectural genter/gexit control flow only; nothing is enforced."""
    ENTRY = 0xfffffe0007100000
    GL_VECTOR = 0xfffffe0007200000

    def setUp(self):
        self.tables = Tables()
        self.endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True, observe_sprr=True, virtual_gxf=True)
        self.s = self.endpoint.sysreg
        self.hw = self.endpoint.hardware
        self.tables.enable(self.endpoint)
        self.hw.values[self.s.VBAR_EL12] = 0xfffffe00070ad000
        self.hw.values[self.s.ESR_EL12] = 0x11
        self.hw.calls.clear()

    def access(self, register, **kwargs):
        return self.tables.access(self.endpoint, register, **kwargs)

    def instruction(self, imm_tag, mode=4):
        return self.endpoint.feed(self.tables.event(0x5a000000 | imm_tag, mode=mode))

    def enable(self):
        self.access(self.s.GXF_CONFIG_EL1, value=1)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'virtual-gxf-config')
        _, after = self.access(self.s.GXF_CONFIG_EL1, read=True, rt=2)
        self.assertEqual(after.regs[2], 1)
        self.access(self.s.GXF_ENTRY_EL1, value=self.ENTRY)
        self.access(self.s.VBAR_GL1, value=self.GL_VECTOR)

    def test_genter_swaps_world_and_gexit_restores_it(self):
        self.enable()
        self.hw.calls.clear()
        before, after = self.instruction(0x6093)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'virtual-genter')
        self.assertEqual(after.elr, self.ENTRY)
        self.assertEqual(int(after.spsr) & 0x3cf, 0x3c5)
        self.assertEqual(after.spsr.SS, 1)
        self.assertEqual(self.hw.values[self.s.VBAR_EL12], self.GL_VECTOR)
        self.assertEqual(self.hw.values[self.s.ELR_EL12], before.elr)
        self.assertEqual(self.hw.values[self.s.SPSR_EL12], int(before.spsr))
        self.assertEqual(self.hw.values[self.s.ESR_EL12], 0xfe010003)
        self.assertEqual(list(after.sp)[:2], [before.sp[0], 0])
        _, status = self.access(self.s.GXF_STATUS_EL1, read=True, rt=5)
        self.assertEqual(status.regs[5], 1)
        # Guarded reads of the GL1 bank see the live EL1 bank; writes reach it.
        _, esr = self.access(self.s.ESR_GL1, read=True, rt=6)
        self.assertEqual(esr.regs[6], 0xfe010003)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'guarded-bank-register')
        self.access(self.s.ELR_GL1, value=before.elr+0x40)
        self.assertEqual(self.hw.values[self.s.ELR_EL12], before.elr+0x40)
        self.assertEqual(self.endpoint.report['virtual_gxf']['genter'], 1)
        self.assertTrue(self.endpoint.report['virtual_gxf']['guarded'])
        self.assertFalse(self.endpoint.report['virtual_gxf']['permissions_enforced'])
        # gexit returns to the (modified) link, restores vectors, ESR and SP_EL1.
        _, exited = self.instruction(0x60a0, mode=5)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'virtual-gexit')
        self.assertEqual(exited.elr, before.elr+0x40)
        self.assertEqual(int(exited.spsr) & 0xf, 4)
        self.assertEqual(self.hw.values[self.s.VBAR_EL12], 0xfffffe00070ad000)
        self.assertEqual(self.hw.values[self.s.ESR_EL12], 0x11)
        self.assertEqual(list(exited.sp)[:2], [before.sp[0], before.sp[1]])
        _, status = self.access(self.s.GXF_STATUS_EL1, read=True, rt=5)
        self.assertEqual(status.regs[5], 0)
        self.assertEqual(self.endpoint.report['virtual_gxf']['gexit'], 1)
        # The captured guarded bank is readable afterwards.
        _, esr = self.access(self.s.ESR_GL1, read=True, rt=6)
        self.assertEqual(esr.regs[6], 0xfe010003)

    def test_transitions_fail_closed(self):
        self.instruction(0x6090)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-guarded-transition')
        self.endpoint.report.pop('stop_reason')
        self.access(self.s.GXF_CONFIG_EL1, value=1)
        self.instruction(0x6090)  # no entry point staged
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-guarded-transition')
        self.endpoint.report.pop('stop_reason')
        self.instruction(0x60a0)  # gexit while not guarded
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-guarded-transition')
        self.endpoint.report.pop('stop_reason')
        self.access(self.s.GXF_CONFIG_EL1, value=3)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-el2-register')
        self.assertFalse(self.endpoint.report['virtual_gxf']['guarded'])
        strict = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True, observe_sprr=True)
        self.tables.enable(strict)
        self.tables.access(strict, self.s.GXF_CONFIG_EL1, value=1)
        self.assertEqual(strict.report['stop_reason'], 'unsupported-el2-register')
        strict.report.pop('stop_reason')
        strict.feed(self.tables.event(0x5a006090))
        self.assertEqual(strict.report['stop_reason'], 'unsupported-exception')


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class StagedHypervisorConfigurationTests(unittest.TestCase):
    """The monitor's EL2 configuration for the level below it is recorded, never applied."""
    def setUp(self):
        self.tables = Tables()
        self.endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True, stage_el2_config=True)
        self.s = self.endpoint.sysreg
        self.tables.enable(self.endpoint)
        self.endpoint.hardware.calls.clear()

    def test_writes_stage_and_read_back_without_hardware(self):
        for reg in (self.s.AGTCNTRDIR_EL12, self.s.VTTBR_EL2, self.s.VTCR_EL2, self.s.CTRR_LOCK_EL2, self.s.HFGWTR_EL2):
            with self.subTest(register=reg):
                self.tables.access(self.endpoint, reg, value=0x5150, rt=2)
                self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
                self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'staged-el2-register')
                _, after = self.tables.access(self.endpoint, reg, read=True, rt=3)
                self.assertEqual(after.regs[3], 0x5150)
        self.assertEqual(self.endpoint.hardware.calls, [])
        self.assertEqual(self.endpoint.report['staged_el2_registers']['VTTBR_EL2'], 0x5150)
        # Unnamed EL2-encoded Apple registers are rewritten and staged with the Apple set.
        self.tables.access(self.endpoint, (3, 4, 15, 10, 0), value=0x77, rt=2)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'staged-apple-register')
        self.assertEqual(self.endpoint.report['staged_apple_registers']['S3_4_C15_C10_0'], 0x77)
        self.assertEqual(self.endpoint.hardware.calls, [])
        # Translation controls keep their own validated path: a live TCR change still stops.
        self.tables.access(self.endpoint, self.s.TCR_EL2, value=0)
        self.assertEqual(self.endpoint.report['stop_reason'], 'live-translation-control-change')

    def test_default_still_stops(self):
        strict = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True)
        self.tables.enable(strict)
        self.tables.access(strict, self.s.AGTCNTRDIR_EL12, value=3)
        self.assertEqual(strict.report['stop_reason'], 'unsupported-el2-register')
