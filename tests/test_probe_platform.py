"""Platform regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from probe_control_support import MemoryMapFixture
import os
import struct
import unittest
from types import SimpleNamespace
from sptm_entry_probe import (
    FC_XNU_AGT_ESR,
    FC_XNU_AGT_HVC,
    FC_XNU_AGT_LINKED,
    FC_XNU_AGT_WORD,
    patch_xnu_agtcnt_rdir,
    restore_xnu_agtcnt_rdir,
    FC_XNU_AHCR_NOP_SITES,
    restore_xnu_cntp_ctl,
    restore_xnu_apple_physical_timer,
    FC_XNU_M3_COMPAT_CHIPS,
    patch_xnu_m3_ahcr_nops,
    FC_XNU_PMCR1_EL12_LINKED,
    FC_XNU_PMCR1_EL1_WORD,
    FC_XNU_PMCR1_EL12_WORD,
    patch_xnu_pmcr1_bank_collapse,
    ABSENT_REGION,
    emit_memory_map_regions,
    FC_XNU_DOCKCHANNEL_UART_IPA,
    FC_XNU_DOCKCHANNEL_UART_FAR,
    FC_XNU_DOCKCHANNEL_CONFIG_IPA,
    xnu_dockchannel_uart_mapping,
    xnu_dockchannel_uart_catalog,
    match_xnu_dockchannel_uart,
    FC_XNU_PANIC_CARVEOUT_IPA,
    FC_XNU_PANIC_CARVEOUT_SIZE,
    xnu_panic_carveout_contract,
    FC_XNU_SOCD_IPA,
    FC_XNU_SOCD_SIZE,
    xnu_socd_trace_contract,
)
from sptm_entry_probe import FC_XNU_PPERM_SITES, patch_xnu_pperm_guest_window
from sptm_entry_probe import restore_xnu_pperm_guest_window


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
    def test_pperm_window_rewrites_only_exact_sites_to_distinct_hvcs(self):
        lo = min(site[2] for site in FC_XNU_PPERM_SITES)
        hi = max(site[2] for site in FC_XNU_PPERM_SITES) + 4
        segment = {'va': lo, 'filesize': hi-lo}
        chunk = bytearray(hi-lo)
        for _, _, pc, word, _, _ in FC_XNU_PPERM_SITES:
            struct.pack_into('<I', chunk, pc-lo, word)
        patched, records = patch_xnu_pperm_guest_window(bytes(chunk), segment, True)
        self.assertEqual(len(records), 8)
        for _, _, pc, _, tag, _ in FC_XNU_PPERM_SITES:
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
