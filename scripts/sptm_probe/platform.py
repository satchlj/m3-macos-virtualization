# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Existing platform contracts, compatibility transforms, and restore helpers."""
import struct
from phase53_retype_hvc import RETYPE_HVC_SITES, source_pinned_rewrite_plan
from .constants import *

def verify_gl1_fast_rewrite(source_chunk, rewritten_chunk, segment_fileoff,
                            tags):
    """Prove the pinned seven source words became the exact configured HVCs."""
    sites = []
    for name, post_offset, original_word, register, imm_low in GL1_FAST_SITE_CONTRACT:
        file_offset = post_offset - 4
        chunk_offset = file_offset - segment_fileoff
        if not 0 <= chunk_offset <= len(source_chunk) - 4:
            raise ValueError('GL1 fast-redirect site lies outside __TEXT_EXEC: ' + name)
        observed_original = struct.unpack_from('<I', source_chunk, chunk_offset)[0]
        if observed_original != original_word:
            raise ValueError('GL1 fast-redirect source drift at %s: %#x != %#x' %
                             (name, observed_original, original_word))
        imm = tags[register] | imm_low
        expected_hvc = 0xd4000002 | (imm << 5)
        observed_hvc = struct.unpack_from('<I', rewritten_chunk, chunk_offset)[0]
        if observed_hvc != expected_hvc:
            raise ValueError('GL1 fast-redirect rewrite drift at %s: %#x != %#x' %
                             (name, observed_hvc, expected_hvc))
        sites.append(dict(
            name=name, register=register,
            instruction_pc=hex(FC_IMAGE_BASE + file_offset),
            post_hvc_pc=hex(FC_IMAGE_BASE + post_offset),
            original_word=hex(original_word), hvc_imm=hex(imm),
            rewritten_word=hex(expected_hvc)))
    return sites

def xnu_dockchannel_uart_mapping(reg_base, reg_size, compatible,
                                 page_size=0x4000):
    """Validate the exact attempt-59b UART register and stage-2 page span."""
    compatible = tuple(compatible)
    if 'aapl,dock-channels' not in compatible:
        raise ValueError('dockchannel-uart compatibility mismatch')
    if reg_base != FC_XNU_DOCKCHANNEL_UART_IPA or reg_size != 0x1000:
        raise ValueError('dockchannel-uart register range mismatch')
    if reg_base & (page_size - 1) or reg_size > page_size:
        raise ValueError('dockchannel-uart is not contained in one aligned page')
    return dict(ipa=reg_base, size=page_size, device_size=reg_size,
                mapped_device_size=reg_size,
                extra_before=0, extra_after=page_size-reg_size,
                compatible=list(compatible))


def xnu_dockchannel_uart_catalog(reg0, reg1, compatible, page_size=0x4000):
    irq = xnu_dockchannel_uart_mapping(*reg1, compatible, page_size)
    config_base, config_size = reg0
    if config_base != FC_XNU_DOCKCHANNEL_CONFIG_IPA or config_size != 0x10000:
        raise ValueError('dockchannel-uart config range mismatch')
    if config_base & (page_size - 1) or config_size < page_size:
        raise ValueError('dockchannel-uart config first page is not aligned')
    config = dict(ipa=config_base, size=page_size, device_size=config_size,
                  mapped_device_size=page_size, extra_before=0, extra_after=0,
                  compatible=list(compatible))
    data_page = dict(ipa=config_base + 0xc000, size=page_size,
                     device_size=config_size, mapped_device_size=page_size,
                     extra_before=0, extra_after=0,
                     compatible=list(compatible))
    return [dict(name='irq', linked_pc=FC_XNU_DOCKCHANNEL_READ_LINKED,
                 word=FC_XNU_DOCKCHANNEL_READ_WORD, esr=FC_XNU_DOCKCHANNEL_READ_ESR,
                 far=FC_XNU_DOCKCHANNEL_UART_FAR,
                 expected_ipa=FC_XNU_DOCKCHANNEL_UART_IPA, **irq),
            dict(name='config-first-page', linked_pc=FC_XNU_DOCKCHANNEL_WRITE_LINKED,
                 word=FC_XNU_DOCKCHANNEL_WRITE_WORD, esr=FC_XNU_DOCKCHANNEL_WRITE_ESR,
                 far=FC_XNU_DOCKCHANNEL_CONFIG_FAR,
                 expected_ipa=FC_XNU_DOCKCHANNEL_CONFIG_IPA + 8, **config),
            dict(name='data-rx8-final-page', linked_pc=FC_XNU_DOCKCHANNEL_READ_LINKED,
                 word=FC_XNU_DOCKCHANNEL_READ_WORD, esr=FC_XNU_DOCKCHANNEL_RX8_ESR,
                 far=FC_XNU_DOCKCHANNEL_RX8_FAR,
                 expected_ipa=FC_XNU_DOCKCHANNEL_RX8_IPA,
                 bank='Data bank 1B', register_candidate='DockChannelDataRegs.RX_8',
                 register_offset=0x1c, register_layout_inferred=True,
                 semantics_candidate='DATA[31:8], COUNT[7:0]', **data_page)]


def match_xnu_dockchannel_uart(native_ctx, runtime_entry, catalog):
    for site in catalog or ():
        runtime_pc = runtime_entry + site['linked_pc'] - FC_XNU_ENTRY_LINKED
        if (native_ctx.elr == runtime_pc and int(native_ctx.esr) == site['esr']
                and native_ctx.far == site['far']):
            return site
    return None


def xnu_panic_carveout_contract(region, embedded_size, page_size=0x4000):
    region = tuple(map(int, region))
    if region != (FC_XNU_PANIC_CARVEOUT_IPA, FC_XNU_PANIC_CARVEOUT_SIZE):
        raise ValueError('panic carveout region-id-98 mismatch')
    if int(embedded_size) != FC_XNU_PANIC_CARVEOUT_SIZE:
        raise ValueError('embedded-panic-log-size mismatch')
    if region[0] & (page_size - 1) or region[1] % page_size:
        raise ValueError('panic carveout is not page aligned')
    return dict(ipa=region[0], size=region[1], pages=region[1] // page_size,
                region_id='region-id-98')


def match_xnu_panic_carveout(native_ctx, runtime_entry):
    return (native_ctx.elr == runtime_entry + FC_XNU_PANIC_CARVEOUT_LINKED
            - FC_XNU_ENTRY_LINKED
            and int(native_ctx.esr) == FC_XNU_PANIC_CARVEOUT_ESR
            and native_ctx.far == FC_XNU_PANIC_CARVEOUT_FAR)


def xnu_socd_trace_contract(region, device_type, page_size=0x4000):
    if tuple(map(int, region)) != (FC_XNU_SOCD_IPA, FC_XNU_SOCD_SIZE):
        raise ValueError('socd-trace-ram region mismatch')
    if device_type != 'socd-trace-ram':
        raise ValueError('socd-trace-ram device type mismatch')
    page = FC_XNU_SOCD_IPA & -page_size
    offset = FC_XNU_SOCD_IPA - page
    if offset + FC_XNU_SOCD_SIZE > page_size:
        raise ValueError('socd-trace-ram crosses a stage-2 page')
    return dict(ipa=page, source=FC_XNU_SOCD_IPA, source_size=FC_XNU_SOCD_SIZE,
                size=page_size, pages=1, data_offset=offset,
                zero_prefix=offset, zero_suffix=page_size-offset-FC_XNU_SOCD_SIZE)


def match_xnu_socd_trace(native_ctx, runtime_entry):
    return (native_ctx.elr == runtime_entry + FC_XNU_SOCD_LINKED - FC_XNU_ENTRY_LINKED
            and int(native_ctx.esr) == FC_XNU_SOCD_ESR
            and native_ctx.far == FC_XNU_SOCD_FAR
            and (int(native_ctx.regs[9]) & 0xffffffff) == 2
            and native_ctx.regs[11] == FC_XNU_SOCD_FAR)


def emit_memory_map_regions(mmap, layout, guest_base, tuple_type):
    """Emit planned regions while retaining iBoot's absent-AuxKC sentinel."""
    auxkc = {}
    for name, (offset, size) in layout['regions'].items():
        mmap._types[name] = (tuple_type, False)
        raw_value = name.endswith(('-virt', '-entry')) or name == 'slide'
        value = offset if raw_value else guest_base + offset
        if name.startswith('AuxKC') and size == 0:
            emitted = ABSENT_REGION
        else:
            emitted = (value, size)
        setattr(mmap, name, emitted)
        if name.startswith('AuxKC'):
            auxkc[name] = emitted
    for name in list(mmap._properties):
        if name.startswith('AuxKC') and name not in layout['regions']:
            mmap._types[name] = (tuple_type, False)
            setattr(mmap, name, ABSENT_REGION)
            auxkc[name] = ABSENT_REGION
        elif name.startswith('CL4') and name not in layout['regions']:
            mmap._types[name] = (tuple_type, False)
            setattr(mmap, name, (guest_base, 0))
    return {'absent_sentinel': list(ABSENT_REGION),
            'entries': {name: list(value) for name, value in sorted(auxkc.items())}}
def patch_xnu_agtcnt_rdir(chunk, segment, enabled):
    """Replace one pinned XNU EL12 write with a trap that performs that write at EL2."""
    if not enabled:
        return chunk, None
    offset = FC_XNU_AGT_LINKED - segment['va']
    original = bytes(chunk[offset:offset+4]) if 0 <= offset <= len(chunk)-4 else b''
    if original != struct.pack('<I', FC_XNU_AGT_WORD):
        raise ValueError('Pinned XNU AGTCNTRDIR_EL12 instruction changed or is outside __TEXT_EXEC')
    replacement = struct.pack('<I', 0xd4000002 | (FC_XNU_AGT_HVC << 5))
    patched = chunk[:offset] + replacement + chunk[offset+4:]
    return patched, dict(linked_va=hex(FC_XNU_AGT_LINKED), original=hex(FC_XNU_AGT_WORD),
                         replacement=hex(struct.unpack('<I', replacement)[0]),
                         operation='write guest AGTCNTRDIR_EL12 through physical EL12 alias',
                         allowed_value=3)

def patch_xnu_pperm_guest_window(chunk, segment, enabled):
    if not enabled: return chunk, []
    out, records = chunk, []
    for window_type, step, pc, word, tag, operation in FC_XNU_PPERM_SITES:
        off = pc - segment['va']
        if bytes(out[off:off+4]) != struct.pack('<I', word):
            raise ValueError('Pinned XNU PPERM instruction mismatch: '
                             + window_type + '-' + operation)
        replacement = struct.pack('<I', 0xd4000002 | (tag << 5))
        out = out[:off] + replacement + out[off+4:]
        records.append(dict(window_type=window_type, step=step,
            linked_va=hex(pc), original=hex(word),
            replacement=hex(struct.unpack('<I',replacement)[0]), operation=operation))
    return out, records


def patch_xnu_phase53_retype_hvc(chunk, segment, enabled):
    """Plan only the three pinned wrapper MOV rewrites after full verification."""
    if not enabled:
        return chunk, []

    def read_linked_word(linked_pc):
        offset = linked_pc - segment['va']
        raw = bytes(chunk[offset:offset + 4]) if 0 <= offset <= len(chunk) - 4 else b''
        return struct.unpack('<I', raw)[0] if len(raw) == 4 else -1

    plan = source_pinned_rewrite_plan(read_linked_word)
    out = bytearray(chunk)
    records = []
    for linked_pc, source_word, hvc_word in plan:
        offset = linked_pc - segment['va']
        struct.pack_into('<I', out, offset, hvc_word)
        site = next(item for item in RETYPE_HVC_SITES
                    if item.linked_pc == linked_pc)
        records.append(dict(
            phase=site.phase, linked_va=hex(linked_pc),
            runtime_va=hex(site.runtime_pc), post_hvc_pc=hex(site.post_hvc_pc),
            original=hex(source_word), replacement=hex(hvc_word),
            hvc_immediate=hex(site.hvc_immediate)))
    return bytes(out), records


def restore_xnu_agtcnt_rdir(access, register, previous, guest_returned):
    """Restore the saved guest timer bank, without touching hardware after a lost guest."""
    result = dict(register='AGTCNTRDIR_EL12', attempted=False)
    if not guest_returned:
        result['reason'] = 'guest-did-not-return'
        return result
    if previous is None:
        result['reason'] = 'guest-bank-was-not-modified'
        return result
    result['attempted'] = True
    result['restored_value'] = int(previous)
    access.msr(register, int(previous))
    result['readback'] = int(access.mrs(register))
    result['verified'] = result['readback'] == result['restored_value']
    return result

def restore_xnu_pperm_guest_window(access, register, state, guest_returned):
    result = dict(attempted=False, physical_pperm_el1_touched=False)
    if not guest_returned or not state.get('modified') or state.get('previous') is None:
        result['reason'] = 'guest-bank-not-left-modified'
        return result
    result['attempted'] = True
    result['restored'] = int(state['previous'])
    access.msr(register, result['restored'])
    result['readback'] = int(access.mrs(register))
    result['verified'] = result['readback'] == result['restored']
    return result


def restore_xnu_cntp_ctl(access, register, previous, guest_returned):
    """Restore only the guest EL02 physical-timer control bank after return."""
    result = dict(register='CNTP_CTL_EL02', attempted=False)
    if not guest_returned:
        result['reason'] = 'guest-did-not-return'
        return result
    if previous is None:
        result['reason'] = 'guest-bank-was-not-modified'
        return result
    result['attempted'] = True
    result['observed_previous'] = int(previous)
    result['restored_value'] = int(previous) & 0x3
    access.msr(register, result['restored_value'])
    result['readback_raw'] = int(access.mrs(register))
    # ISTATUS bit 2 is dynamic and read-only. Verify only ENABLE and IMASK.
    result['readback'] = result['readback_raw'] & 0x3
    result['verified'] = result['readback'] == result['restored_value']
    result['host_timer_bank_touched'] = False
    return result


def restore_xnu_apple_physical_timer(access, register, previous, guest_returned):
    """Restore the full candidate-bank value; its bit layout is not established."""
    result = dict(register='S3_4_C15_C4_3', attempted=False,
                  routing_established=False, bit_semantics_established=False,
                  physical_s3_1_bank_touched=False)
    if not guest_returned:
        result['reason'] = 'guest-did-not-return'
        return result
    if previous is None:
        result['reason'] = 'candidate-bank-was-not-modified'
        return result
    result['attempted'] = True
    result['restored_value_raw'] = int(previous)
    access.msr(register, int(previous))
    result['readback_raw'] = int(access.mrs(register))
    result['verified_exact'] = result['readback_raw'] == result['restored_value_raw']
    return result


def patch_xnu_m3_ahcr_nops(chunk, segment, enabled, chip_id):
    """Apply the upstream M3 diagnostic NOP behavior to the exact pinned AHCR pair."""
    if not enabled:
        return chunk, None
    if chip_id not in FC_XNU_M3_COMPAT_CHIPS:
        raise ValueError('AHCR diagnostic compatibility requires an upstream-supported chip ID')
    patched = bytes(chunk)
    sites = []
    for linked_va, word in FC_XNU_AHCR_NOP_SITES:
        offset = linked_va - segment['va']
        original = patched[offset:offset+4] if 0 <= offset <= len(patched)-4 else b''
        if original != struct.pack('<I', word):
            raise ValueError('Pinned XNU AHCR_EL2 instruction changed or is outside __TEXT_EXEC')
        patched = patched[:offset] + struct.pack('<I', 0xd503201f) + patched[offset+4:]
        sites.append(dict(linked_va=hex(linked_va), original=hex(word), replacement='0xd503201f'))
    return patched, dict(mode='diagnostic-upstream-nop', chip_id=hex(chip_id), sites=sites,
                         upstream_origin_commit=FC_XNU_M3_COMPAT_ORIGIN,
                         pinned_upstream_revision=FC_XNU_M3_COMPAT_PINNED,
                         hardware_effects_emulated=False)


def patch_xnu_pmcr1_bank_collapse(chunk, segment, enabled):
    """Collapse one pinned EL12 PMU filter write onto the native EL1 bank."""
    if not enabled:
        return chunk, None
    offset = FC_XNU_PMCR1_EL12_LINKED - segment['va']
    prior = bytes(chunk[offset-4:offset]) if 4 <= offset <= len(chunk)-4 else b''
    original = bytes(chunk[offset:offset+4]) if 0 <= offset <= len(chunk)-4 else b''
    if prior != struct.pack('<I', FC_XNU_PMCR1_EL1_WORD):
        raise ValueError('Pinned preceding XNU PMCR1_EL1 write changed or is outside __TEXT_EXEC')
    if original != struct.pack('<I', FC_XNU_PMCR1_EL12_WORD):
        raise ValueError('Pinned XNU PMCR1_EL12 write changed or is outside __TEXT_EXEC')
    replacement = struct.pack('<I', FC_XNU_PMCR1_EL1_WORD)
    patched = chunk[:offset] + replacement + chunk[offset+4:]
    return patched, dict(linked_va=hex(FC_XNU_PMCR1_EL12_LINKED),
                         original=hex(FC_XNU_PMCR1_EL12_WORD),
                         replacement=hex(FC_XNU_PMCR1_EL1_WORD), rt='x17',
                         prior_linked_va=hex(FC_XNU_PMCR1_EL12_LINKED-4),
                         prior_verified=hex(FC_XNU_PMCR1_EL1_WORD),
                         operation='collapse PMCR1_EL12 write onto native PMCR1_EL1 bank',
                         nested_guest_pmu_supported=False, host_register_io=False,
                         shadow_state=False)


__all__ = (
    'verify_gl1_fast_rewrite',
    'xnu_dockchannel_uart_mapping',
    'xnu_dockchannel_uart_catalog',
    'match_xnu_dockchannel_uart',
    'xnu_panic_carveout_contract',
    'match_xnu_panic_carveout',
    'xnu_socd_trace_contract',
    'match_xnu_socd_trace',
    'emit_memory_map_regions',
    'patch_xnu_agtcnt_rdir',
    'patch_xnu_pperm_guest_window',
    'patch_xnu_phase53_retype_hvc',
    'restore_xnu_agtcnt_rdir',
    'restore_xnu_pperm_guest_window',
    'restore_xnu_cntp_ctl',
    'restore_xnu_apple_physical_timer',
    'patch_xnu_m3_ahcr_nops',
    'patch_xnu_pmcr1_bank_collapse',
)
