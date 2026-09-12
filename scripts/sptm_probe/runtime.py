# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Existing run setup, source loading, execution lifecycle, and cleanup."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

from free_run_watchdog import FreeRunWatchdog
from guest_handoff import classify_entry
from step_batch import StepBatch, RECORD as BATCH_RECORD
from boot_data_audit import audit_tree
from boot_data_relocation import plan_copies, relocate_tree, read_copy
from run_manifest import RunCapture, file_identity, trace_count, append_event
from sptm_layout import plan, align, PAGE
from vel2_smoke import verify_image
from zero_loop import recognize as recognize_zero_loop
from guest_pt import validate_monitor_entry, validate_root_switch, translate
from sprr_permissions import leaf_permissions
from guest_debug import GuestDebugState, UnsupportedGuestDebug
from guest_exception_stop import GuestExceptionStop
from guarded_pause import GuardedPause
from phase53_entropy_replay import (load_pinned_source,
                                    replay_entropy_properties)
from phase53_retype_hvc import (GENTER_SITE as PHASE53_RETYPE_GENTER_SITE,
                                POST_SITE as PHASE53_RETYPE_POST_SITE,
                                PRE_SITE as PHASE53_RETYPE_PRE_SITE,
                                RETYPE_HVC_SITES,
                                RetypeHvcStateMachine,
                                canonicalize_pac_return,
                                source_pinned_rewrite_plan)

from functools import partial
from .constants import *
from .adapters import (
    PpermWindowLimit, Gl1FastRedirect,
    TpidrGl2FastShadow,
    Vel2StepFilter,
    audit_and_disable_tpidr_gl2_fast_shadow,
    phase53_hvc_gl1_counter_checks,
)
from .platform import *
from .callback import RunBindings, stopped as dispatch_event

def run_probe(a, report, save, capture):
    capture.phase('layout-validation')
    layout = plan(a.payload, 0x100000, 0x4000)
    report['layout'] = layout
    save()
    if not a.execute:
        report['stop_reason'] = 'offline-layout-validated'
        print('SPTM layout validated offline; no target accessed.')
        return
    capture.phase('target-setup')
    sys.path.insert(0, str(a.checkout.resolve()/'proxyclient'))
    from m1n1.proxy import UartInterface, M1N1Proxy, START, EXC, EXC_RET, ExcInfo, IODEV
    from m1n1.proxyutils import ProxyUtils
    from m1n1.adt import load_adt, ADT2Tuple
    from m1n1.tgtypes import BootArgs_r3
    from m1n1.hv import HV
    from m1n1.hv.types import HV_EVENT
    from m1n1.hv.vel2 import patch_synthetic_code
    from m1n1.sysreg import SCTLR_EL12, TCR_EL12, TTBR0_EL12, TTBR1_EL12, MAIR_EL12, CPACR_EL12, MDCR_EL2, MDSCR_EL1, ESR_ISS_MSR, OSLAR_EL1, sysreg_rev, sysreg_fwd, HCR_EL2, SCTLR_EL2, SCTLR_EL1, CNTVOFF_EL2, SPRR_PPERM_EL1, SPRR_UPERM_EL0, SPRR_CONFIG_EL1, GXF_CONFIG_EL1, SPRR_AMRANGE_EL1, SPRR_UMPRR_EL1, SPRR_PMPRR_EL1, SPRR_UPERM_SH1_EL1, SPRR_UPERM_SH2_EL1, SPRR_UPERM_SH3_EL1, SPRR_PPERM_SH1_EL1, SPRR_PPERM_SH2_EL1, SPRR_PPERM_SH3_EL1, GXF_STATUS_EL1, GXF_ENTRY_EL1, GXF_PABENTRY_EL1, VBAR_GL1, TPIDR_GL1, ASPSR_GL1, SPSR_GL1, ELR_GL1, ESR_GL1, FAR_GL1, AFSR1_GL1, ASPSR_EL1, VMKEYLO_EL2, VMKEYHI_EL2, APSTS_EL12, APCTL_EL1, APCTL_EL12, KERNKEYLO_EL1, KERNKEYHI_EL1
    from m1n1.sysreg import VM_TMR_FIQ_ENA_EL2, TCR_EL1, TCR_EL2, TTBR0_EL1, TTBR0_EL2, TTBR1_EL1, TTBR1_EL2, MAIR_EL1, MAIR_EL2, HID16_EL1, ESR_EL12, ELR_EL12, FAR_EL12, SPSR_EL12, VBAR_EL12, AFSR1_EL12, AGTCNTRDIR_EL12, CNTP_CTL_EL02
    translation_banks = {
        TCR_EL1: TCR_EL12, TCR_EL2: TCR_EL12,
        TTBR0_EL1: TTBR0_EL12, TTBR0_EL2: TTBR0_EL12,
        TTBR1_EL1: TTBR1_EL12, TTBR1_EL2: TTBR1_EL12,
        MAIR_EL1: MAIR_EL12, MAIR_EL2: MAIR_EL12,
    }
    iface = UartInterface(a.device)
    p = M1N1Proxy(iface)
    iface.nop(); p.nop()
    expected = capture.manifest['expected_runtime']
    if expected is None or file_identity(a.checkout/'build/m1n1-raw.elf') != expected:
        raise ValueError('Expected runtime changed after manifest capture')
    report['image_sections'] = verify_image(iface, p.get_base(), a.checkout/'build/m1n1-raw.elf')
    u = ProxyUtils(p)
    # These values differed after the first monitor run on a fresh runtime.
    # Observe them without claiming a complete architectural reset or changing HID16.
    observed_registers = {'APCTL_EL12': APCTL_EL12, 'HID16_EL1': HID16_EL1}
    report['initial_observed_registers'] = {name: u.mrs(reg) for name, reg in observed_registers.items()}
    exception_registers = {'ESR_EL12': ESR_EL12, 'ELR_EL12': ELR_EL12,
                           'FAR_EL12': FAR_EL12, 'SPSR_EL12': SPSR_EL12, 'VBAR_EL12': VBAR_EL12}
    report['initial_guest_exception_registers'] = {name: u.mrs(reg) for name, reg in exception_registers.items()}
    report['complete_register_reset_claimed'] = False
    adt_bytes = u.get_adt()
    capture.save_input('host-device-tree.adt', adt_bytes)
    report['device_tree_sha256'] = hashlib.sha256(adt_bytes).hexdigest()
    adt = load_adt(adt_bytes)
    if a.xnu_phase53_adt_entropy_replay:
        source_blob, source_identity = load_pinned_source(
            Path(__file__).resolve().parents[1])
        captured_source = capture.save_input(
            'phase53-entropy-source-attempt-108.adt', source_blob)
        report['xnu_phase53_adt_entropy_replay'] = replay_entropy_properties(
            adt, load_adt(source_blob), source_identity)
        report['xnu_phase53_adt_entropy_replay']['captured_source'] = captured_source
    else:
        report['xnu_phase53_adt_entropy_replay'] = {
            'requested': False, 'applied': False}
    chip_id = int(adt['chosen'].chip_id)
    report['chip_id'] = hex(chip_id)
    if a.xnu_pperm_guest_window and chip_id not in FC_XNU_M3_COMPAT_CHIPS:
        raise ValueError('xnu-pperm-guest-window requires verified M3 chip identity')
    dockchannel_mmio = None
    if a.xnu_dockchannel_uart_mmio:
        dockchannel = adt['arm-io']['dockchannel-uart']
        reg0 = tuple(map(int, dockchannel.get_reg(0)))
        reg1 = tuple(map(int, dockchannel.get_reg(1)))
        dockchannel_mmio = xnu_dockchannel_uart_catalog(
            reg0, reg1, dockchannel.compatible)
        report['xnu_dockchannel_uart_mmio'] = dict(
            enabled=True, mappings=[dict(site, mapped=False,
                linked_pc=hex(site['linked_pc']), word=hex(site['word']),
                expected_far=hex(site['far']), expected_esr=hex(site['esr']))
                for site in dockchannel_mmio])
    panic_carveout = None
    if a.xnu_private_panic_carveout:
        carveouts = adt['chosen']['carveout-memory-map']
        panic_carveout = xnu_panic_carveout_contract(
            carveouts._properties['region-id-98'],
            adt['chosen'].embedded_panic_log_size)
        report['xnu_private_panic_carveout'] = dict(
            enabled=True, copied=False, mapped=False,
            original_writes=False, **panic_carveout)
    socd_trace = None
    if a.xnu_private_socd_trace:
        node = adt['socd-trace-ram']
        socd_trace = xnu_socd_trace_contract(
            node.get_reg(0), node._properties.get('device_type'))
        report['xnu_private_socd_trace'] = dict(
            enabled=True, copied=False, mapped=False, original_writes=False,
            source_bytes_requested=FC_XNU_SOCD_SIZE, source_bytes_read=0,
            adjacent_source_bytes_read=0,
            **socd_trace)
    mmap = adt['chosen']['memory-map']
    # SPTM's hibernation bootstrap requires a chosen/hibernation node to exist, or
    # it panics "chosen/hibernation node not found in DT for key" (0xc0f50, hit in
    # attempt-28). The individual keys (key-exclave / key-sptm-ctrr / key-xnu-ctrr)
    # are optional: the reader (0xc0f08) returns 0 for an absent key and every
    # caller skips it (cbz x0), so an empty node suffices for a non-hibernating
    # research boot.
    if 'hibernation' not in [c.name for c in adt['chosen']]:
        adt.create_node('chosen/hibernation')
    # sptm_hibentry.c strictly requires the CTRR/exclave keys to be PRESENT (panics
    # "key not found in DT", 0xe2b94, attempt-29) and non-zero (an all-zero key is
    # treated as NULL, 0xe1498 scan). They are 48-byte values copied into an SPTM
    # struct; on a cold research boot we never resume hibernation, so dummy non-zero
    # keys let boot proceed. If SPTM instead programs CTRR hardware with them, the
    # probe traps the system-register write (a clean stop, not a brick). Real per-boot
    # key material from iBoot/SEP is unavailable; this is a deliberate stub.
    from construct import GreedyBytes as _GreedyBytes
    _hib = adt['chosen']['hibernation']
    # Per-key expected sizes from the reader's size check (0xc0fa8, "key has
    # unexpected size" at line 474): key-exclave is 32 bytes, the two CTRR keys are
    # 48. attempt-30 used 48 for all three and tripped the size check on key-exclave.
    _hib_key_sizes = {'key-sptm-ctrr': 48, 'key-xnu-ctrr': 48, 'key-exclave': 32}
    for _k, _sz in _hib_key_sizes.items():
        if _k not in _hib._properties:
            _hib._types[_k] = (_GreedyBytes, False)
            setattr(_hib, _k, b'\x11' * _sz)
    report['hibernation_stub_keys'] = {'sizes': _hib_key_sizes, 'fill': '0x11',
                                       'note': 'dummy non-zero; cold boot, no resume'}
    tc_addr, tc_size = mmap.TrustCache
    if not 0 < tc_size <= 0x1000000:
        raise ValueError('Unexpected trustcache size')
    trustcache = iface.readmem(tc_addr, tc_size)
    report['trustcache_sha256'] = hashlib.sha256(trustcache).hexdigest()
    layout = plan(a.payload, 0x100000, len(trustcache))
    report['layout'] = layout
    boot_copies = None
    if a.relocate_boot_data:
        boot_copies = plan_copies(mmap, u.ba.phys_base, u.ba.mem_size, layout['size'])
        layout['boot_data_copies'] = boot_copies
        layout['size'] = boot_copies['end_offset']
    guest_size = align(layout['size']+0x4000000)
    base = u.memalign(0x2000000, guest_size)
    entry = base+layout['entry_offset']
    batch = StepBatch(p, iface, u.memalign(16, a.step_batch*BATCH_RECORD.size), a.step_batch) if a.step_batch else None
    report['native_batch_capacity'] = a.step_batch
    vector_stop = GuestExceptionStop(a.step_batch) if a.stop_on_vector_entry else None
    report['vector_stop_enabled'] = vector_stop is not None
    # A second, identical scanner driven by VBAR_GL1 catches the guarded-world
    # divert (a PC in the guarded vector range) that the EL1 VBAR_EL12 scanner
    # cannot see. VBAR_GL1 is read live per host stop (0 = not yet in guarded world).
    guarded_vector_stop = GuestExceptionStop(a.step_batch) if a.stop_on_guarded_vector else None
    report['guarded_vector_stop_enabled'] = guarded_vector_stop is not None
    guarded_vbar = 0
    # Single-step only a bounded [start, end) window; batch elsewhere.
    ss_window = None
    if a.single_step_window is not None:
        _p = a.single_step_window.split(':')
        _s = int(_p[0], 0)
        ss_window = (_s, _s + (int(_p[1], 0) if len(_p) > 1 else 1))
    report['single_step_window'] = list(ss_window) if ss_window else None
    # Multi-call driver: one real guarded call per selector, all in one run. The idle->genter
    # patch makes the idle a genter loop; we set x16 at each genter (FC_IDLE_PC) and capture x0
    # at each return (FC_IDLE_PC+4). gc_state is a mutable dict so no nonlocal is needed.
    multi_call_selectors = [int(s, 0) for s in a.guarded_call_selectors.split(',') if s.strip()] if a.guarded_call_selectors else None
    gc_state = dict(index=0, in_call=False, started=0)
    report['guarded_call_selectors'] = [hex(s) for s in multi_call_selectors] if multi_call_selectors else None
    guard_pause = GuardedPause(capture.root/'pauses', timeout_seconds=a.pause_timeout) if a.pause_on_guard else None
    report['guard_pause_enabled'] = guard_pause is not None
    report.update(guest_base=base, guest_size=guest_size, entry=entry)
    # Construct the full guest image locally, including all zero-filled segment tails.
    blob = bytearray(guest_size)
    sources = {n: Path(meta['path']).read_bytes() for n,meta in layout['images'].items()}
    if dockchannel_mmio is not None:
        segment = layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        for site in dockchannel_mmio:
            source_offset = segment['fileoff'] + site['linked_pc'] - segment['va']
            source_word, = struct.unpack_from('<I', sources['kernelcache'], source_offset)
            if source_word != site['word']:
                raise ValueError('pinned XNU dockchannel instruction mismatch: '+site['name'])
    if panic_carveout is not None:
        segment = layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        source_offset = (segment['fileoff'] + FC_XNU_PANIC_CARVEOUT_LINKED
                         - segment['va'])
        source_word, = struct.unpack_from('<I', sources['kernelcache'], source_offset)
        if source_word != FC_XNU_PANIC_CARVEOUT_WORD:
            raise ValueError('pinned XNU panic carveout instruction mismatch')
        report['xnu_private_panic_carveout'].update(
            linked_pc=hex(FC_XNU_PANIC_CARVEOUT_LINKED), instruction=hex(source_word),
            expected_esr=hex(FC_XNU_PANIC_CARVEOUT_ESR),
            expected_far=hex(FC_XNU_PANIC_CARVEOUT_FAR))
    if socd_trace is not None:
        segment = layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        source_offset = segment['fileoff'] + FC_XNU_SOCD_LINKED - segment['va']
        source_word, = struct.unpack_from('<I', sources['kernelcache'], source_offset)
        if source_word != FC_XNU_SOCD_WORD:
            raise ValueError('pinned XNU SOCd trace instruction mismatch')
        report['xnu_private_socd_trace'].update(
            linked_pc=hex(FC_XNU_SOCD_LINKED), instruction=hex(source_word),
            expected_esr=hex(FC_XNU_SOCD_ESR), expected_far=hex(FC_XNU_SOCD_FAR))
    if any(hashlib.sha256(data).hexdigest() != layout['images'][name]['sha256']
           for name, data in sources.items()):
        raise ValueError('Payload changed between layout validation and image construction')
    if panic_carveout is not None:
        source_data = read_copy(iface.readmem, panic_carveout['ipa'], panic_carveout['size'])
        source_sha = hashlib.sha256(source_data).hexdigest()
        private_host = u.memalign(PAGE, panic_carveout['size'])
        spans = ((base, base + guest_size, 'guest identity allocation'),
                 (panic_carveout['ipa'], panic_carveout['ipa'] + panic_carveout['size'],
                  'original firmware carveout'))
        for lo, hi, name in spans:
            if private_host < hi and lo < private_host + panic_carveout['size']:
                raise ValueError('Private panic copy overlaps '+name)
        for offset in range(0, panic_carveout['size'], 0x10000):
            iface.writemem(private_host + offset, source_data[offset:offset + 0x10000])
        p.dc_cvau(private_host, panic_carveout['size'])
        private_data = read_copy(iface.readmem, private_host, panic_carveout['size'])
        private_sha = hashlib.sha256(private_data).hexdigest()
        if private_sha != source_sha or private_data != source_data:
            raise ValueError('Private panic carveout copy verification failed')
        panic_carveout['private_host'] = private_host
        report['xnu_private_panic_carveout'].update(
            copied=True, private_host=private_host, source_sha256=source_sha,
            private_sha256=private_sha, transient_source_bytes=True,
            raw_source_artifact_saved=False,
            private_outside_guest=True, private_outside_original=True)
    if socd_trace is not None:
        source_data = read_copy(iface.readmem, socd_trace['source'], socd_trace['source_size'])
        report['xnu_private_socd_trace']['source_bytes_read'] = len(source_data)
        source_sha = hashlib.sha256(source_data).hexdigest()
        private_page = bytearray(PAGE)
        start = socd_trace['data_offset']
        private_page[start:start + len(source_data)] = source_data
        private_host = u.memalign(PAGE, PAGE)
        spans = ((base, base + guest_size, 'guest identity allocation'),
                 (socd_trace['ipa'], socd_trace['ipa'] + PAGE,
                  'original SOCd containing page'))
        for lo, hi, name in spans:
            if private_host < hi and lo < private_host + PAGE:
                raise ValueError('Private SOCd copy overlaps ' + name)
        iface.writemem(private_host, private_page)
        p.dc_cvau(private_host, PAGE)
        private_data = read_copy(iface.readmem, private_host, PAGE)
        private_sha = hashlib.sha256(private_data).hexdigest()
        if private_data != bytes(private_page):
            raise ValueError('Private SOCd page copy verification failed')
        socd_trace['private_host'] = private_host
        report['xnu_private_socd_trace'].update(
            copied=True, private_host=private_host, source_sha256=source_sha,
            private_page_sha256=private_sha, private_outside_guest=True,
            private_outside_original=True, raw_source_artifact_saved=False)
    from m1n1.hv.vel2 import REGISTERS
    # Public Apple register listing names this auxiliary virtual counter offset.
    # Only its zero-offset state is modelled; no real Apple register is written.
    apple_cntvoff = (3,1,15,9,4)
    permission_shadow = {sysreg_fwd[name]: 0 for name in SPRR_PERMISSION_REGISTERS}
    apple_shadow = {(sysreg_fwd[name] if isinstance(name, str) else name): 0 for name in APPLE_OBSERVED_REGISTERS}
    extra_regs = sorted({reg for reg in sysreg_rev if reg[0] == 3 and reg[1] == 4 and reg not in REGISTERS} | set(translation_banks) | set(permission_shadow) | set(apple_shadow) | {VM_TMR_FIQ_ENA_EL2,apple_cntvoff,SPRR_CONFIG_EL1,GXF_CONFIG_EL1,GXF_STATUS_EL1})
    if len(extra_regs) > 256:
        raise ValueError('EL2 register probe encoding exhausted')
    tpidr_gl2_register = sysreg_fwd['TPIDR_GL2']
    tpidr_gl2_shadow_tag_base = 0x8000 | (extra_regs.index(tpidr_gl2_register) << 6)
    tpidr_gl2_fast_shadow = None
    gl1_fast_tags = {
        name: 0x8000 | (extra_regs.index(sysreg_fwd[name]) << 6)
        for name in Gl1FastRedirect.TAG_NAMES}
    gl1_fast_redirect = None
    txm_sstep_fast_path = None
    report['xnu_txm_sstep_fast_path'] = dict(
        requested=bool(a.xnu_txm_sstep_fast_path), activated=False,
        range0=[hex(value) for value in FC_TXM_RUNTIME_TEXT],
        range1=[hex(value) for value in FC_SPTM_RUNTIME_TEXT],
        terminal_pc=hex(FC_XNU_TXM_HANDLER_CMD1_RETAB),
        expected_first_pc=hex(FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR),
        max_steps=FC_TXM_COMPLETION_FAST_STEPS,
        activation_gate=(
            'exact cmd1 completion SVC PC plus source/live instruction match'),
        scope_limits=(
            'software-step callbacks only; fail closed outside TXM/SPTM text, '
            'at the exact XNU RETAB trampoline, or at the firmware step limit'))
    report['xnu_phase53_retype_survey'] = dict(
        requested=bool(a.xnu_phase53_retype_survey), activated=False,
        call_limit=a.xnu_phase53_retype_survey_limit,
        per_leg_step_limit=FC_XNU_PHASE53_RETYPE_SURVEY_FAST_STEPS,
        aggregate_step_limit=FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS,
        rearm_limit=FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS,
        target_types=[hex(value) for value in
                      FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES],
        primary_target='0xb->0x14')
    report['xnu_phase53_retype_hvc_fast_path'] = dict(
        requested=bool(a.xnu_phase53_retype_hvc_fast_path), activated=False,
        call_limit=a.xnu_phase53_retype_survey_limit,
        pre_hvc=hex(PHASE53_RETYPE_PRE_SITE.hvc_immediate),
        genter_hvc=hex(PHASE53_RETYPE_GENTER_SITE.hvc_immediate),
        post_hvc=hex(PHASE53_RETYPE_POST_SITE.hvc_immediate),
        activation_gate=(
            'verified allocation trace plus three atomically source-pinned wrapper rewrites'),
        scope_limits=(
            'strict PRE/GENTER/POST ordering; exact source/live wrapper, caller frame, '
            'owned FTE, seven base GL1 redirects, and an optional exact four-site '
            'nested redirect sequence; at most 64 calls'))
    report['xnu_phase53_descriptor_bind'] = dict(
        requested=bool(a.xnu_phase53_descriptor_bind), activated=False,
        per_leg_step_limit=FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS,
        aggregate_step_limit=FC_XNU_PHASE53_DESCRIPTOR_BIND_TOTAL_STEPS,
        rearm_limit=FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS,
        target='primary 0xb->0x14 page followed by selector-3 L2 bind')
    report['xnu_phase53_leaf_page_bind'] = dict(
        requested=bool(a.xnu_phase53_leaf_page_bind), activated=False,
        per_leg_step_limit=FC_XNU_PHASE53_LEAF_BIND_FAST_STEPS,
        aggregate_step_limit=FC_XNU_PHASE53_LEAF_BIND_TOTAL_STEPS,
        rearm_limit=FC_XNU_PHASE53_LEAF_BIND_MAX_REARMS,
        target='first exact selector-2 leaf bind below the verified L2 table')
    if a.xnu_txm_sstep_fast_path:
        try:
            txm_sstep_fast_path = Vel2StepFilter(p)
            report['xnu_txm_sstep_fast_path']['proxy_api'] = dict(
                enable=Vel2StepFilter.ENABLE,
                status=Vel2StepFilter.STATUS,
                disable=Vel2StepFilter.DISABLE)
            report['xnu_txm_sstep_fast_path']['preflight'] = (
                txm_sstep_fast_path.prepare())
        except Exception as fast_path_error:
            report['xnu_txm_sstep_fast_path']['preflight_error'] = str(
                fast_path_error)
            report['stop_reason'] = 'xnu-txm-sstep-fast-path-unavailable'
            try:
                save()
            finally:
                iface.dev.close()
            raise
    report['xnu_tpidr_gl2_fast_shadow'] = dict(
        requested=bool(a.xnu_tpidr_gl2_fast_shadow), activated=False,
        register='TPIDR_GL2', encoding=list(tpidr_gl2_register),
        tag_base=hex(tpidr_gl2_shadow_tag_base),
        value_provenance='existing host apple_shadow at the activation gate',
        activation_gate=('verified kernelcache continuation after the bounded XNU prefix, '
                         'before native handoff and SS clear'),
        scope_limits=('accelerates only the exact rewritten TPIDR_GL2 0x8000-family HVC tag; '
                      'does not make native GL2 access valid, emulate other registers, enforce '
                      'SPRR, or establish macOS boot'))
    if a.xnu_tpidr_gl2_fast_shadow:
        try:
            tpidr_gl2_fast_shadow = TpidrGl2FastShadow(p)
            report['xnu_tpidr_gl2_fast_shadow']['proxy_api'] = dict(
                enable=TpidrGl2FastShadow.ENABLE,
                status=TpidrGl2FastShadow.STATUS,
                disable=TpidrGl2FastShadow.DISABLE)
            report['xnu_tpidr_gl2_fast_shadow']['preflight'] = (
                tpidr_gl2_fast_shadow.prepare())
        except Exception as fast_shadow_error:
            report['xnu_tpidr_gl2_fast_shadow']['preflight_error'] = str(fast_shadow_error)
            report['stop_reason'] = 'xnu-tpidr-gl2-fast-shadow-unavailable'
            try:
                save()
            finally:
                iface.dev.close()
            raise
    report['xnu_gl1_fast_redirect'] = dict(
        requested=bool(getattr(a, 'xnu_gl1_fast_redirect', False)), activated=False,
        pc_base=hex(FC_IMAGE_BASE),
        tags={name: hex(value) for name, value in gl1_fast_tags.items()},
        activation_gate=(
            'verified kernelcache continuation plus eleven pinned source/HVC words, '
            'before native handoff and SS clear'),
        scope_limits=(
            'accelerates only eleven exact post-HVC PC/full-immediate pairs through '
            'live GL12 aliases; every other guarded access remains host-visible'))
    if getattr(a, 'xnu_gl1_fast_redirect', False):
        try:
            gl1_fast_redirect = Gl1FastRedirect(p)
            report['xnu_gl1_fast_redirect']['proxy_api'] = dict(
                enable=Gl1FastRedirect.ENABLE,
                status=Gl1FastRedirect.STATUS,
                disable=Gl1FastRedirect.DISABLE)
            report['xnu_gl1_fast_redirect']['preflight'] = (
                gl1_fast_redirect.prepare())
        except Exception as gl1_fast_error:
            report['xnu_gl1_fast_redirect']['preflight_error'] = str(gl1_fast_error)
            report['stop_reason'] = 'xnu-gl1-fast-redirect-unavailable'
            try:
                save()
            finally:
                iface.dev.close()
            raise
    # R2 (--real-guarded): mirror the vel2 HV's own per-register guest SPRR/GXF handling (hv_exc.c).
    #  real_native  -> not trapped by the HV; the guest accesses them natively (SPRR/GXF *config* +
    #    guarded entry). SPRR_CONFIG has no _EL12 alias (attempt-15 EC-0), so it MUST be native.
    #  real_redirect -> SYSREG_MAP: the guest's EL1 access is redirected to its _EL12/_GL12 alias
    #    (perms, APCTL, GL exception bank). SPRR_PPERM native is EC-0 (attempt-14), so it MUST map.
    #  genter/gexit stay native (patched-off above).
    # TPIDR_GL2 was here (accessed natively), but attempt-19 proved that wrong: SPTM's
    # first guarded instruction `msr TPIDR_GL2` traps UNDEFINED (ESR EC 0x00) because a
    # GL2 register is undefined at the GL1 level our EL1 guest reaches under genter. It is
    # already in APPLE_OBSERVED_REGISTERS, so dropping it from real_native routes it to the
    # apple_shadow handler (trap-to-HVC, store/return a shadow value) like the rest of the
    # GL2/EL12 bank. TPIDR_GL1 stays native: it is a GL1 register, defined at GL1, and has
    # not faulted; if it does, the guarded-vector stop will catch it cleanly.
    real_native = {sysreg_fwd[n] for n in ('SPRR_CONFIG_EL1','GXF_CONFIG_EL1','GXF_ENTRY_EL1',
        'GXF_PABENTRY_EL1','GXF_STATUS_EL1','TPIDR_GL1')}
    real_redirect = {sysreg_fwd[n] for n in ('SPRR_PPERM_EL1','SPRR_UPERM_EL0','APCTL_EL1',
        'SPSR_GL1','ASPSR_GL1','ELR_GL1','ESR_GL1')}
    if a.real_guarded_vbar:
        real_redirect.add(VBAR_GL1)
    patched_count = 0
    def patch_probe_code(chunk):
        # Host-side VHE controls; monitor MMU requires an explicit validated profile.
        from m1n1.hv.vel2 import sysreg_opcode
        patched = bytearray(patch_synthetic_code(chunk))
        for offset in range(0,len(chunk),4):
            word = struct.unpack_from('<I',chunk,offset)[0]
            for reg, tag in [(HCR_EL2,0x6000),(SCTLR_EL2,0x6040),(SCTLR_EL1,0x6040)]:
                for read in (False,True):
                    if word & ~31 == sysreg_opcode(reg,read):
                        imm = tag | (int(read)<<5) | (word & 31)
                        struct.pack_into('<I',patched,offset,0xd4000002 | (imm<<5))
            for index,reg in enumerate(extra_regs):
                if a.real_guarded and reg in real_native:
                    continue  # not trapped by the HV: the guest accesses these natively
                for read in (False,True):
                    if word & ~31 == sysreg_opcode(reg,read):
                        imm = 0x8000 | (index<<6) | (int(read)<<5) | (word & 31)
                        struct.pack_into('<I',patched,offset,0xd4000002 | (imm<<5))
            if not a.real_guarded and word & 0xfffffff0 == 0x00201420:
                struct.pack_into('<I',patched,offset,0xd4000002 | ((0x6090 | (word & 15))<<5))
            elif not a.real_guarded and word == 0x00201400:
                struct.pack_into('<I',patched,offset,0xd4000002 | (0x60a0<<5))
            if not a.free_run and word == 0xd69f03e0:
                # Single-step mode retains the legacy overlay as an observation stop.
                # Free-run uses base ERET_HVC and verifies the actual target mapping.
                struct.pack_into('<I',patched,offset,0xd4000002 | (0x6080<<5))
        return bytes(patched)
    shadow_sprr_config = 0
    real_sprr_on = False
    shadow_hcr = 0
    shadow_sctlr = 0
    monitor_mmu_validated = False
    guest_debug = GuestDebugState()
    report['guest_debug'] = guest_debug.snapshot()
    for placement in layout['placements']:
        which, name = placement['image'], placement['segment']
        seg = layout['images'][which]['segments'][name]
        chunk = sources[which][seg['fileoff']:seg['fileoff']+seg['filesize']]
        if which == 'sptm' and name == '__TEXT_EXEC':
            rewritten = patch_probe_code(chunk)
            if getattr(a, 'xnu_gl1_fast_redirect', False):
                report['xnu_gl1_fast_redirect']['verified_sites'] = (
                    verify_gl1_fast_rewrite(
                        chunk, rewritten, seg['fileoff'], gl1_fast_tags))
            patched_count += sum(chunk[i:i+4] != rewritten[i:i+4] for i in range(0,len(chunk),4))
            chunk = rewritten
            if a.first_contact or a.guarded_call_selectors:
                # Patch the WFE at the normal-world idle (0xf8b88) to genter #0 so SPTM,
                # on reaching idle, issues a real guarded call. __TEXT_EXEC fileoff ==
                # image offset, so the chunk offset is (VA - image_base) - seg fileoff.
                fc_off = (FC_IDLE_PC - FC_IMAGE_BASE) - seg['fileoff']
                original = bytes(chunk[fc_off:fc_off+4]) if 0 <= fc_off <= len(chunk)-4 else b''
                if original == struct.pack('<I', 0xd503205f):  # confirm it is the WFE
                    chunk = chunk[:fc_off] + struct.pack('<I', FC_GENTER) + chunk[fc_off+4:]
                    report['first_contact_patch'] = dict(va=hex(FC_IDLE_PC), chunk_offset=fc_off,
                        original='0xd503205f (wfe)', patched=hex(FC_GENTER))
                else:
                    report['first_contact_patch_error'] = (
                        'idle PC 0x%x did not hold the expected WFE (found %s at chunk off %d); refusing to patch'
                        % (FC_IDLE_PC, original.hex() or 'out-of-range', fc_off))
                    raise ValueError(report['first_contact_patch_error'])
        elif which == 'kernelcache' and name == '__TEXT_EXEC' and a.xnu_run:
            chunk, patch_record = patch_xnu_agtcnt_rdir(chunk, seg, True)
            report['xnu_agtcnt_rdir_patch'] = patch_record
            chunk, compat_record = patch_xnu_m3_ahcr_nops(
                chunk, seg, a.xnu_m3_nop_ahcr_compat, chip_id)
            if compat_record is not None:
                report['xnu_m3_ahcr_compat'] = compat_record
            chunk, report['xnu_pmcr1_bank_collapse'] = patch_xnu_pmcr1_bank_collapse(
                chunk, seg, True)
            _, retype_hvc_patches = patch_xnu_phase53_retype_hvc(
                chunk, seg, a.xnu_phase53_retype_hvc_fast_path)
            if retype_hvc_patches:
                report['xnu_phase53_retype_hvc_fast_path'].update(
                    planned_patches=retype_hvc_patches,
                    patch_scope='late live writes to the isolated guest image only')
            chunk, pperm_patches = patch_xnu_pperm_guest_window(
                chunk, seg, a.xnu_pperm_guest_window)
            if pperm_patches:
                report['xnu_pperm_guest_window'] = dict(enabled=True, patches=pperm_patches,
                    sequence=[], memcpy_crossed=False, atomic_crossed=False,
                    physical_pperm_el1_touched=False,
                    chip_id=hex(chip_id), profile='native XNU under real-guarded VEL2',
                    limit=a.xnu_pperm_guest_window_limit, started_windows=0,
                    completed_windows=0, memcpy_crossed_windows=0,
                    atomic_crossed_windows=0)
        off = placement['offset']
        blob[off:off+len(chunk)] = chunk
    report['sptm_rewritten_instructions'] = patched_count
    report['auxkc_memory_map'] = emit_memory_map_regions(mmap, layout, base, ADT2Tuple)
    if boot_copies is not None:
        report['boot_data_relocations'] = relocate_tree(adt, boot_copies, base)
        for index, span in enumerate(boot_copies['spans']):
            data = read_copy(iface.readmem, span['start'], span['size'])
            if len(data) != span['size']:
                raise ValueError('Truncated host boot input')
            capture.save_input(f'boot-data-{index}.bin', data)
            blob[span['offset']:span['offset']+span['size']] = data
    # The probe maps no MMIO or firmware memory outside this owned RAM allocation.
    # Existing ADT peripheral descriptions remain observations, not stage-2 permissions.
    adt_blob = adt.build()
    report['guest_boot_data_audit'] = audit_tree(adt, base, guest_size)
    if len(adt_blob) > 0x100000:
        raise ValueError('ADT exceeded reservation')
    capture.save_input('guest-device-tree.adt', adt_blob)
    off = layout['adt_offset']
    blob[off:off+len(adt_blob)] = adt_blob
    off = layout['regions']['TrustCache'][0]
    blob[off:off+len(trustcache)] = trustcache
    ba = u.ba.copy()
    if ba.revision != 3:
        raise ValueError('This probe expects the observed revision-3 bootargs')
    ba.virt_base = layout['virtual_base']
    ba.phys_base = base
    ba.mem_size = guest_size
    ba.mem_size_act = guest_size
    ba.top_of_kernel_data = base+layout['size']
    ba.devtree = ba.virt_base+layout['adt_offset']
    ba.devtree_size = len(adt_blob)
    ba.video.base = 0
    ba.video.display = 0
    ba.cmdline = ''
    args = BootArgs_r3.build(ba)
    args_off = layout['regions']['BootArgs'][0]
    blob[args_off:args_off+len(args)] = args
    original = bytes(blob[layout['entry_offset']:layout['entry_offset']+4])
    # First stop establishes the instruction budget before executing any monitor instruction.
    struct.pack_into('<I',blob,layout['entry_offset'],0xd4000002 | (0x7ffe << 5))
    report['guest_image_sha256'] = hashlib.sha256(blob).hexdigest()
    save()
    print('Writing isolated guest RAM',guest_size,flush=True)
    u.compressed_writemem(base,blob,True)
    p.dc_cvau(base,guest_size)
    p.ic_ivau(base,guest_size)
    current = p.iodev_whoami()
    for dev in IODEV:
        if dev >= IODEV.USB0 and dev != current:
            p.iodev_set_usage(dev,0)
    p.hv_init()
    u.msr(SCTLR_EL12,0x30d00800)
    u.msr(CPACR_EL12,3 << 20)
    if not u.cpu_features.apple_sysregs_unlocked:
        raise RuntimeError('Guest pointer-authentication setup requires unlocked system registers')
    # Same guest PAuth initialization as public HV.init; these are fixed test keys.
    u.msr(VMKEYLO_EL2,0x4E7672476F6E6147)
    u.msr(VMKEYHI_EL2,0x697665596F755570)
    u.msr(APSTS_EL12,1)
    u.msr(MDCR_EL2,u.mrs(MDCR_EL2) | (1 << 8))
    if not a.free_run:
        # MDSCR_EL1.SS is the software-step MASTER enable; with it set the step state
        # machine re-arms after every instruction (clearing only SPSR.SS gives just one
        # free instruction, then it steps again). Free-run leaves it clear so the guest
        # runs natively between traps. The entry-guard still fires: entry is reached via
        # the injected hvc, which traps regardless of MDSCR.SS.
        u.msr(MDSCR_EL1,u.mrs(MDSCR_EL1) | 1)
    if a.real_guarded:
        # Establish the EL2 SPRR/GXF context before the guest runs, exactly as the vel2 HV does at
        # guest boot (hv/__init__.py, apple_sysregs_unlocked path). Without this the context is
        # absent, so both the guest's native SPRR/GXF access and the _EL12 aliases are EC-0 undefined
        # (attempts 14-16). This makes real guarded execution possible.
        u.msr(SPRR_CONFIG_EL1, 1)
        u.msr(GXF_CONFIG_EL1, 1)
    if p.hv_map(base,base | HV.PTE_ATTRIBUTES | HV.PTE_VALID,guest_size,1) < 0:
        raise RuntimeError('Guest map failed')
    # Diagnostic memory backing (observation only): back specific guest IPA pages the monitor
    # dereferences with zeroed host RAM so the read resolves and we can watch whether it advances
    # or begins a broader region walk. Host-owned pages, never an identity map into machine memory.
    backed_pages = []
    for spec in (a.back_page or []):
        page_base, _, count_text = spec.partition(':')
        ipa = int(page_base, 0)
        count = int(count_text, 0) if count_text else 1
        if ipa & 0x3fff:
            raise RuntimeError('Diagnostic back-page IPA must be 16KB aligned: '+spec)
        if not 1 <= count <= 4096:
            raise RuntimeError('Diagnostic back-page count must be 1..4096: '+spec)
        span = count*0x4000
        host = u.memalign(0x4000, span)
        p.memset32(host, 0, span)
        p.dc_cvau(host, span)
        p.ic_ivau(host, span)
        if p.hv_map(ipa, host | HV.PTE_ATTRIBUTES | HV.PTE_VALID, span, 1) < 0:
            raise RuntimeError('Diagnostic back-page map failed: '+spec)
        backed_pages.append(dict(ipa=ipa, host_pa=host, size=span, pages=count, zeroed=True))
    if backed_pages:
        report['diagnostic_backed_pages'] = backed_pages
        save()
    # Observation-grade virtual guarded world. genter/gexit follow the architectural control
    # flow: the GL1 exception bank becomes the live EL1 bank while guarded (world swap), the
    # link PC/PSTATE are banked, SP_EL1 is swapped. Nothing enforces SPRR or guarded pages.
    gxf_banks = {SPSR_GL1: SPSR_EL12, ELR_GL1: ELR_EL12, ESR_GL1: ESR_EL12, FAR_GL1: FAR_EL12, AFSR1_GL1: AFSR1_EL12, VBAR_GL1: VBAR_EL12}
    gxf_state = dict(config=0, guarded=False, el_bank={}, sp_bank=0, genter=0, gexit=0)
    # Hypervisor configuration the monitor programs for the level below it; recorded, never applied.
    el2_shadow = {}
    def gxf_report():
        return report.setdefault('virtual_gxf', dict(enabled=bool(a.virtual_gxf), permissions_enforced=False,
                                                     guarded_pages_enforced=False, guarded=False, genter=0, gexit=0, config_events=[]))
    gxf_report()
    entered = False
    handoff_state = dict(active=False, events=0)
    txm_context_step_state = dict(active=False)
    txm_validator_trace_state = dict(active=False)
    phase53_allocation_trace_state = dict(active=False)
    phase53_retype_survey_state = dict(active=False)
    phase53_retype_hvc_state = dict(active=False)
    phase53_descriptor_bind_state = dict(active=False)
    aic_observation_state = dict(
        active=False, certified_erets=[], replayed_erets=0)
    xnu_agt_state = dict(previous=None, writes=0)
    xnu_cntp_ctl_state = dict(previous=None, writes=0)
    xnu_pperm_state = dict(previous=None, step=0, window_type=None, modified=False,
                           started=0, completed=0)
    xnu_apple_timer_state = dict(previous=None, writes=0)
    watchdog = FreeRunWatchdog(iface, a.hang_budget) if a.free_run else None
    def phase53_kernel_runtime(linked_pc):
        return (int(report['handoff']['target_pc'], 0) + linked_pc -
                FC_XNU_ENTRY_LINKED)

    def phase53_kernel_source(linked_pc, size):
        segment = layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        offset = segment['fileoff'] + linked_pc - segment['va']
        if not (segment['fileoff'] <= offset and
                offset + size <= segment['fileoff'] + segment['filesize']):
            raise ValueError('Phase53 kernel source range outside __TEXT_EXEC')
        raw = sources['kernelcache'][offset:offset + size]
        if len(raw) != size:
            raise ValueError('Truncated Phase53 kernel source range')
        return raw

    def phase53_owned_table(table):
        if (table & (PAGE - 1) or
                not base <= table < table + PAGE <= base + guest_size):
            raise ValueError('Phase53 table outside owned guest RAM')
        raw = iface.readmem(table, PAGE)
        if len(raw) != PAGE:
            raise ValueError('Truncated Phase53 translation table')
        return raw

    def phase53_read_live(roots, va, size):
        leaf = translate(va, roots['ttbr0'], roots['ttbr1'],
                         phase53_owned_table)
        if ((leaf['pa'] & (PAGE - 1)) + size > PAGE or
                not base <= leaf['pa'] < leaf['pa'] + size <=
                    base + guest_size):
            raise ValueError('Phase53 live range outside one owned page')
        raw = iface.readmem(leaf['pa'], size)
        if len(raw) != size:
            raise ValueError('Truncated Phase53 live range')
        return leaf, raw

    def phase53_capture_fte(roots, physical_address):
        pointer_leaf, pointer_raw = phase53_read_live(
            roots, FC_SPTM_PHASE53_FTE_BASE_POINTER, 8)
        fte_base = struct.unpack('<Q', pointer_raw)[0]
        center_va = fte_base + (
            ((physical_address - base) >> 10) & 0x3ffffffffffff0)
        records = []
        for delta in (-16, 0, 16):
            va = center_va + delta
            leaf, raw = phase53_read_live(roots, va, 16)
            records.append(dict(
                delta=delta, va=hex(va), pa=hex(leaf['pa']),
                hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest(),
                in_flight_ops=struct.unpack('<H', raw[:2])[0],
                type=raw[2], complete=True,
                level_three=leaf['level'] == 3,
                access_flag=leaf['access_flag']))
        return dict(
            base_pointer_va=hex(FC_SPTM_PHASE53_FTE_BASE_POINTER),
            base_pointer_pa=hex(pointer_leaf['pa']),
            base_pointer_hex=pointer_raw.hex(),
            pointer_level_three=pointer_leaf['level'] == 3,
            pointer_access_flag=pointer_leaf['access_flag'],
            fte_base=hex(fte_base), center_va=hex(center_va),
            records=records)

    def phase53_fte_checks(prefix, snapshot, expected_type):
        center = snapshot['records'][1]
        return {
            prefix + '_pointer_level_three':
                snapshot['pointer_level_three'],
            prefix + '_pointer_access_flag':
                snapshot['pointer_access_flag'],
            prefix + '_records_complete':
                all(item['complete'] for item in snapshot['records']),
            prefix + '_records_level_three':
                all(item['level_three'] for item in snapshot['records']),
            prefix + '_records_access_flag':
                all(item['access_flag'] for item in snapshot['records']),
            prefix + '_center_unlocked': center['in_flight_ops'] == 0,
            prefix + '_center_type': center['type'] == (expected_type & 0xff),
        }

    def phase53_wrapper_snapshot(roots, patched=True):
        source = phase53_kernel_source(
            FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED,
            len(FC_XNU_PHASE53_RETYPE_WRAPPER_WORDS) * 4)
        runtime = phase53_kernel_runtime(
            FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED)
        leaf, live = phase53_read_live(roots, runtime, len(source))
        expected_source = struct.pack(
            '<' + 'I' * len(FC_XNU_PHASE53_RETYPE_WRAPPER_WORDS),
            *FC_XNU_PHASE53_RETYPE_WRAPPER_WORDS)
        expected_live_words = list(FC_XNU_PHASE53_RETYPE_WRAPPER_WORDS)
        if patched:
            expected_live_words[2] = PHASE53_RETYPE_PRE_SITE.hvc_word
            expected_live_words[4] = PHASE53_RETYPE_GENTER_SITE.hvc_word
            expected_live_words[7] = PHASE53_RETYPE_POST_SITE.hvc_word
        expected_live = struct.pack(
            '<' + 'I' * len(expected_live_words), *expected_live_words)
        return dict(
            linked_pc=hex(FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED),
            runtime_pc=hex(runtime), pa=hex(leaf['pa']),
            source_hex=source.hex(), live_hex=live.hex(),
            source_exact=source == expected_source,
            live_exact=live == expected_live,
            level_three=leaf['level'] == 3,
            access_flag=leaf['access_flag'])

    def phase53_hvc_target_bytes_match(handoff):
        """Accept source-exact target bytes plus only our three live HVCs."""
        if handoff.get('bytes_match') is True:
            return True
        if handoff.get('image') != 'kernelcache':
            return False
        try:
            linked_value = handoff['linked_pc']
            linked_pc = (int(linked_value, 0) if isinstance(linked_value, str)
                         else int(linked_value))
            live = bytes.fromhex(handoff['bytes_hex'])
            expected = bytearray(phase53_kernel_source(linked_pc, len(live)))
        except (KeyError, TypeError, ValueError):
            return False
        substituted = False
        for site in RETYPE_HVC_SITES:
            offset = site.linked_pc - linked_pc
            if 0 <= offset <= len(expected) - 4:
                expected[offset:offset + 4] = struct.pack('<I', site.hvc_word)
                substituted = True
        return substituted and live == expected

    def phase53_set_retype_hvcs(roots, install):
        pending = []
        for site in RETYPE_HVC_SITES:
            runtime_pc = phase53_kernel_runtime(site.linked_pc)
            leaf, before = phase53_read_live(roots, runtime_pc, 4)
            source = phase53_kernel_source(site.linked_pc, 4)
            expected_hvc = struct.pack('<I', site.hvc_word)
            expected_source = struct.pack('<I', site.source_word)
            replacement = expected_hvc if install else expected_source
            allowed_before = ((expected_source,) if install else
                              (expected_hvc, expected_source))
            if before not in allowed_before or source != expected_source:
                raise ValueError('Phase53 %s HVC %s gate rejected' %
                                 (site.phase,
                                  'install' if install else 'restore'))
            pending.append((site, runtime_pc, leaf, before, replacement))

        try:
            for site, runtime_pc, leaf, before, replacement in pending:
                if before != replacement:
                    iface.writemem(leaf['pa'], replacement)
                    p.dc_cvau(leaf['pa'], 4)
                    p.ic_ivau(leaf['pa'], 4)
            records = []
            for site, runtime_pc, leaf, before, replacement in pending:
                after = iface.readmem(leaf['pa'], 4)
                if after != replacement:
                    raise ValueError('Phase53 %s HVC %s readback failed' %
                                     (site.phase,
                                      'install' if install else 'restore'))
                records.append(dict(
                    phase=site.phase, runtime_pc=hex(runtime_pc),
                    pa=hex(leaf['pa']), before_hex=before.hex(),
                    after_hex=after.hex(),
                    operation='install' if install else 'restore',
                    write_required=before != replacement,
                    complete=True))
            return records
        except Exception as operation_error:
            if install:
                try:
                    phase53_set_retype_hvcs(roots, False)
                except Exception as rollback_error:
                    raise RuntimeError('%s; idempotent rollback failed: %s' %
                                       (operation_error, rollback_error)) from operation_error
            raise operation_error

    def phase53_install_retype_hvcs(roots):
        return phase53_set_retype_hvcs(roots, True)

    def phase53_restore_retype_hvcs(roots):
        return phase53_set_retype_hvcs(roots, False)
    def pause_guard(guard, flag, context):
        """Hold a side-effect-free policy rejection for a local decision; True means retry with the flag enabled."""
        if guard_pause is None or getattr(a, flag):
            return False
        # Snapshot the pending trap; the retried event object is amended after the decision.
        context = {k: list(v) if isinstance(v, list) else v for k, v in context.items()}
        policies = dict(allow_monitor_mmu=a.allow_monitor_mmu, allow_live_ttbr=a.allow_live_ttbr)
        def on_pause(directory, status):
            report.setdefault('guard_pauses', []).append(dict(
                pause_id=status['pause_id'], guard=guard, flag=flag, context=context,
                decision=None, applied_changes={}))
            save()
            print('Guard pause waiting for a decision:', directory, flush=True)
        decision = guard_pause.wait(guard, context, policies, allowed_flags=[flag], on_pause=on_pause)
        record = report['guard_pauses'][-1]
        record['decision'] = {k: decision.get(k) for k in ('action', 'changes', 'reason', 'request_id')}
        applied = {}
        if decision['action'] == 'resume':
            for name, value in decision['changes'].items():
                # The channel already validated names and Boolean values against this trap's allowlist.
                if name == flag and type(value) is bool:
                    setattr(a, name, value)
                    applied[name] = value
        record['applied_changes'] = applied
        if applied:
            report['policy_overrides'] = {**report.get('policy_overrides', {}), **applied}
        return decision['action'] == 'resume' and getattr(a, flag) is True
    callback_bindings = RunBindings({**globals(), **locals()})
    stopped = partial(dispatch_event, callback_bindings)
    for reason in (START.EXCEPTION,START.EXCEPTION_LOWER):
        for code in EXC:
            iface.set_handler(reason,code,stopped)
    for code in HV_EVENT:
        iface.set_handler(START.HV,code,stopped)
    p.hv_vel2_set_active(True)
    if a.free_run:
        # Trap wfe so SPTM's panic halt (a wfe self-loop at FC_IDLE_PC) surfaces instead
        # of spinning forever; a benign wfe is skipped in the handler.
        hcr_now = u.mrs(HCR_EL2)
        p.hv_write_hcr(hcr_now | (1 << 14) | (1 << 3))  # TWE + FMO (watchdog timer FIQ)
        report['free_run'] = dict(enabled=True, twe=True, fmo=True, hcr=hex(hcr_now | (1 << 14) | (1 << 3)),
                                  on_demand_stage2=a.on_demand_stage2)
    report['hardware_executed'] = True
    execution_started = None
    guest_returned = False
    try:
        capture.phase('guest-execution')
        save()
        execution_started = time.monotonic()
        launch = lambda: p.hv_start(entry,base+args_off,0,0,0)
        if watchdog is not None:
            watchdog.run(launch)
        else:
            launch()
        guest_returned = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        entered = callback_bindings.entered
        shadow_hcr = callback_bindings.shadow_hcr
        shadow_sctlr = callback_bindings.shadow_sctlr
        shadow_sprr_config = callback_bindings.shadow_sprr_config
        real_sprr_on = callback_bindings.real_sprr_on
        guarded_vbar = callback_bindings.guarded_vbar
        monitor_mmu_validated = callback_bindings.monitor_mmu_validated
        if execution_started is not None:
            report['guest_execution_duration_seconds'] = time.monotonic()-execution_started
        if watchdog is not None:
            report['watchdog'] = watchdog.status()
        report['guest_returned'] = guest_returned
        if not guest_returned:
            report['cleanup_skipped'] = 'hv_start did not return; target state unknown, no proxy I/O'
            if a.xnu_txm_sstep_fast_path:
                report['xnu_txm_sstep_fast_path']['teardown_skipped'] = (
                    'hv_start did not return; target state unknown, no proxy I/O')
            if a.xnu_tpidr_gl2_fast_shadow:
                report['xnu_tpidr_gl2_fast_shadow']['teardown_skipped'] = (
                    'hv_start did not return; target state unknown, no proxy I/O')
            if getattr(a, 'xnu_gl1_fast_redirect', False):
                report['xnu_gl1_fast_redirect']['teardown_skipped'] = (
                    'hv_start did not return; target state unknown, no proxy I/O')
            if getattr(a, 'xnu_phase53_retype_hvc_fast_path', False):
                report['xnu_phase53_retype_hvc_fast_path']['restoration_skipped'] = (
                    'hv_start did not return; target state unknown, no proxy I/O')
            if watchdog is not None:
                report['stop_reason'] = 'guest-unresponsive'
            try:
                save()
            finally:
                iface.dev.close()
        else:
            if getattr(a, 'xnu_phase53_retype_hvc_fast_path', False):
                hvc_report = report['xnu_phase53_retype_hvc_fast_path']
                hvc_report.update(
                    completed_calls=phase53_retype_hvc_state.get('completed_calls', 0),
                    final_stage=phase53_retype_hvc_state.get('stage'),
                    failed=phase53_retype_hvc_state.get(
                        'failed', hvc_report.get('failed', False)),
                    patches_live=phase53_retype_hvc_state.get('patches_live', False))
                if phase53_retype_hvc_state.get('machine') is not None:
                    hvc_report['final_state_machine'] = (
                        phase53_retype_hvc_state['machine'].snapshot())
                if phase53_retype_hvc_state.get('current_call') is not None:
                    hvc_report['current_call'] = phase53_retype_hvc_state['current_call']
                if phase53_retype_hvc_state.get('patches_live'):
                    try:
                        restoration = phase53_restore_retype_hvcs(
                            phase53_retype_hvc_state['roots'])
                        phase53_retype_hvc_state['patches_live'] = False
                        hvc_report.update(
                            enabled=False, patches_live=False,
                            cleanup_restoration=restoration,
                            restored_at_teardown=True)
                    except Exception as restoration_error:
                        hvc_report['restoration_error'] = str(restoration_error)
                        report.setdefault(
                            'cleanup_error',
                            'Phase53 retype HVC restoration failed: ' +
                            str(restoration_error))
            if getattr(a, 'xnu_gl1_fast_redirect', False):
                try:
                    teardown = gl1_fast_redirect.disable()
                    report['xnu_gl1_fast_redirect']['teardown'] = teardown
                    report['xnu_gl1_fast_redirect']['disabled_at_teardown'] = True
                    report['xnu_gl1_fast_redirect']['final_aliases'] = {
                        name: u.mrs(HV.MSR_REDIRECTS[sysreg_fwd[name]])
                        for name in Gl1FastRedirect.TAG_NAMES}
                except Exception as teardown_error:
                    report['xnu_gl1_fast_redirect']['teardown_error'] = str(teardown_error)
                    report.setdefault(
                        'cleanup_error', 'GL1 fast-redirect teardown failed: ' +
                        str(teardown_error))
            if a.xnu_txm_sstep_fast_path:
                try:
                    teardown = txm_sstep_fast_path.disable()
                    report['xnu_txm_sstep_fast_path']['teardown'] = teardown
                    report['xnu_txm_sstep_fast_path'][
                        'disabled_at_teardown'] = True
                except Exception as teardown_error:
                    report['xnu_txm_sstep_fast_path'][
                        'teardown_error'] = str(teardown_error)
                    report.setdefault('cleanup_error',
                                      'VEL2 step-filter teardown failed: ' +
                                      str(teardown_error))
            if a.xnu_tpidr_gl2_fast_shadow:
                fast_report = report['xnu_tpidr_gl2_fast_shadow']
                teardown, teardown_errors = audit_and_disable_tpidr_gl2_fast_shadow(
                    tpidr_gl2_fast_shadow, apple_shadow, tpidr_gl2_register,
                    synchronize=fast_report['activated'])
                fast_report.update(teardown)
                if teardown['host_shadow_synchronized']:
                    report['staged_apple_registers'] = {
                        sysreg_rev.get(r, 'S3_%d_C%d_C%d_%d' % r[1:]): v
                        for r, v in apple_shadow.items()}
                if teardown_errors:
                    report.setdefault('cleanup_error',
                                      'TPIDR_GL2 fast-shadow ' +
                                      '; '.join(teardown_errors))
            try:
                report['final_guest_exception_registers'] = {name: u.mrs(reg) for name, reg in exception_registers.items()}
            except Exception as snapshot_error:
                report['exception_snapshot_error'] = str(snapshot_error)
            try:
                report['xnu_agtcnt_rdir_cleanup'] = restore_xnu_agtcnt_rdir(
                    u, AGTCNTRDIR_EL12, xnu_agt_state['previous'], guest_returned)
                if not report['xnu_agtcnt_rdir_cleanup'].get('verified', True):
                    report.setdefault('cleanup_error', 'AGTCNTRDIR_EL12 restore readback mismatch')
            except Exception as restore_error:
                report['xnu_agtcnt_rdir_cleanup'] = dict(
                    register='AGTCNTRDIR_EL12', attempted=True, error=str(restore_error))
                report.setdefault('cleanup_error', 'AGTCNTRDIR_EL12 restore failed: ' + str(restore_error))
            # The handler exits the guest even when validation raises. Attempt to
            # restore guest controls on both success and error; report USB failures.
            if a.snapshot_leaf:
                # Walk the final monitor translation for each requested VA before teardown and
                # decode the leaf both natively and through SPRR. Observation only: reads guest
                # memory and live guest permission aliases (staged shadows in virtual mode), changes nothing.
                try:
                    controls = dict(ttbr0=u.mrs(TTBR0_EL12), ttbr1=u.mrs(TTBR1_EL12),
                                    tcr=u.mrs(TCR_EL12), mair=u.mrs(MAIR_EL12))
                    if a.real_guarded:
                        pperm = int(u.mrs(HV.MSR_REDIRECTS[SPRR_PPERM_EL1]))
                        uperm = int(u.mrs(HV.MSR_REDIRECTS[SPRR_UPERM_EL0]))
                    else:
                        pperm = permission_shadow[SPRR_PPERM_EL1]
                        uperm = permission_shadow[SPRR_UPERM_EL0]
                    controls['permission_source'] = 'live guest aliases' if a.real_guarded else 'staged shadows'
                    snaps = []
                    for spec in a.snapshot_leaf:
                        va = int(spec, 0)
                        def read_leaf_page(table, _va=va):
                            data = iface.readmem(table, PAGE)
                            capture.save_input('leaf-%x-%x.bin' % (_va, table), data)
                            return data
                        try:
                            leaf = translate(va, controls['ttbr0'], controls['ttbr1'], read_leaf_page)
                            snaps.append(dict(va=va, pa=leaf['pa'], level=leaf['level'],
                                              descriptor=leaf['descriptor'], native_descriptor_bits=leaf,
                                              pperm_el1=pperm, uperm_el0=uperm,
                                              native=leaf_permissions(leaf['descriptor'], pperm, uperm, 'ordinary'),
                                              guarded=leaf_permissions(leaf['descriptor'], pperm, uperm, 'guarded')))
                        except Exception as walk_error:
                            snaps.append(dict(va=va, error=str(walk_error)))
                    report['final_leaf_snapshots'] = snaps
                    report['final_leaf_controls'] = controls
                    save()
                except Exception as snapshot_error:
                    report['final_leaf_snapshot_error'] = str(snapshot_error)
            if a.real_guarded:
                # Snapshot the guest's guarded exception bank at exit (via _GL12/_EL12 aliases) so a
                # divert into a guarded vector is legible: e.g. if VBAR_GL1 matches the spin address the
                # divert is a guarded exception, not a stray jump. Best-effort; reads only.
                # Guard each read independently: a single throwing mrs must not lose the
                # whole snapshot (a wasted hardware attempt). ESR_GL1 (cause) + ELR_GL1
                # (faulting guarded PC) + VBAR_GL1 (vector base) decide whether the divert
                # is a guarded exception (divert == VBAR_GL1 + offset) or a stray jump.
                gl = {}
                report['guarded_bank_exit'] = gl
                for name in ('VBAR_GL1','SPSR_GL1','ASPSR_GL1','ELR_GL1','ESR_GL1',
                             'GXF_ENTRY_EL1','GXF_PABENTRY_EL1'):
                    try:
                        reg = sysreg_fwd[name]
                        if reg in HV.MSR_REDIRECTS:
                            gl[name] = u.mrs(HV.MSR_REDIRECTS[reg])
                        else:
                            gl[name + '_error'] = 'no MSR_REDIRECTS alias'
                    except Exception as gl_error:
                        gl[name + '_error'] = str(gl_error)
            try:
                u.msr(SCTLR_EL12,0x30d00800)
                u.exec('dsb ishst; tlbi vmalle1is; dsb ish; isb')
                if batch is not None:
                    batch.disable()
                p.hv_vel2_set_active(False)
                if a.xnu_pperm_guest_window:
                    cleanup = restore_xnu_pperm_guest_window(
                        u, HV.MSR_REDIRECTS[SPRR_PPERM_EL1],
                        xnu_pperm_state, guest_returned)
                    if not cleanup.get('verified', True):
                        report.setdefault('cleanup_error', 'PPERM_EL12 restore mismatch')
                    report['xnu_pperm_guest_window_cleanup'] = cleanup
                # The guest can no longer resume. Restore only the writable guest
                # EL02 timer bits now, so an expired prior timer cannot interrupt cleanup.
                try:
                    report['xnu_cntp_ctl_cleanup'] = restore_xnu_cntp_ctl(
                        u, CNTP_CTL_EL02, xnu_cntp_ctl_state['previous'], guest_returned)
                    if not report['xnu_cntp_ctl_cleanup'].get('verified', True):
                        report.setdefault('cleanup_error', 'CNTP_CTL_EL02 restore readback mismatch')
                except Exception as restore_error:
                    report['xnu_cntp_ctl_cleanup'] = dict(
                        register='CNTP_CTL_EL02', attempted=True, error=str(restore_error))
                    report.setdefault('cleanup_error', 'CNTP_CTL_EL02 restore failed: ' + str(restore_error))
                try:
                    report['xnu_apple_physical_timer_cleanup'] = restore_xnu_apple_physical_timer(
                        u, FC_XNU_APPLE_PHYS_TIMER_EL02,
                        xnu_apple_timer_state['previous'], guest_returned)
                    if not report['xnu_apple_physical_timer_cleanup'].get('verified_exact', True):
                        report.setdefault('cleanup_error',
                                          'S3_4_C15_C4_3 full-value restore readback mismatch')
                except Exception as restore_error:
                    report['xnu_apple_physical_timer_cleanup'] = dict(
                        register='S3_4_C15_C4_3', attempted=True,
                        physical_s3_1_bank_touched=False, error=str(restore_error))
                    report.setdefault('cleanup_error',
                                      'S3_4_C15_C4_3 restore failed: ' + str(restore_error))
                if a.real_guarded:
                    # Try to restore the EL2 SPRR/GXF context this run enabled (~367-368).
                    # NOTE: attempt-22 showed this alone does NOT make a 2nd real-guarded run
                    # work — it still crashed at hv_start. Hypothesis (hv.c hv_start): whenever
                    # gxf_enabled() is true, hv_start does gl2_call(hv_set_gxf_vbar), re-entering
                    # GL2; after SPTM's guarded run GL2 is dirty, so it faults. The disable below
                    # may not even take (GXF_CONFIG can be locked after guarded use), and
                    # el2_context_restored only meant the write did not throw. So read the state
                    # back to see what is actually left dirty. Isolated; reads only after writes.
                    try:
                        u.msr(GXF_CONFIG_EL1, 0)
                        u.msr(SPRR_CONFIG_EL1, 0)
                        u.exec('isb')
                        after = dict(gxf_config=u.mrs(GXF_CONFIG_EL1), sprr_config=u.mrs(SPRR_CONFIG_EL1))
                        try:
                            after['gxf_status'] = u.mrs(sysreg_fwd['GXF_STATUS_EL1'])
                        except Exception as e:
                            after['gxf_status_error'] = str(e)
                        try:
                            vb = sysreg_fwd['VBAR_GL1']
                            after['vbar_gl1'] = u.mrs(HV.MSR_REDIRECTS[vb]) if vb in HV.MSR_REDIRECTS else None
                        except Exception as e:
                            after['vbar_gl1_error'] = str(e)
                        after['gxf_en_cleared'] = not (after['gxf_config'] & 1)
                        report['el2_context_after'] = after
                        report['el2_context_restored'] = True
                    except Exception as restore_error:
                        report['el2_context_restore_error'] = str(restore_error)
                u.msr(MDSCR_EL1,0)
                p.nop()
                report['proxy_alive_after_exit'] = True
                report['final_observed_registers'] = {name: u.mrs(reg) for name, reg in observed_registers.items()}
            except Exception as cleanup_error:
                report['cleanup_error'] = str(cleanup_error)
            try:
                save()
            finally:
                iface.dev.close()
    print('SPTM entry probe stopped:',report.get('stop_reason'))
