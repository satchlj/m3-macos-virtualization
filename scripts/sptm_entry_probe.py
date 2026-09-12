#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See ../LICENSES/Asahi-m1n1-MIT.txt and ../THIRD_PARTY_NOTICES.md.
"""Bounded SPTM instruction trace in isolated guest RAM; not a macOS boot loader."""
import argparse
import hashlib
import json
import os
import signal
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

class PpermWindowLimit(Exception):
    pass


class TpidrGl2FastShadow:
    """Strict host boundary for the opt-in firmware TPIDR_GL2 HVC fast path."""
    ENABLE = 'hv_vel2_tpidr_gl2_shadow_enable'
    STATUS = 'hv_vel2_tpidr_gl2_shadow_status'
    DISABLE = 'hv_vel2_tpidr_gl2_shadow_disable'
    STATUS_FIELDS = ('enabled', 'tag_base', 'shadow', 'reads',
                     'writes', 'forwarded')

    def __init__(self, proxy):
        self.proxy = proxy
        missing = [name for name in (self.ENABLE, self.STATUS, self.DISABLE)
                   if not callable(getattr(proxy, name, None))]
        if missing:
            raise RuntimeError('TPIDR_GL2 fast-shadow proxy API unavailable: ' +
                               ', '.join(missing))

    @staticmethod
    def _validate_tag(tag_base):
        if (type(tag_base) is not int or not 0 <= tag_base <= 0xffff or
                tag_base & 0xc03f != 0x8000):
            raise RuntimeError('Invalid TPIDR_GL2 fast-shadow HVC tag base: ' +
                               repr(tag_base))

    def status(self):
        status = getattr(self.proxy, self.STATUS)()
        if not isinstance(status, dict):
            raise RuntimeError('TPIDR_GL2 fast-shadow status is not a dictionary')
        missing = [name for name in self.STATUS_FIELDS if name not in status]
        if missing:
            raise RuntimeError('TPIDR_GL2 fast-shadow status missing: ' +
                               ', '.join(missing))
        if type(status['enabled']) is not bool:
            raise RuntimeError('TPIDR_GL2 fast-shadow enabled status is not Boolean')
        for name in self.STATUS_FIELDS[1:]:
            value = status[name]
            if type(value) is not int or not 0 <= value <= (1 << 64) - 1:
                raise RuntimeError('TPIDR_GL2 fast-shadow status field is not u64: ' + name)
        if status['enabled'] or status['tag_base']:
            self._validate_tag(status['tag_base'])
        return {name: status[name] for name in self.STATUS_FIELDS}

    @staticmethod
    def _check_result(operation, result):
        # Existing m1n1 proxy wrappers raise on firmware errors and return None;
        # accepting an explicit zero also keeps the boundary usable with raw wrappers.
        if result not in (None, 0):
            raise RuntimeError('TPIDR_GL2 fast-shadow %s failed: %r' %
                               (operation, result))

    def prepare(self):
        """Prove the accelerator is disabled before any guest can run."""
        before = self.status()
        if before['enabled']:
            self._check_result('preflight disable',
                               getattr(self.proxy, self.DISABLE)())
        after = self.status()
        if after['enabled']:
            raise RuntimeError('TPIDR_GL2 fast shadow remained enabled at preflight')
        return dict(before=before, after=after,
                    stale_state_cleared=before['enabled'])

    def enable(self, tag_base, initial_value):
        self._validate_tag(tag_base)
        if type(initial_value) is not int or not 0 <= initial_value <= (1 << 64) - 1:
            raise RuntimeError('Invalid TPIDR_GL2 fast-shadow initial value')
        try:
            self._check_result('enable', getattr(self.proxy, self.ENABLE)(
                tag_base, initial_value))
            status = self.status()
            if (not status['enabled'] or status['tag_base'] != tag_base or
                    status['shadow'] != initial_value or
                    any(status[name] for name in
                        ('reads', 'writes', 'forwarded'))):
                raise RuntimeError('TPIDR_GL2 fast-shadow enable readback mismatch')
            return status
        except Exception as enable_error:
            # An ambiguous transport failure may have occurred after firmware changed
            # state. Always attempt the independent disable operation before returning
            # control to a callback that will exit the guest.
            try:
                self._check_result('enable-failure disable',
                                   getattr(self.proxy, self.DISABLE)())
                after = self.status()
                if after['enabled']:
                    raise RuntimeError('still enabled')
            except Exception as disable_error:
                raise RuntimeError('%s; fail-closed disable also failed: %s' %
                                   (enable_error, disable_error)) from enable_error
            raise

    def disable(self):
        self._check_result('disable', getattr(self.proxy, self.DISABLE)())
        status = self.status()
        if status['enabled']:
            raise RuntimeError('TPIDR_GL2 fast shadow remained enabled at teardown')
        return status


class Vel2StepFilter:
    """Fail-closed host boundary for a one-shot firmware software-step run."""
    ENABLE = 'hv_vel2_step_filter_enable'
    STATUS = 'hv_vel2_step_filter_status'
    DISABLE = 'hv_vel2_step_filter_disable'
    STATUS_FIELDS = ('active', 'status', 'steps', 'first_pc', 'last_pc',
                     'previous_pc', 'range0_hits', 'range1_hits',
                     'range_switches', 'terminal_pc', 'max_steps',
                     'range0_start', 'range0_end', 'range1_start', 'range1_end',
                     'expected_first_pc')
    DISABLED = 0
    RUNNING = 1
    TERMINAL = 3

    def __init__(self, proxy):
        self.proxy = proxy
        missing = [name for name in (self.ENABLE, self.STATUS, self.DISABLE)
                   if not callable(getattr(proxy, name, None))]
        if missing:
            raise RuntimeError('VEL2 step-filter proxy API unavailable: ' +
                               ', '.join(missing))

    def status(self):
        status = getattr(self.proxy, self.STATUS)()
        if not isinstance(status, dict):
            raise RuntimeError('VEL2 step-filter status is not a dictionary')
        missing = [name for name in self.STATUS_FIELDS if name not in status]
        if missing:
            raise RuntimeError('VEL2 step-filter status missing: ' +
                               ', '.join(missing))
        if type(status['active']) is not bool:
            raise RuntimeError('VEL2 step-filter active status is not Boolean')
        for name in self.STATUS_FIELDS[1:]:
            value = status[name]
            if type(value) is not int or not 0 <= value <= (1 << 64) - 1:
                raise RuntimeError('VEL2 step-filter status field is not u64: ' +
                                   name)
        return {name: status[name] for name in self.STATUS_FIELDS}

    @staticmethod
    def _check_result(operation, result):
        if result not in (None, 0):
            raise RuntimeError('VEL2 step-filter %s failed: %r' %
                               (operation, result))

    def prepare(self):
        try:
            before = self.status()
        except Exception as status_error:
            try:
                self._check_result('preflight recovery disable',
                                   getattr(self.proxy, self.DISABLE)())
            except Exception as disable_error:
                raise RuntimeError('%s; preflight recovery disable failed: %s' %
                                   (status_error, disable_error)) from status_error
            raise
        if before['active'] or before['status'] != self.DISABLED:
            self._check_result('preflight disable',
                               getattr(self.proxy, self.DISABLE)())
        after = self.status()
        if after['active'] or after['status'] != self.DISABLED:
            raise RuntimeError('VEL2 step filter remained armed at preflight')
        return dict(before=before, after=after,
                    stale_state_cleared=(before['active'] or
                                         before['status'] != self.DISABLED))

    def enable(self, range0, range1, terminal_pc, max_steps,
               expected_first_pc):
        values = (*range0, *range1, terminal_pc, max_steps,
                  expected_first_pc)
        if (any(type(value) is not int for value in values) or
                not 0 < max_steps <= (1 << 24) or
                not range0[0] < range0[1] or
                not range1[0] < range1[1] or
                any(value & 3 for value in
                    (*range0, *range1, terminal_pc, expected_first_pc))):
            raise RuntimeError('Invalid VEL2 step-filter bounds')
        try:
            self._check_result('enable', getattr(self.proxy, self.ENABLE)(
                *range0, *range1, terminal_pc, max_steps,
                expected_first_pc))
            status = self.status()
            if (not status['active'] or status['status'] != self.RUNNING or
                    status['terminal_pc'] != terminal_pc or
                    status['max_steps'] != max_steps or
                    status['range0_start'] != range0[0] or
                    status['range0_end'] != range0[1] or
                    status['range1_start'] != range1[0] or
                    status['range1_end'] != range1[1] or
                    status['expected_first_pc'] != expected_first_pc or
                    any(status[name] for name in
                        ('steps', 'first_pc', 'last_pc', 'previous_pc',
                         'range0_hits', 'range1_hits', 'range_switches'))):
                raise RuntimeError('VEL2 step-filter enable readback mismatch')
            return status
        except Exception as enable_error:
            try:
                self._check_result('enable-failure disable',
                                   getattr(self.proxy, self.DISABLE)())
                after = self.status()
                if after['active'] or after['status'] != self.DISABLED:
                    raise RuntimeError('still active')
            except Exception as disable_error:
                raise RuntimeError('%s; fail-closed disable also failed: %s' %
                                   (enable_error, disable_error)) from enable_error
            raise

    def disable(self):
        before = None
        errors = []
        try:
            before = self.status()
        except Exception as error:
            errors.append('stop audit failed: ' + str(error))
        try:
            self._check_result('disable', getattr(self.proxy, self.DISABLE)())
        except Exception as error:
            errors.append('disable failed: ' + str(error))
        after = None
        try:
            after = self.status()
            if after['active'] or after['status'] != self.DISABLED:
                errors.append('VEL2 step filter remained active at teardown')
        except Exception as error:
            errors.append('disable audit failed: ' + str(error))
        if errors:
            raise RuntimeError('; '.join(errors))
        return dict(before=before, after=after)


def audit_and_disable_tpidr_gl2_fast_shadow(adapter, host_shadow, register,
                                            synchronize=True):
    """Audit firmware counters/value, restore host ownership, and always disable."""
    result = {'stop_audit_attempted': True, 'host_shadow_synchronized': False,
              'disabled_at_teardown': False}
    errors = []
    try:
        audit = adapter.status()
        result['stop_audit'] = audit
        if synchronize:
            host_shadow[register] = audit['shadow']
            result['host_shadow_synchronized'] = True
            result['final_value_hex'] = hex(audit['shadow'])
    except Exception as error:
        result['stop_audit_error'] = str(error)
        errors.append('stop audit failed: ' + str(error))
    try:
        result['disable_status'] = adapter.disable()
        result['disabled_at_teardown'] = True
    except Exception as error:
        result['disable_error'] = str(error)
        errors.append('disable failed: ' + str(error))
    return result, errors


# Apple SPRR/GXF registers the monitor programs. All are rewritten to HVC and staged in a
# host dictionary: recorded, readable back, never written to hardware. Names resolve
# through the pinned sysreg tables; unnamed encodings are listed as tuples. Two registers
# the monitor already uses natively without incident, AFPCR_EL0 and APSTS_EL1, stay native.
SPRR_PERMISSION_REGISTERS = ('SPRR_PPERM_EL1', 'SPRR_UPERM_EL0', 'SPRR_PMPRR_EL1',
    'SPRR_UPERM_SH1_EL1', 'SPRR_UPERM_SH2_EL1', 'SPRR_UPERM_SH3_EL1',
    'SPRR_PPERM_SH1_EL1', 'SPRR_PPERM_SH2_EL1', 'SPRR_PPERM_SH3_EL1')
APPLE_OBSERVED_REGISTERS = (
    'SPRR_AMRANGE_EL1', 'SPRR_UMPRR_EL1', 'GXF_ENTRY_EL1', 'GXF_PABENTRY_EL1', 'VBAR_GL1', 'TPIDR_GL1',
    'ASPSR_GL1', 'SPSR_GL1', 'ELR_GL1', 'ESR_GL1', 'FAR_GL1', 'AFSR1_GL1', 'ASPSR_EL1',
    # The monitor's own guarded level and the level below it, as a virtual EL2 sees them.
    'TPIDR_GL2', 'AFSR1_GL2', 'VBAR_GL12', 'SP_GL12',
    'GXF_CONFIG_EL12', 'GXF_ENTRY_EL12', 'GXF_PABENTRY_EL12',
    'SPRR_CONFIG_EL12', 'SPRR_AMRANGE_EL12', 'SPRR_PPERM_EL12', 'SPRR_PMPRR_EL12',
    'SPRR_PPERM_SH1_EL12', 'SPRR_PPERM_SH2_EL12', 'SPRR_PPERM_SH3_EL12',
    'APCTL_EL12', 'APSTS_EL12', 'VMKEYLO_EL2', 'VMKEYHI_EL2',
    'APIAKeyLo_EL12', 'APIAKeyHi_EL12', 'APIBKeyLo_EL12', 'APIBKeyHi_EL12',
    'APDAKeyLo_EL12', 'APDAKeyHi_EL12', 'APDBKeyLo_EL12', 'APDBKeyHi_EL12',
    'APGAKeyLo_EL12', 'APGAKeyHi_EL12', 'KERNKEYLO_EL12', 'KERNKEYHI_EL12',
    # Guarded (GL1) register the monitor writes from guarded execution; undefined outside a
    # real guarded entry, so it caused the attempt-7 EC-0 stop (msr S3_1_C15_C8_2 at 0xbf7c4).
    # Staged, not applied. Its C15_C8 neighbours are already covered; L2C_ERR_STS_EL1 is a plain
    # EL1 register that reads natively and is deliberately left unstaged to preserve fidelity.
    'PMCR1_GL1',
    (3, 6, 15, 0, 5), (3, 6, 15, 1, 1), (3, 6, 15, 8, 5),
    # Unnamed EL2-encoded Apple registers the monitor programs from guarded execution.
    (3, 4, 15, 0, 6), (3, 4, 15, 9, 7), (3, 4, 15, 10, 0), (3, 4, 15, 10, 1), (3, 4, 15, 10, 2), (3, 4, 15, 10, 3),
    (3, 4, 15, 10, 7), (3, 4, 15, 12, 0), (3, 4, 15, 12, 5), (3, 4, 15, 15, 2), (3, 4, 15, 15, 4), (3, 4, 15, 15, 5))

# R2 first-contact addresses (verified disassembly of sptm.macho; see
# docs/real-memory-stage0/first-contact-build-spec.md). Image virtual base
# 0xfffffe0007004000; __TEXT_EXEC fileoff == image offset.
FC_IMAGE_BASE = 0xfffffe0007004000
FC_IDLE_PC = 0xfffffe00070f8b88  # NOT idle: this wfe;b is SPTM's PANIC HALT (inside the panic fn 0xf8980, reached via 0xf8ca0). Treat a stop here as a panic.
FC_GENTER = 0x00201420             # genter #0 -> guarded-ESR type 0 (guarded call)
FC_DISPATCH = 0xfffffe00070a4524   # real service dispatcher (reads guarded ESR type)
FC_T0 = 0xfffffe00070a4a14         # type-0 handler
FC_STOP = 0xfffffe00070a4ac0       # T0 'b ->0xe8d4c': halt here, before the C service runs
FC_INIT = 0xfffffe00070b0b98       # per-CPU init; a genter lands here iff GXF_ENTER is stale
FC_SERVICE = 0xfffffe00070e8d4c    # the C service (must NOT execute in first contact)
FC_PANIC = 0xfffffe00070f8ca0      # SPTM panic (noreturn); halt before it (e.g. an invalid CALL_SPTM func index)
FC_XNU_GEXIT = 0xfffffe00070a5260  # native gexit #0; preceding trapped MSRs hold XNU ELR/SPSR
FC_XNU_TXM_CONTEXT_ERET_PC = 0xfffffe00070a410c
FC_XNU_TXM_CONTEXT_ERET_WORD = 0xd69f03e0
FC_XNU_TXM_CONTEXT_TARGET = 0xfffffe001703103c
FC_XNU_TXM_CONTEXT_LINKED = '0xfffffff01703103c'
FC_XNU_TXM_CONTEXT_STACK = 0xfffffdf000188000
FC_XNU_TXM_CONTEXT_SELECTOR = 0x2000000000001
FC_XNU_TXM_CONTEXT_X18 = 0x1c0
FC_XNU_TXM_CONTEXT_BYTES = bytes.fromhex(
    '1f000091007e40921f0000f160f6ff54e803009108354092880000b4a0feffb0')
FC_XNU_TXM_CONTEXT_SHA256 = 'cef67431c02543f1848194725aa1a71be428f35c07ac64d7c7754c488faff4a8'
FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES = bytes.fromhex(
    '007e40921f0000f160f6ff54e803009108354092880000b4a0feffb000601191'
    'a9880014e803009108c5729208114091080110d11f010091e8630191090080d2'
    '2a0080d2')
FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_SHA256 = (
    '14f527c547bfbb682ea82b6f633a77558640486ef69dd76e24f67dde9f0ab045')
FC_XNU_TXM_CONTEXT_CASB_WORD = 0x08a97d0a
FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES = bytes.fromhex(
    '89000034a0feffb0002012919c880014ff0700b9ffe70139280080d2e8030039'
    '920000b5')
FC_XNU_TXM_CONTEXT_POST_CLAIM_SHA256 = (
    '8d15a9c9a1dd8080fb1276865c9fd73aaea4cb09b806dd6a73d9836c7b9fdf15')
FC_XNU_TXM_CONTEXT_X18_CBNZ_WORD = 0xb5000092
FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES = bytes.fromhex(
    '920000b5320080d2f2e70139a10400d44df7ff17')
FC_XNU_TXM_CONTEXT_X18_WINDOW_SHA256 = (
    '4850ee67ef037e71c56ace33641ff164dfe63af7afe3d5a0fd159db01daf715d')
FC_XNU_TXM_CONTEXT_OUTBOUND_BRANCH_WORD = 0x17fff74d
FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET = 0xfffffe001702edec
FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED = 0xfffffff01702edec
FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES = bytes.fromhex(
    '7f2303d5ffc301d1fa6702a9f85f03a9f65704a9f44f05a9fd7b06a9fd830191'
    'f70305aaf80304aaf60303aaf50302aaf40301aaf90300aafc08009428008052')
FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_SHA256 = (
    'b1d0f82afbba467201b2fde19cb65a48472d116986ee74e9839391fa3856d10c')
FC_XNU_TXM_HANDLER_PROLOGUE_BYTES = FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES[:12]
FC_XNU_TXM_HANDLER_PROLOGUE_SHA256 = (
    '655880939a21073461ec3205710e563192708ef39efba1bcda2fcc6b7a4b547f')
FC_XNU_TXM_HANDLER_LOCAL_SETUP_SIZE = 72
FC_XNU_TXM_HANDLER_LOCAL_SETUP_SHA256 = (
    '1fcac5866c4d8affc36d9629bfca548ecb049ccbaf79adcb9396937c0e395920')
FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE = 164
FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SHA256 = (
    '154e2bc48712d68ffffb82e2f24932f557e3ee82cab83447de95615f276d9b63')
FC_XNU_TXM_HANDLER_GLOBAL = 0xfffffe0017074690
FC_XNU_TXM_HANDLER_RESPONSE_POINTER = 0xfffffe0017014500
FC_XNU_TXM_HANDLER_RESPONSE_STOP = 0xfffffe001702f2a0
FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN = 0xfffffe002bc5fb88
FC_XNU_RUNTIME_TEXT = (0xfffffe00288ec000, 0xfffffe002bfb0000)
FC_SPTM_RUNTIME_TEXT = (0xfffffe00070a0000, 0xfffffe00070fc000)
FC_TXM_RUNTIME_TEXT = (0xfffffe0017024000, 0xfffffe0017068000)
FC_TXM_COMPLETION_FAST_STEPS = 65536
FC_XNU_PHASE53_FAST_STEPS = 1 << 24
FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC = 0xfffffe0017031208
FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC_WORD = 0xd40004c1
FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR = 0xfffffe00070a8400
FC_VEL2_STEP_FILTER_TERMINAL = 3
FC_VEL2_STEP_FILTER_OUTSIDE = 4
FC_VEL2_STEP_FILTER_RUNNING = 1
FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET = 0xfffffe00070a5fd4
FC_XNU_TXM_HANDLER_CMD1_RETURN_LINKED = 0xfffffff01703120c
FC_XNU_TXM_HANDLER_CMD1_RETURN_BYTES = bytes.fromhex('e827c1a8c0035fd6')
FC_XNU_TXM_HANDLER_CMD1_GUARDED_ESR = 0x56000026
FC_XNU_TXM_HANDLER_CMD1_GUARDED_ASPSR = 5
FC_XNU_TXM_HANDLER_CMD1_MDSCR_PC = 0xfffffe00070a649c
FC_XNU_TXM_HANDLER_CMD1_MDSCR_ESR = 0x62240124
FC_XNU_TXM_HANDLER_CMD1_MDSCR_WORD = 0xd5100249
FC_XNU_TXM_HANDLER_CMD1_MDSCR_VALUE = 1 << 12
FC_XNU_TXM_HANDLER_CMD1_RETAB = 0xfffffe002bf79a5c
FC_XNU_TXM_HANDLER_CMD1_RETAB_LINKED = 0xfffffe000bf79a5c
FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD = 0xd65f0fff
FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS = 0xfffffe00070a4520
FC_XNU_TXM_HANDLER_CMD1_RETAB_SPSR = 0x604013c4
FC_XNU_PHASE53_ALLOC_CALL = 0xfffffe002bc5fc78
FC_XNU_PHASE53_ALLOC_CALL_LINKED = 0xfffffe000bc5fc78
FC_XNU_PHASE53_ALLOC_CALL_WORD = 0x97ee8bec
FC_XNU_PHASE53_ALLOC_ENTRY = 0xfffffe002b802c28
FC_XNU_PHASE53_AFTER_CMD1_FIRST = FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN
FC_XNU_PHASE53_ALLOC_INTERNAL_CALL = 0xfffffe002b802c58
FC_XNU_PHASE53_ALLOC_INTERNAL_CALL_LINKED = 0xfffffe000b802c58
FC_XNU_PHASE53_ALLOC_INTERNAL_CALL_WORD = 0x97fe97c1
FC_XNU_PHASE53_ALLOC_RETURN = 0xfffffe002b802c5c
FC_XNU_PHASE53_ALLOC_RETURN_LINKED = 0xfffffe000b802c5c
FC_XNU_PHASE53_ALLOC_RETURN_WORD = 0xaa0003f4
FC_XNU_PHASE53_POST_UBFIZ = 0xfffffe002b802cfc
FC_XNU_PHASE53_POST_UBFIZ_LINKED = 0xfffffe000b802cfc
FC_XNU_PHASE53_POST_UBFIZ_WORD = 0xd0fe29b7
FC_XNU_PHASE53_UBFIZ_PC = 0xfffffe002b802cf8
FC_XNU_PHASE53_RETYPE_CALL = 0xfffffe002b802d5c
FC_XNU_PHASE53_RETYPE_CALL_LINKED = 0xfffffe000b802d5c
FC_XNU_PHASE53_RETYPE_CALL_WORD = 0x941dddd5
FC_XNU_PHASE53_GENTER = 0xfffffe002bf7a4c4
FC_XNU_PHASE53_GENTER_LINKED = 0xfffffe000bf7a4c4
FC_XNU_PHASE53_GENTER_WORD = 0x00201420
FC_XNU_PHASE53_GENTER_PREVIOUS = 0xfffffe002bf7a4c0
FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED = 0xfffffe000bf7a4c0
FC_XNU_PHASE53_GENTER_PREVIOUS_WORD = 0xd2800030
FC_XNU_PHASE53_GEXIT = 0xfffffe00070a4520
FC_XNU_PHASE53_GEXIT_LINKED = 0xfffffff0270a4520
FC_XNU_PHASE53_GEXIT_WORD = 0x00201400
FC_XNU_PHASE53_GENTER_RETURN = 0xfffffe002bf7a4c8
FC_XNU_PHASE53_GENTER_RETURN_LINKED = 0xfffffe000bf7a4c8
FC_XNU_PHASE53_GENTER_RETURN_WORD = 0x97db1f6a
FC_XNU_PHASE53_GENTER_RETURN_SPSR = 0x604013c4
FC_XNU_PHASE53_RETYPE_RETURN = 0xfffffe002b802d60
FC_XNU_PHASE53_RETYPE_RETURN_LINKED = 0xfffffe000b802d60
FC_XNU_PHASE53_RETYPE_RETURN_WORD = 0xaa1503e0
FC_SPTM_PHASE53_FTE_BASE_POINTER = 0xfffffe00070993a8
FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY = 0xfffffe002bf7a4b0
FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED = 0xfffffe000bf7a4b0
FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_WORD = 0xd503237f
FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB = 0xfffffe002bf7a4d4
FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED = 0xfffffe000bf7a4d4
FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_WORD = 0xd65f0fff
FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_PREVIOUS = 0xfffffe002bf7a4d0
FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS = 1 << 27
FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS = 512
FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES = (0x12, 0x13, 0x14)
FC_XNU_TXM_HANDLER_HELPER = 0xfffffe0017031214
FC_XNU_TXM_HANDLER_HELPER_LINKED = 0xfffffff017031214
FC_XNU_TXM_HANDLER_HELPER_BYTES = bytes.fromhex(
    '5f2403d5e003009100c4729200104091000010d1c0035fd6')
FC_XNU_TXM_HANDLER_HELPER_SHA256 = (
    'c326d045bef11306062f7d48fcc0b9affac9d115a1ce0277f3dc4f662b3247c6')
FC_XNU_ENTRY_LINKED = 0xfffffe000bfb0000
FC_XNU_AGT_LINKED = 0xfffffe000bf91db0
FC_XNU_AGT_WORD = 0xd51cfec8       # msr AGTCNTRDIR_EL12, x8
FC_XNU_AGT_HVC = 0x60b8            # private exact-access trap; low bits retain rt=x8
FC_XNU_AGT_ESR = (0x16 << 26) | (1 << 25) | FC_XNU_AGT_HVC  # HVC64, IL=1, imm16
FC_XNU_CNTP_CTL_LINKED = 0xfffffe000bf923b0
FC_XNU_CNTP_CTL_WORD = 0xd51be228  # msr CNTP_CTL_EL0, x8
FC_XNU_CNTP_CTL_ESR = 0x6232f904
FC_XNU_APPLE_PHYS_TIMER_LINKED = 0xfffffe000bf923b4
FC_XNU_APPLE_PHYS_TIMER_WORD = 0xd519fd88  # msr S3_1_C15_C13_4, x8
FC_XNU_APPLE_PHYS_TIMER_ESR = 0x62387d1a
FC_XNU_APPLE_PHYS_TIMER_EL02 = (3, 4, 15, 4, 3)
FC_XNU_APPLE_PHYS_TIMER_OBSERVED_PRIOR = 6
FC_XNU_AHCR_NOP_SITES = (
    (0xfffffe000b8178d4, 0xd53cfc2a), # mrs x10, AHCR_EL2
    (0xfffffe000b8178dc, 0xd51cfc2a), # msr AHCR_EL2, x10
)
FC_XNU_M3_COMPAT_CHIPS = (0x8122, 0x6030, 0x6031, 0x6032, 0x6034)
ABSENT_REGION = (0xffffffffffffffff, 0xffffffffffffffff)
FC_XNU_DOCKCHANNEL_UART_IPA = 0x2e410c000
FC_XNU_DOCKCHANNEL_UART_FAR = 0xfffffe003a010000
FC_XNU_DOCKCHANNEL_READ_LINKED = 0xfffffe000b6b6fac
FC_XNU_DOCKCHANNEL_READ_WORD = 0xb9400016  # ldr w22, [x0]
FC_XNU_DOCKCHANNEL_READ_ESR = 0x93960006
FC_XNU_DOCKCHANNEL_CONFIG_IPA = 0x2e4128000
FC_XNU_DOCKCHANNEL_CONFIG_FAR = 0xfffffe003a000008
FC_XNU_DOCKCHANNEL_WRITE_LINKED = 0xfffffe000b6b740c
FC_XNU_DOCKCHANNEL_WRITE_WORD = 0xb9000001  # str w1, [x0]
FC_XNU_DOCKCHANNEL_WRITE_ESR = 0x93810047
FC_XNU_DOCKCHANNEL_RX8_IPA = 0x2e413401c
FC_XNU_DOCKCHANNEL_RX8_FAR = 0xfffffe003a00c01c
FC_XNU_DOCKCHANNEL_RX8_ESR = 0x93960007
FC_XNU_PANIC_CARVEOUT_IPA = 0x103e6c28000
FC_XNU_PANIC_CARVEOUT_SIZE = 0x188000
FC_XNU_PANIC_CARVEOUT_FAR = 0xfffffe003a014000
FC_XNU_PANIC_CARVEOUT_LINKED = 0xfffffe000bf3f3f4
FC_XNU_PANIC_CARVEOUT_WORD = 0xb9400009  # ldr w9, [x0]
FC_XNU_PANIC_CARVEOUT_ESR = 0x93890006
FC_XNU_SOCD_IPA = 0x2ede69014
FC_XNU_SOCD_SIZE = 0x39c
FC_XNU_SOCD_FAR = 0xfffffe003a61d014
FC_XNU_SOCD_LINKED = 0xfffffe000b72118c
FC_XNU_SOCD_WORD = 0xb9000169  # str w9, [x11]
FC_XNU_SOCD_ESR = 0x93890046
FC_XNU_PPERM_SITES = ((0xfffffe000b800260, 0xd53ef1c8, 0x6110, 'read-a'),
    (0xfffffe000b80026c, 0xd51ef1c8, 0x6111, 'write-b'),
    (0xfffffe000b80029c, 0xd53ef1c8, 0x6112, 'read-b'),
    (0xfffffe000b8002a8, 0xd51ef1c8, 0x6113, 'write-a'))


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
FC_XNU_M3_COMPAT_ORIGIN = '874ff59ea1297b8bdc438c6ad425efdcf4224dd3'
FC_XNU_M3_COMPAT_PINNED = '1c98fd09817cede0043d25c95fb540dbd683ef18'
FC_XNU_PMCR1_EL12_LINKED = 0xfffffe000b823a18
FC_XNU_PMCR1_EL1_WORD = 0xd519f111   # msr S3_1_C15_C1_0, x17
FC_XNU_PMCR1_EL12_WORD = 0xd519f751  # msr S3_1_C15_C7_2, x17
GXF_ENTER_ENC = (3, 6, 15, 8, 1)   # S3_6_C15_C8_1 = GXF_ENTER_EL1
TXM_WORLD_RETURN_LINKED = {
    '0xfffffff017068010',  # selector 0x100000001, TXM-rx bootstrap
    '0xfffffff0170532d8',  # selector 0x100000003
    '0xfffffff0170532ec',  # selector 0x100000002
    '0xfffffff017053300',  # selector 0x100000004
    '0xfffffff017053314',  # selector 0xfe00000000
    '0xfffffff017053328',  # selector 0xfd00000000
    '0xfffffff01705333c',  # selector 0xff00000000
}


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
    for pc, word, tag, operation in FC_XNU_PPERM_SITES:
        off = pc - segment['va']
        if bytes(out[off:off+4]) != struct.pack('<I', word):
            raise ValueError('Pinned XNU PPERM instruction mismatch: '+operation)
        replacement = struct.pack('<I', 0xd4000002 | (tag << 5))
        out = out[:off] + replacement + out[off+4:]
        records.append(dict(linked_va=hex(pc), original=hex(word), replacement=hex(struct.unpack('<I',replacement)[0]), operation=operation))
    return out, records


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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--checkout', type=Path, default=os.environ.get('VEL2_CHECKOUT'))
    ap.add_argument('--payload', type=Path, required=True)
    ap.add_argument('--device')
    ap.add_argument('--execute', action='store_true')
    ap.add_argument('--allow-monitor-mmu', action='store_true', help='Permit only the captured VHE monitor profile after address checks')
    ap.add_argument('--emulate-zero-loops', action='store_true', help='Emulate only an exact bounded zero-fill instruction pattern')
    ap.add_argument('--allow-live-ttbr', action='store_true', help='Validate bounded same-profile root replacements and continuation mappings')
    ap.add_argument('--relocate-boot-data', action='store_true', help='Copy RTBuddySeg, SEPFW and preoslog into guest RAM with contained firmware aliases')
    ap.add_argument('--steps', type=int, default=128)
    ap.add_argument('--report', type=Path, required=True)
    ap.add_argument('--run-dir', type=Path, help='Parent for unique attempt bundles; defaults beside report')
    ap.add_argument('--trace-window', type=int, help='Keep this many recent events in JSON and stream all events to JSONL; minimum 8192')
    ap.add_argument('--step-batch', type=int, default=0, help='Native ordinary-step batch size (0 disables; maximum 256); requires matching batch-capable runtime')
    ap.add_argument('--observe-sprr', action='store_true', help='Stage SPRR configuration writes while translation is live without enforcing any permission; observation only')
    ap.add_argument('--virtual-gxf', action='store_true', help='Observation-grade guarded world: genter/gexit control flow and banked exception state, no permission or guarded-page enforcement')
    ap.add_argument('--stage-el2-config', action='store_true', help='Record the monitor\'s remaining EL2 configuration writes (stage-2, traps, CTRR, locks, timers) without applying them')
    ap.add_argument('--stop-on-vector-entry', action='store_true', help='Exit at the first recorded PC inside the current guest VBAR_EL12 vector range')
    ap.add_argument('--pause-on-guard', action='store_true', help='Hold a deliberately rejected policy guard for a local resume/exit decision')
    ap.add_argument('--pause-timeout', type=float, default=3600, help='Seconds to wait for a guard decision before exiting the guest (maximum 86400)')
    ap.add_argument('--back-page', action='append', default=None, metavar='IPA[:COUNT]', help='Diagnostic: back COUNT contiguous 16KB guest IPA pages (hex base, 0x4000-aligned; COUNT default 1) with zeroed host RAM so monitor reads/writes to that region resolve; repeatable, observation only')
    ap.add_argument('--on-demand-stage2', type=int, default=0, metavar='MAXPAGES', help='Back guest stage-2 translation faults on demand: on a data-abort translation fault, translate the faulting VA stage-1-only to its IPA, map a fresh zeroed 16KB host page there, and retry. MAXPAGES caps the total pages mapped (0 disables). Needed once SPTM builds its frame table over physical pages our fixed guest window does not back.')
    ap.add_argument('--handoff-steps', type=int, default=0, help='After a verified TXM/XNU entry handoff, single-step at most 1..4096 events; default 0 stops before transfer')
    ap.add_argument('--handoff-breakpoint-offset', type=lambda value: int(value, 0), help='Rejected legacy control: software HVC breakpoints route into SPTM under real guarded execution')
    ap.add_argument('--native-handoff', action='store_true', help='After a verified TXM/XNU entry handoff, resume it natively without single-step; use guarded-vector and watchdog stops to capture the next firmware exception')
    ap.add_argument('--xnu-steps', type=int, default=0, help='After native TXM completion, normalize the verified XNU GEXIT to physical EL1h and single-step up to 1..4096 events')
    ap.add_argument('--xnu-run', action='store_true', help='After the bounded verified XNU prefix, run natively until the next probe exception or watchdog')
    ap.add_argument('--xnu-m3-nop-ahcr-compat', action='store_true', help='Diagnostic: reproduce upstream m1n1 M3 behavior by NOPing only the exact pinned XNU AHCR_EL2 pair; does not emulate AHCR hardware effects')
    ap.add_argument('--xnu-dockchannel-uart-mmio', action='store_true', help='After XNU handoff, lazily identity-map only the source-verified M3 dockchannel-uart register page on its exact stage-2 fault; requires --xnu-run and --on-demand-stage2')
    ap.add_argument('--xnu-private-panic-carveout', action='store_true', help='Copy the verified panic-log carveout into private host RAM, then remap its original IPA only at the exact first XNU fault; original firmware memory is never written; requires --xnu-run and --on-demand-stage2')
    ap.add_argument('--xnu-private-socd-trace', action='store_true', help='Copy only the exact 924-byte /socd-trace-ram region into a private zero-padded 16KB page and map it at the exact first XNU fault; requires --xnu-run and --on-demand-stage2')
    ap.add_argument('--xnu-pperm-guest-window', action='store_true', help='Redirect only the pinned XNU temporary PPERM A-B-A window to PPERM_EL12; requires --xnu-run')
    ap.add_argument('--xnu-pperm-guest-window-limit', type=int, default=1, help='Maximum complete PPERM guest windows (1..4096); requires --xnu-pperm-guest-window for values other than 1')
    ap.add_argument('--xnu-apple-physical-timer-hypothesis', action='store_true', help='Diagnostic hypothesis: service only the exact attempt-65 Apple timer trap through candidate guest bank S3_4_C15_C4_3 after verifying its retained raw value 6; routing and bit semantics remain inferred; requires --xnu-run')
    ap.add_argument('--xnu-tpidr-gl2-fast-shadow', action='store_true', help='After the verified XNU prefix only, move the existing TPIDR_GL2 HVC shadow into the pinned firmware fast path; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-entry-one-step', action='store_true', help='At the exact verified TXM context-entry ERET only, execute mov sp,x0 and stop at the following software-step; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-entry-register-prefix', action='store_true', help='Execute only the exact deterministic non-memory TXM context-entry prefix and stop before its first CASB; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-stack-claim-one-step', action='store_true', help='After the verified TXM register prefix, execute only its exact CASB 0-to-1 owned-stack claim and stop; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-stack-metadata-init', action='store_true', help='After the verified TXM stack claim, take only the exact x9==0 path, verify its three same-page metadata stores, and stop before the x18 branch; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-x18-branch-one-step', action='store_true', help='After verified TXM stack metadata initialization, execute only the exact taken x18 CBNZ and stop before its target branch; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-outbound-branch-one-step', action='store_true', help='After the verified x18 branch, execute only the exact outbound B into the TXM command handler and stop before PACIBSP; requires --xnu-run')
    ap.add_argument('--xnu-txm-handler-boundary', choices=('prologue', 'register-saves', 'local-setup', 'validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace'), help='Replay the exact TXM context-entry path and stop at a named, source-pinned handler boundary; requires --xnu-run')
    ap.add_argument('--xnu-txm-sstep-fast-path', action='store_true', help='At the source/live-verified cmd1 completion SVC only, use the bounded firmware software-step filter across TXM/SPTM and stop at the exact XNU return; requires --xnu-txm-handler-boundary=cmd1-completion-trace')
    ap.add_argument('--xnu-phase53-allocation-trace', action='store_true', help='After verified cmd1 completion, continue with the bounded firmware filter to the exact XNU allocation call; requires cmd1 completion fast path')
    ap.add_argument('--xnu-phase53-retype-survey', action='store_true', help='After the verified Phase 5.3 allocation retype, survey at most 64 subsequent common-wrapper retypes and stop at the first XNU root/page-table target')
    ap.add_argument('--xnu-phase53-retype-survey-limit', type=int, default=64, help='Maximum completed common-wrapper retypes in the Phase 5.3 survey (1..64)')
    ap.add_argument('--hang-budget', type=int, help='Required with --free-run: guest wall-clock limit in seconds (1..86400); timer-polled clean interrupt, then 15s grace')
    ap.add_argument('--free-run', action='store_true', help='Run the guest natively (no single-step) to reach a milestone fast: handle every trap as now but resume without the single-step bit, disable batching, enable HCR.TWE so the panic wfe-halt (0xf8b88) traps (a benign wfe is skipped), and stop at a verified image entry handoff or the panic halt. Pair with --on-demand-stage2. Per-step features (zero-loop emulation, single-step window, guarded-call selectors) do not apply.')
    ap.add_argument('--snapshot-leaf', action='append', default=None, metavar='VA', help='At exit, walk the final monitor ttbr for each VA (hex), save the walked tables, and decode the leaf against live guest SPRR permissions in real mode (staged otherwise); observation only, repeatable')
    ap.add_argument('--single-step-after', type=int, default=0, help='After this many recorded events, stop native batching and single-step so a vector-entry syndrome is captured without batch overshoot (0 disables)')
    ap.add_argument('--real-guarded', action='store_true', help='R2 (real enforcement): do not virtualize genter/gexit (native GXF transitions) and really enable SPRR at the enable point (apply captured permissions then config), instead of staging. Off by default; first-contact use only, gated by the reversibility rehearsal.')
    ap.add_argument('--real-guarded-vbar', action='store_true', help='With real guarded execution, apply SPTM VBAR_GL1 writes through the existing VBAR_GL12 alias so TXM exceptions reach SPTM vectors; hardware-check one register path at a time')
    ap.add_argument('--single-step-window', metavar='START:COUNT', help='Single-step recorded events in [START, START+COUNT) and batch outside it, so a bounded transition (e.g. the genter divert) is captured at instruction granularity without crawling the whole tail or spinning to budget. COUNT default 1.')
    ap.add_argument('--stop-on-guarded-vector', action='store_true', help='In --real-guarded, stop at the first guarded-world exception vector entry (a recorded PC inside the current VBAR_GL1 range) and snapshot the guarded bank (ESR_GL1/ELR_GL1/VBAR_GL1) so the original trigger syndrome is captured before the self-fault spin overwrites it.')
    ap.add_argument('--first-contact', action='store_true', help='R2 first contact (requires --real-guarded): patch the SPTM normal-world WFE idle at 0xf8b88 to genter #0 so, once SPTM finishes init and reaches idle, it issues a real guarded call into the dispatcher (0xa4524). Single-step across the boundary and HALT at 0xa4ac0, before the T0 branch to the C service (0xe8d4c) -- non-mutating by construction. Requires single-step coverage of the idle region (single-step-window/after).')
    ap.add_argument('--guarded-call-selectors', metavar='HEX[,HEX...]', help='R2 multi-call (requires --real-guarded): reuse the idle->genter patch to issue one real guarded call per selector, IN ONE run (the patched idle is a genter loop: genter->service->gexit->b->genter). Sets x16=selector at each genter and captures x0 at each return; stops after the list. MUTATING -- the C service runs. Needs single-step coverage of the call region. This is the way to do consecutive guarded work without a power cycle (a 2nd hv_start cannot: SPTM locks SPRR/GXF).')
    a = ap.parse_args()
    if a.checkout is None or not 1 <= a.steps <= 33554432:
        ap.error('A checkout and 1..33554432 steps are required')
    if a.real_guarded and a.virtual_gxf:
        ap.error('--real-guarded and --virtual-gxf are mutually exclusive (real vs observation-grade GXF)')
    if a.real_guarded_vbar and not a.real_guarded:
        ap.error('--real-guarded-vbar requires --real-guarded')
    if a.single_step_window is not None:
        try:
            parts = a.single_step_window.split(':')
            start = int(parts[0], 0)
            count = int(parts[1], 0) if len(parts) > 1 else 1
        except (ValueError, IndexError):
            ap.error('--single-step-window must be START[:COUNT] (decimal or 0x hex)')
        if len(parts) > 2 or start < 0 or not 1 <= count <= 1048576:
            ap.error('--single-step-window START must be >= 0 and COUNT 1..1048576')
    if a.stop_on_guarded_vector and not a.real_guarded:
        ap.error('--stop-on-guarded-vector requires --real-guarded')
    if a.first_contact and not a.real_guarded:
        ap.error('--first-contact requires --real-guarded')
    if a.guarded_call_selectors is not None:
        if not a.real_guarded:
            ap.error('--guarded-call-selectors requires --real-guarded')
        try:
            sels = [int(s, 0) for s in a.guarded_call_selectors.split(',') if s.strip()]
        except ValueError:
            ap.error('--guarded-call-selectors must be a comma-separated list of hex/int selector values')
        if not sels or len(sels) > 256 or any(not 0 <= s <= (1 << 64) - 1 for s in sels):
            ap.error('--guarded-call-selectors: 1..256 selectors, each a 64-bit value')
    if not 0 <= a.step_batch <= 256:
        ap.error('--step-batch must be 0..256')
    if a.steps > 2097152 and not a.step_batch:
        ap.error('Budgets above 2097152 require native step batching')
    if a.trace_window is not None and a.trace_window < 8192:
        ap.error('--trace-window must be at least 8192')
    if a.steps > 131072 and a.trace_window is None:
        ap.error('Budgets above 131072 require --trace-window')
    if a.execute and not a.device:
        ap.error('--execute requires --device')
    if not 0 < a.pause_timeout <= 86400:
        ap.error('--pause-timeout must be in (0, 86400] seconds')
    if a.free_run and (a.hang_budget is None or not 1 <= a.hang_budget <= 86400):
        ap.error('--free-run requires --hang-budget in 1..86400 seconds')
    if a.hang_budget is not None and not a.free_run:
        ap.error('--hang-budget requires --free-run')
    if a.xnu_apple_physical_timer_hypothesis and not a.xnu_run:
        ap.error('--xnu-apple-physical-timer-hypothesis requires --xnu-run')
    if a.xnu_tpidr_gl2_fast_shadow and not a.xnu_run:
        ap.error('--xnu-tpidr-gl2-fast-shadow requires --xnu-run')
    if a.xnu_txm_context_entry_one_step and not a.xnu_run:
        ap.error('--xnu-txm-context-entry-one-step requires --xnu-run')
    if a.xnu_txm_context_entry_register_prefix and not a.xnu_run:
        ap.error('--xnu-txm-context-entry-register-prefix requires --xnu-run')
    if a.xnu_txm_context_stack_claim_one_step and not a.xnu_run:
        ap.error('--xnu-txm-context-stack-claim-one-step requires --xnu-run')
    if a.xnu_txm_context_stack_metadata_init and not a.xnu_run:
        ap.error('--xnu-txm-context-stack-metadata-init requires --xnu-run')
    if a.xnu_txm_context_x18_branch_one_step and not a.xnu_run:
        ap.error('--xnu-txm-context-x18-branch-one-step requires --xnu-run')
    if a.xnu_txm_context_outbound_branch_one_step and not a.xnu_run:
        ap.error('--xnu-txm-context-outbound-branch-one-step requires --xnu-run')
    if a.xnu_txm_handler_boundary is not None and not a.xnu_run:
        ap.error('--xnu-txm-handler-boundary requires --xnu-run')
    if (a.xnu_txm_sstep_fast_path and
            a.xnu_txm_handler_boundary != 'cmd1-completion-trace'):
        ap.error('--xnu-txm-sstep-fast-path requires --xnu-txm-handler-boundary=cmd1-completion-trace')
    if (a.xnu_phase53_allocation_trace and
            (not a.xnu_txm_sstep_fast_path or
             a.xnu_txm_handler_boundary != 'cmd1-completion-trace')):
        ap.error('--xnu-phase53-allocation-trace requires the cmd1 completion fast path')
    if a.xnu_phase53_retype_survey and not a.xnu_phase53_allocation_trace:
        ap.error('--xnu-phase53-retype-survey requires --xnu-phase53-allocation-trace')
    if not 1 <= a.xnu_phase53_retype_survey_limit <= 64:
        ap.error('--xnu-phase53-retype-survey-limit must be in 1..64')
    if (a.xnu_phase53_retype_survey_limit != 64 and
            not a.xnu_phase53_retype_survey):
        ap.error('--xnu-phase53-retype-survey-limit requires --xnu-phase53-retype-survey')
    if sum((a.xnu_txm_context_entry_one_step,
            a.xnu_txm_context_entry_register_prefix,
            a.xnu_txm_context_stack_claim_one_step,
            a.xnu_txm_context_stack_metadata_init,
            a.xnu_txm_context_x18_branch_one_step,
            a.xnu_txm_context_outbound_branch_one_step,
            a.xnu_txm_handler_boundary is not None)) > 1:
        ap.error('TXM context-entry probes are mutually exclusive')
    if not 0 <= a.handoff_steps <= 4096 or (a.handoff_steps and not (a.free_run and a.real_guarded)):
        ap.error('--handoff-steps requires --free-run --real-guarded and a budget in 1..4096')
    if a.native_handoff and (not (a.free_run and a.real_guarded) or a.handoff_steps):
        ap.error('--native-handoff requires --free-run --real-guarded and is mutually exclusive with handoff steps')
    if not 0 <= a.xnu_steps <= 4096 or (a.xnu_steps and not a.native_handoff):
        ap.error('--xnu-steps requires --native-handoff and a budget in 1..4096')
    if a.xnu_run and not a.xnu_steps:
        ap.error('--xnu-run requires --xnu-steps')
    if a.xnu_m3_nop_ahcr_compat and not a.xnu_run:
        ap.error('--xnu-m3-nop-ahcr-compat requires --xnu-run')
    if a.xnu_dockchannel_uart_mmio and not (a.xnu_run and a.on_demand_stage2):
        ap.error('--xnu-dockchannel-uart-mmio requires --xnu-run and --on-demand-stage2')
    if a.xnu_private_panic_carveout and not (a.xnu_run and a.on_demand_stage2):
        ap.error('--xnu-private-panic-carveout requires --xnu-run and --on-demand-stage2')
    if a.xnu_private_socd_trace and not (a.xnu_run and a.on_demand_stage2):
        ap.error('--xnu-private-socd-trace requires --xnu-run and --on-demand-stage2')
    if a.xnu_pperm_guest_window and not a.xnu_run:
        ap.error('--xnu-pperm-guest-window requires --xnu-run')
    if not 1 <= a.xnu_pperm_guest_window_limit <= 4096:
        ap.error('--xnu-pperm-guest-window-limit must be 1..4096')
    if a.xnu_pperm_guest_window_limit != 1 and not a.xnu_pperm_guest_window:
        ap.error('--xnu-pperm-guest-window-limit requires --xnu-pperm-guest-window')
    if a.handoff_breakpoint_offset is not None:
        ap.error('--handoff-breakpoint-offset is unsafe in real guarded execution: its HVC routes to SPTM, not EL2')
    parameters = {k: str(v) if isinstance(v, Path) else v for k, v in vars(a).items()}
    capture = RunCapture(a.run_dir or a.report.parent/(a.report.name+'.runs'), a.report,
                         parameters, repo=Path(__file__).resolve().parents[1], checkout=a.checkout)
    report = {'scope': 'bounded-sptm-entry', 'guest_boot_verified': False,
              'hardware_executed': False, 'steps_limit': a.steps, 'trace': [], 'run_id': capture.run_id, 'trace_window': a.trace_window}
    error = None
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Received signal '+str(signum))
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        capture.save(report)
        run_probe(a, report, lambda: capture.save(report), capture)
    except BaseException as caught:
        error = caught
        raise
    finally:
        signal.signal(signal.SIGTERM, previous)
        try:
            capture.finish(report, error)
        except Exception as save_error:
            print('Attempt finalization failed:', save_error, file=sys.stderr)
            if error is None:
                raise
        print('Attempt bundle:', capture.root, file=sys.stderr)


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
        aggregate_step_limit=FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS,
        rearm_limit=FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS,
        target_types=[hex(value) for value in
                      FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES],
        primary_target='0xb->0x14')
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
            chunk, pperm_patches = patch_xnu_pperm_guest_window(
                chunk, seg, a.xnu_pperm_guest_window)
            if pperm_patches:
                report['xnu_pperm_guest_window'] = dict(enabled=True, patches=pperm_patches,
                    sequence=[], memcpy_crossed=False, physical_pperm_el1_touched=False,
                    chip_id=hex(chip_id), profile='native XNU under real-guarded VEL2',
                    limit=a.xnu_pperm_guest_window_limit, started_windows=0,
                    completed_windows=0, memcpy_crossed_windows=0)
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
    xnu_agt_state = dict(previous=None, writes=0)
    xnu_cntp_ctl_state = dict(previous=None, writes=0)
    xnu_pperm_state = dict(previous=None, step=0, modified=False,
                           started=0, completed=0)
    xnu_apple_timer_state = dict(previous=None, writes=0)
    watchdog = FreeRunWatchdog(iface, a.hang_budget) if a.free_run else None
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
    def stopped(reason,code,info):
        nonlocal entered, shadow_hcr, shadow_sctlr, shadow_sprr_config, real_sprr_on, guarded_vbar, monitor_mmu_validated
        ret = EXC_RET.EXIT_GUEST
        event = dict(reason=int(reason),code=int(code))
        try:
            native_sptm_callback = False
            native_xnu_agt_callback = False
            native_xnu_cntp_ctl_callback = False
            native_xnu_apple_timer_callback = False
            native_xnu_pperm_site = None
            native_dockchannel_site = None
            native_panic_carveout = False
            native_socd_trace = False
            if handoff_state.get('native'):
                native_ctx = iface.readstruct(info, ExcInfo)
                if dockchannel_mmio is not None and report.get('handoff', {}).get('target_pc'):
                    native_dockchannel_site = match_xnu_dockchannel_uart(
                        native_ctx, int(report['handoff']['target_pc'], 0), dockchannel_mmio)
                if panic_carveout is not None and report.get('handoff', {}).get('target_pc'):
                    native_panic_carveout = match_xnu_panic_carveout(
                        native_ctx, int(report['handoff']['target_pc'], 0))
                if socd_trace is not None and report.get('handoff', {}).get('target_pc'):
                    native_socd_trace = match_xnu_socd_trace(
                        native_ctx, int(report['handoff']['target_pc'], 0))
                # XNU's real guarded calls re-enter our instrumented SPTM. Only
                # admit the exact HVC produced from the pinned SPTM instruction;
                # other native exceptions remain observation stops.
                if (reason == START.EXCEPTION_LOWER and code == EXC.SYNC
                        and int(native_ctx.esr) >> 26 == 0x16):
                    segment = layout.get('images', {}).get('sptm', {}).get('segments', {}).get('__TEXT_EXEC', {})
                    off = native_ctx.elr - 4 - FC_IMAGE_BASE
                    lo = segment.get('fileoff', 0)
                    hi = lo + segment.get('filesize', 0)
                    original_word = sources.get('sptm', b'')[off:off+4] if lo <= off < hi else b''
                    expected = struct.pack('<I', 0xd4000002 | ((int(native_ctx.esr) & 0xffff) << 5))
                    if len(original_word) == 4 and patch_probe_code(original_word) == expected:
                        native_sptm_callback = True
                        report['xnu_sptm_callbacks'] = report.get('xnu_sptm_callbacks', 0) + 1
                    if a.xnu_pperm_guest_window:
                        tag = int(native_ctx.esr) & 0xffff
                        for index, site in enumerate(FC_XNU_PPERM_SITES):
                            pc, word, expected_tag, operation = site
                            runtime_pc = int(report['handoff']['target_pc'], 0) + pc - FC_XNU_ENTRY_LINKED
                            kseg = layout.get('images', {}).get('kernelcache', {}).get('segments', {}).get('__TEXT_EXEC', {})
                            source_off = kseg.get('fileoff', 0) + pc - kseg.get('va', 0)
                            source_original = sources.get('kernelcache', b'')[source_off:source_off+4]
                            if (tag == expected_tag and native_ctx.elr - 4 == runtime_pc
                                    and source_original == struct.pack('<I', word)):
                                native_xnu_pperm_site = (index, site)
                                native_sptm_callback = False
                                break
                if (reason == START.EXCEPTION_LOWER and code == EXC.SYNC
                        and int(native_ctx.esr) == FC_XNU_AGT_ESR):
                    segment = layout.get('images', {}).get('kernelcache', {}).get('segments', {}).get('__TEXT_EXEC', {})
                    within_segment = (segment.get('va', 0) <= FC_XNU_AGT_LINKED
                                      and FC_XNU_AGT_LINKED + 4 <= segment.get('va', 0) + segment.get('filesize', 0))
                    source_off = segment.get('fileoff', 0) + FC_XNU_AGT_LINKED - segment.get('va', 0)
                    original_word = (sources.get('kernelcache', b'')[source_off:source_off+4]
                                     if within_segment else b'')
                    runtime_pc = (int(report.get('handoff', {}).get('target_pc', '0'), 0)
                                  + FC_XNU_AGT_LINKED - FC_XNU_ENTRY_LINKED)
                    native_xnu_agt_callback = (native_ctx.elr - 4 == runtime_pc
                        and original_word == struct.pack('<I', FC_XNU_AGT_WORD))
                if (reason == START.EXCEPTION_LOWER and code == EXC.SYNC
                        and int(native_ctx.esr) == FC_XNU_CNTP_CTL_ESR):
                    segment = layout.get('images', {}).get('kernelcache', {}).get('segments', {}).get('__TEXT_EXEC', {})
                    within_segment = (segment.get('va', 0) <= FC_XNU_CNTP_CTL_LINKED
                                      and FC_XNU_CNTP_CTL_LINKED + 4 <= segment.get('va', 0) + segment.get('filesize', 0))
                    source_off = segment.get('fileoff', 0) + FC_XNU_CNTP_CTL_LINKED - segment.get('va', 0)
                    original_word = (sources.get('kernelcache', b'')[source_off:source_off+4]
                                     if within_segment else b'')
                    runtime_pc = (int(report.get('handoff', {}).get('target_pc', '0'), 0)
                                  + FC_XNU_CNTP_CTL_LINKED - FC_XNU_ENTRY_LINKED)
                    native_xnu_cntp_ctl_callback = (native_ctx.elr == runtime_pc
                        and original_word == struct.pack('<I', FC_XNU_CNTP_CTL_WORD))
                if (a.xnu_apple_physical_timer_hypothesis
                        and reason == START.EXCEPTION_LOWER and code == EXC.SYNC
                        and int(native_ctx.esr) == FC_XNU_APPLE_PHYS_TIMER_ESR):
                    segment = layout.get('images', {}).get('kernelcache', {}).get('segments', {}).get('__TEXT_EXEC', {})
                    within_segment = (segment.get('va', 0) <= FC_XNU_APPLE_PHYS_TIMER_LINKED
                                      and FC_XNU_APPLE_PHYS_TIMER_LINKED + 4 <= segment.get('va', 0) + segment.get('filesize', 0))
                    source_off = segment.get('fileoff', 0) + FC_XNU_APPLE_PHYS_TIMER_LINKED - segment.get('va', 0)
                    original_word = (sources.get('kernelcache', b'')[source_off:source_off+4]
                                     if within_segment else b'')
                    runtime_pc = (int(report.get('handoff', {}).get('target_pc', '0'), 0)
                                  + FC_XNU_APPLE_PHYS_TIMER_LINKED - FC_XNU_ENTRY_LINKED)
                    native_xnu_apple_timer_callback = (native_ctx.elr == runtime_pc
                        and original_word == struct.pack('<I', FC_XNU_APPLE_PHYS_TIMER_WORD))
            if batch is not None:
                try:
                    batch.drain(report)
                except Exception:
                    report['trace_incomplete'] = True
                    raise
            if watchdog is not None and watchdog.expired:
                ctx = iface.readstruct(info, ExcInfo)
                event.update(kind='hang-budget', pc=ctx.elr, spsr=int(ctx.spsr), regs=list(ctx.regs))
                report['stop_reason'] = 'hang'
            elif ((phase53_allocation_trace_state.get('active') or
                   phase53_retype_survey_state.get('active')) and
                  handoff_state.get('native') and
                  reason == START.EXCEPTION_LOWER and code == EXC.SYNC and
                  int(native_ctx.esr) >> 26 == 0x32 and
                  native_ctx.elr == FC_XNU_TXM_HANDLER_CMD1_RETAB):
                ctx = native_ctx
                phase53_filter_state = (phase53_retype_survey_state
                    if phase53_retype_survey_state.get('active')
                    else phase53_allocation_trace_state)
                phase53_report_key = ('xnu_phase53_retype_survey'
                    if phase53_retype_survey_state.get('active')
                    else 'xnu_phase53_allocation_trace')
                pac_mask = (1 << 40) - 1
                return_pc = ((FC_XNU_RUNTIME_TEXT[0] & ~pac_mask) |
                             (int(ctx.regs[30]) & pac_mask))
                transition = dict(
                    kind='authenticated-retab', trap_pc=hex(ctx.elr),
                    return_pc=hex(return_pc), spsr=hex(int(ctx.spsr)),
                    x30=hex(int(ctx.regs[30])))
                checks = {
                    'exact_spsr': int(ctx.spsr) ==
                        FC_XNU_TXM_HANDLER_CMD1_RETAB_SPSR,
                    'return_pc_in_xnu': FC_XNU_RUNTIME_TEXT[0] <= return_pc <
                        FC_XNU_RUNTIME_TEXT[1],
                }
                try:
                    fast_status = txm_sstep_fast_path.status()
                    current_range = phase53_filter_state['range0']
                    segment_start = phase53_filter_state[
                        'segment_start']
                    roots = phase53_filter_state['roots']
                    def read_phase53_retab_page(table):
                        if (table & (PAGE - 1) or
                                not base <= table < table + PAGE <= base + guest_size):
                            raise ValueError('Phase53 RETAB table outside owned RAM')
                        return iface.readmem(table, PAGE)
                    retab_leaf = translate(ctx.elr, roots['ttbr0'], roots['ttbr1'],
                                           read_phase53_retab_page)
                    retab_live = iface.readmem(retab_leaf['pa'], 4)
                    kernel_segment = layout['images']['kernelcache'][
                        'segments']['__TEXT_EXEC']
                    retab_source_offset = (kernel_segment['fileoff'] +
                        FC_XNU_TXM_HANDLER_CMD1_RETAB_LINKED -
                        kernel_segment['va'])
                    retab_source = sources['kernelcache'][
                        retab_source_offset:retab_source_offset + 4]
                    expected_retab = struct.pack(
                        '<I', FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD)
                    survey_aggregate = (phase53_filter_state.get(
                        'aggregate_steps', 0) + fast_status['steps'])
                    checks.update(
                        source_word=retab_source == expected_retab,
                        live_word=(retab_live == expected_retab and
                                   retab_live == retab_source),
                        level_three=retab_leaf['level'] == 3,
                        access_flag=retab_leaf['access_flag'],
                        filter_outside=(not fast_status['active'] and
                            fast_status['status'] ==
                                FC_VEL2_STEP_FILTER_OUTSIDE),
                        filter_bounded=(0 < fast_status['steps'] <=
                            FC_XNU_PHASE53_FAST_STEPS),
                        filter_last_pc=fast_status['last_pc'] == ctx.elr,
                        filter_previous_pc=fast_status['previous_pc'] ==
                            FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS,
                        filter_segment=(
                            fast_status['first_pc'] == segment_start and
                            fast_status['expected_first_pc'] == segment_start and
                            fast_status['range0_hits'] +
                                fast_status['range1_hits'] ==
                                fast_status['steps']),
                        filter_contract=(
                            fast_status['range0_start'] == current_range[0] and
                            fast_status['range0_end'] == current_range[1] and
                            current_range == FC_TXM_RUNTIME_TEXT and
                            fast_status['range1_start'] ==
                                FC_SPTM_RUNTIME_TEXT[0] and
                            fast_status['range1_end'] ==
                                FC_SPTM_RUNTIME_TEXT[1] and
                            fast_status['terminal_pc'] ==
                                phase53_filter_state['terminal_pc'] and
                            fast_status['max_steps'] ==
                                FC_XNU_PHASE53_FAST_STEPS))
                    if phase53_retype_survey_state.get('active'):
                        checks.update(
                            aggregate_budget=(survey_aggregate <=
                                FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS),
                            rearm_budget=(phase53_filter_state['rearms'] <
                                FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS))
                    transition.update(
                        pa=hex(retab_leaf['pa']),
                        source_hex=retab_source.hex(),
                        live_hex=retab_live.hex(), prior_status=fast_status)
                    if all(checks.values()):
                        enabled_status = txm_sstep_fast_path.enable(
                            FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
                            phase53_filter_state['terminal_pc'],
                            FC_XNU_PHASE53_FAST_STEPS, ctx.elr)
                        phase53_filter_state['range0'] = FC_XNU_RUNTIME_TEXT
                        phase53_filter_state['segment_start'] = ctx.elr
                        if phase53_retype_survey_state.get('active'):
                            phase53_filter_state['aggregate_steps'] = (
                                survey_aggregate)
                            phase53_filter_state['rearms'] += 1
                            report[phase53_report_key].update(
                                aggregate_steps=survey_aggregate,
                                rearms=phase53_filter_state['rearms'])
                        transition.update(enable_status=enabled_status,
                                          checks=checks, complete=True)
                        phase53_filter_state[
                            'world_transitions'].append(transition)
                        report[phase53_report_key][
                            'world_transitions'] = list(
                                phase53_filter_state[
                                    'world_transitions'])
                        event.update(kind='phase53-authenticated-retab',
                                     pc=ctx.elr, esr=int(ctx.esr),
                                     spsr=int(ctx.spsr), regs=list(ctx.regs),
                                     far=ctx.far, sp=list(ctx.sp), checks=checks)
                        ctx.spsr.SS = 1
                        u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                        iface.writemem(info, ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    else:
                        transition.update(checks=checks, complete=False)
                        phase53_filter_state['active'] = False
                        report[phase53_report_key][
                            'world_transition_rejection'] = transition
                        report['stop_reason'] = (
                            'phase53-retab-transition-gate-rejected')
                except Exception as transition_error:
                    checks['gate_readback'] = False
                    transition.update(checks=checks,
                                      error=str(transition_error), complete=False)
                    phase53_filter_state['active'] = False
                    report[phase53_report_key][
                        'world_transition_rejection'] = transition
                    report['stop_reason'] = (
                        'phase53-retab-transition-gate-rejected')
            elif (phase53_retype_survey_state.get('active') and
                  phase53_retype_survey_state.get('stage') == 'seek-entry' and
                  phase53_retype_survey_state.get('completed_calls', 0) > 0 and
                  phase53_retype_survey_state.get('range0') ==
                      FC_TXM_RUNTIME_TEXT and
                  handoff_state.get('native') and
                  reason == START.EXCEPTION_LOWER and code == EXC.SYNC and
                  int(native_ctx.esr) >> 26 == 0x32 and
                  FC_XNU_RUNTIME_TEXT[0] <= native_ctx.elr <
                      FC_XNU_RUNTIME_TEXT[1]):
                ctx = native_ctx
                state = phase53_retype_survey_state
                checks = {
                    'exact_spsr': int(ctx.spsr) ==
                        FC_XNU_PHASE53_GENTER_RETURN_SPSR,
                    'returned_pc_in_xnu': FC_XNU_RUNTIME_TEXT[0] <= ctx.elr <
                        FC_XNU_RUNTIME_TEXT[1],
                }
                transition = dict(
                    kind='survey-unrelated-gexit-return', pc=hex(ctx.elr),
                    spsr=hex(int(ctx.spsr)), completed_calls=
                        state['completed_calls'])
                try:
                    fast_status = txm_sstep_fast_path.status()
                    roots = state['roots']
                    def read_survey_unrelated_return_page(table):
                        if (table & (PAGE - 1) or
                                not base <= table < table + PAGE <=
                                    base + guest_size):
                            raise ValueError(
                                'Phase53 survey table outside owned RAM')
                        return iface.readmem(table, PAGE)
                    kernel_segment = layout['images']['kernelcache'][
                        'segments']['__TEXT_EXEC']
                    sptm_segment = layout['images']['sptm'][
                        'segments']['__TEXT_EXEC']
                    return_leaf = translate(
                        ctx.elr, roots['ttbr0'], roots['ttbr1'],
                        read_survey_unrelated_return_page)
                    gexit_leaf = translate(
                        FC_XNU_PHASE53_GEXIT, roots['ttbr0'], roots['ttbr1'],
                        read_survey_unrelated_return_page)
                    return_live = iface.readmem(return_leaf['pa'], 4)
                    gexit_live = iface.readmem(gexit_leaf['pa'], 4)
                    return_linked = (
                        FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED + ctx.elr -
                        FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY)
                    return_offset = (kernel_segment['fileoff'] +
                                     return_linked - kernel_segment['va'])
                    return_source = sources['kernelcache'][
                        return_offset:return_offset + 4]
                    gexit_offset = (sptm_segment['fileoff'] +
                        FC_XNU_PHASE53_GEXIT_LINKED - sptm_segment['va'])
                    gexit_source = sources['sptm'][
                        gexit_offset:gexit_offset + 4]
                    expected_gexit = struct.pack(
                        '<I', FC_XNU_PHASE53_GEXIT_WORD)
                    aggregate_steps = (state['aggregate_steps'] +
                                       fast_status['steps'])
                    checks.update(
                        return_source_complete=len(return_source) == 4,
                        return_live_source=(len(return_source) == 4 and
                                            return_live == return_source),
                        return_level_three=return_leaf['level'] == 3,
                        return_access_flag=return_leaf['access_flag'],
                        gexit_source=gexit_source == expected_gexit,
                        gexit_live=(gexit_live == expected_gexit and
                                    gexit_live == gexit_source),
                        gexit_level_three=gexit_leaf['level'] == 3,
                        gexit_access_flag=gexit_leaf['access_flag'],
                        filter_outside=(not fast_status['active'] and
                            fast_status['status'] ==
                                FC_VEL2_STEP_FILTER_OUTSIDE),
                        filter_bounded=(0 < fast_status['steps'] <=
                            FC_XNU_PHASE53_FAST_STEPS),
                        filter_last_pc=fast_status['last_pc'] == ctx.elr,
                        filter_previous_pc=fast_status['previous_pc'] ==
                            FC_XNU_PHASE53_GEXIT,
                        filter_segment=(
                            fast_status['first_pc'] == state['segment_start'] and
                            fast_status['expected_first_pc'] ==
                                state['segment_start'] and
                            fast_status['range0_hits'] +
                                fast_status['range1_hits'] ==
                                fast_status['steps']),
                        filter_contract=(
                            fast_status['range0_start'] ==
                                FC_TXM_RUNTIME_TEXT[0] and
                            fast_status['range0_end'] ==
                                FC_TXM_RUNTIME_TEXT[1] and
                            fast_status['range1_start'] ==
                                FC_SPTM_RUNTIME_TEXT[0] and
                            fast_status['range1_end'] ==
                                FC_SPTM_RUNTIME_TEXT[1] and
                            fast_status['terminal_pc'] == state['terminal_pc'] and
                            fast_status['max_steps'] ==
                                FC_XNU_PHASE53_FAST_STEPS),
                        aggregate_budget=(aggregate_steps <=
                            FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS),
                        rearm_budget=(state['rearms'] <
                            FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS))
                    transition.update(
                        return_linked=hex(return_linked),
                        return_pa=hex(return_leaf['pa']),
                        return_source_hex=return_source.hex(),
                        return_live_hex=return_live.hex(),
                        gexit_pa=hex(gexit_leaf['pa']),
                        gexit_source_hex=gexit_source.hex(),
                        gexit_live_hex=gexit_live.hex(),
                        prior_status=fast_status,
                        aggregate_steps=aggregate_steps)
                    if all(checks.values()):
                        enabled_status = txm_sstep_fast_path.enable(
                            FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
                            state['terminal_pc'], FC_XNU_PHASE53_FAST_STEPS,
                            ctx.elr)
                        state.update(
                            range0=FC_XNU_RUNTIME_TEXT,
                            segment_start=ctx.elr,
                            aggregate_steps=aggregate_steps,
                            rearms=state['rearms'] + 1)
                        transition.update(
                            checks=checks, complete=True,
                            enable_status=enabled_status)
                        state['world_transitions'].append(transition)
                        report['xnu_phase53_retype_survey'].update(
                            world_transitions=list(state['world_transitions']),
                            aggregate_steps=aggregate_steps,
                            rearms=state['rearms'])
                        event.update(
                            kind='phase53-survey-unrelated-gexit-return',
                            pc=ctx.elr, esr=int(ctx.esr),
                            spsr=int(ctx.spsr), regs=list(ctx.regs),
                            far=ctx.far, sp=list(ctx.sp), checks=checks)
                        ctx.spsr.SS = 1
                        u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                        iface.writemem(info, ExcInfo.build(ctx))
                        report.pop('stop_reason', None)
                        ret = EXC_RET.HANDLED
                    else:
                        state['active'] = False
                        transition.update(checks=checks, complete=False)
                        report['xnu_phase53_retype_survey'][
                            'unrelated_return_rejection'] = transition
                        report['stop_reason'] = (
                            'phase53-retype-survey-unrelated-return-gate-rejected')
                except Exception as unrelated_return_error:
                    checks['gate_readback'] = False
                    state['active'] = False
                    transition.update(
                        checks=checks, complete=False,
                        error=str(unrelated_return_error))
                    report['xnu_phase53_retype_survey'][
                        'unrelated_return_rejection'] = transition
                    report['stop_reason'] = (
                        'phase53-retype-survey-unrelated-return-gate-rejected')
            elif (phase53_retype_survey_state.get('active') and
                  handoff_state.get('native') and
                  reason == START.EXCEPTION_LOWER and code == EXC.SYNC and
                  int(native_ctx.esr) >> 26 == 0x32 and
                  native_ctx.elr == FC_XNU_PHASE53_GENTER_RETURN and
                  phase53_retype_survey_state.get('stage') ==
                      'seek-genter-return'):
                ctx = native_ctx
                state = phase53_retype_survey_state
                checks = {
                    'exact_spsr': int(ctx.spsr) ==
                        FC_XNU_PHASE53_GENTER_RETURN_SPSR,
                    'wrapper_link': (int(ctx.regs[30]) & ((1 << 40) - 1)) ==
                        (FC_XNU_PHASE53_GENTER_PREVIOUS & ((1 << 40) - 1)),
                }
                record = dict(stage='seek-genter-return', pc=hex(ctx.elr),
                              x30=hex(int(ctx.regs[30])))
                try:
                    fast_status = txm_sstep_fast_path.status()
                    roots = state['roots']
                    def read_survey_return_page(table):
                        if (table & (PAGE - 1) or
                                not base <= table < table + PAGE <=
                                    base + guest_size):
                            raise ValueError(
                                'Phase53 survey table outside owned RAM')
                        return iface.readmem(table, PAGE)
                    kernel_segment = layout['images']['kernelcache'][
                        'segments']['__TEXT_EXEC']
                    sptm_segment = layout['images']['sptm'][
                        'segments']['__TEXT_EXEC']
                    code_specs = (
                        ('selector', FC_XNU_PHASE53_GENTER_PREVIOUS,
                         FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED,
                         FC_XNU_PHASE53_GENTER_PREVIOUS_WORD,
                         kernel_segment, sources['kernelcache']),
                        ('genter', FC_XNU_PHASE53_GENTER,
                         FC_XNU_PHASE53_GENTER_LINKED,
                         FC_XNU_PHASE53_GENTER_WORD,
                         kernel_segment, sources['kernelcache']),
                        ('gexit', FC_XNU_PHASE53_GEXIT,
                         FC_XNU_PHASE53_GEXIT_LINKED,
                         FC_XNU_PHASE53_GEXIT_WORD,
                         sptm_segment, sources['sptm']),
                        ('return', FC_XNU_PHASE53_GENTER_RETURN,
                         FC_XNU_PHASE53_GENTER_RETURN_LINKED,
                         FC_XNU_PHASE53_GENTER_RETURN_WORD,
                         kernel_segment, sources['kernelcache']))
                    code_evidence = {}
                    for name, pc, linked, word, segment, source in code_specs:
                        leaf = translate(pc, roots['ttbr0'], roots['ttbr1'],
                                         read_survey_return_page)
                        live = iface.readmem(leaf['pa'], 4)
                        offset = segment['fileoff'] + linked - segment['va']
                        source_bytes = source[offset:offset + 4]
                        expected = struct.pack('<I', word)
                        checks[name + '_source'] = source_bytes == expected
                        checks[name + '_live'] = (live == expected and
                                                  live == source_bytes)
                        checks[name + '_level_three'] = leaf['level'] == 3
                        checks[name + '_access_flag'] = leaf['access_flag']
                        code_evidence[name] = dict(
                            pa=hex(leaf['pa']), source_hex=source_bytes.hex(),
                            live_hex=live.hex())
                    aggregate_steps = state['aggregate_steps'] + \
                        fast_status['steps']
                    checks.update(
                        filter_stopped=(not fast_status['active'] and
                            ((state['range0'] == FC_TXM_RUNTIME_TEXT and
                              fast_status['status'] ==
                                FC_VEL2_STEP_FILTER_OUTSIDE) or
                             (state['range0'] == FC_XNU_RUNTIME_TEXT and
                              fast_status['status'] ==
                                FC_VEL2_STEP_FILTER_TERMINAL))),
                        filter_last_pc=fast_status['last_pc'] == ctx.elr,
                        filter_previous_pc=fast_status['previous_pc'] ==
                            FC_XNU_PHASE53_GEXIT,
                        filter_segment=(
                            fast_status['first_pc'] == state['segment_start'] and
                            fast_status['expected_first_pc'] ==
                                state['segment_start'] and
                            fast_status['range0_hits'] +
                                fast_status['range1_hits'] ==
                                fast_status['steps']),
                        filter_contract=(
                            fast_status['range0_start'] == state['range0'][0] and
                            fast_status['range0_end'] == state['range0'][1] and
                            fast_status['range1_start'] ==
                                FC_SPTM_RUNTIME_TEXT[0] and
                            fast_status['range1_end'] ==
                                FC_SPTM_RUNTIME_TEXT[1] and
                            fast_status['terminal_pc'] ==
                                FC_XNU_PHASE53_GENTER_RETURN and
                            fast_status['max_steps'] ==
                                FC_XNU_PHASE53_FAST_STEPS),
                        aggregate_budget=(aggregate_steps <=
                            FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS),
                        rearm_budget=(state['rearms'] <
                            FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS))
                    record.update(filter_status=fast_status,
                                  code=code_evidence,
                                  aggregate_steps=aggregate_steps)
                    if all(checks.values()):
                        enabled_status = txm_sstep_fast_path.enable(
                            FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
                            FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB,
                            FC_XNU_PHASE53_FAST_STEPS, ctx.elr)
                        state.update(
                            stage='seek-wrapper-retab',
                            range0=FC_XNU_RUNTIME_TEXT,
                            segment_start=ctx.elr,
                            terminal_pc=FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB,
                            aggregate_steps=aggregate_steps,
                            rearms=state['rearms'] + 1)
                        record.update(checks=checks, complete=True,
                                      enable_status=enabled_status)
                        state['current_call']['genter_return'] = record
                        report['xnu_phase53_retype_survey'].update(
                            current_stage='seek-wrapper-retab',
                            terminal_pc=hex(
                                FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB),
                            aggregate_steps=aggregate_steps,
                            rearms=state['rearms'])
                        event.update(kind='phase53-survey-genter-return',
                                     pc=ctx.elr, checks=checks)
                        ctx.spsr.SS = 1
                        u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                        iface.writemem(info, ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    else:
                        state['active'] = False
                        record.update(checks=checks, complete=False)
                        state.get('current_call', {}).update(
                            genter_return=record)
                        report['xnu_phase53_retype_survey'][
                            'rejection'] = record
                        report['stop_reason'] = (
                            'phase53-retype-survey-genter-return-gate-rejected')
                except Exception as survey_return_error:
                    checks['gate_readback'] = False
                    state['active'] = False
                    record.update(checks=checks, complete=False,
                                  error=str(survey_return_error))
                    state.get('current_call', {}).update(
                        genter_return=record)
                    report['xnu_phase53_retype_survey']['rejection'] = record
                    report['stop_reason'] = (
                        'phase53-retype-survey-genter-return-gate-rejected')
            elif (phase53_allocation_trace_state.get('active') and
                  handoff_state.get('native') and
                  reason == START.EXCEPTION_LOWER and code == EXC.SYNC and
                  int(native_ctx.esr) >> 26 == 0x32 and
                  native_ctx.elr == FC_XNU_PHASE53_GENTER_RETURN):
                ctx = native_ctx
                transition = dict(
                    kind='guarded-service-return', pc=hex(ctx.elr),
                    spsr=hex(int(ctx.spsr)),
                    x30=hex(int(ctx.regs[30])))
                checks = {
                    'exact_spsr': int(ctx.spsr) ==
                        FC_XNU_PHASE53_GENTER_RETURN_SPSR,
                    'wrapper_caller': (int(ctx.regs[30]) & ((1 << 40) - 1)) ==
                        (FC_XNU_PHASE53_GENTER_PREVIOUS & ((1 << 40) - 1)),
                }
                try:
                    fast_status = txm_sstep_fast_path.status()
                    roots = phase53_allocation_trace_state['roots']
                    def read_phase53_guarded_return_page(table):
                        if (table & (PAGE - 1) or
                                not base <= table < table + PAGE <= base + guest_size):
                            raise ValueError(
                                'Phase53 guarded-return table outside owned RAM')
                        return iface.readmem(table, PAGE)
                    selector_leaf = translate(
                        FC_XNU_PHASE53_GENTER_PREVIOUS, roots['ttbr0'],
                        roots['ttbr1'], read_phase53_guarded_return_page)
                    genter_leaf = translate(
                        FC_XNU_PHASE53_GENTER, roots['ttbr0'], roots['ttbr1'],
                        read_phase53_guarded_return_page)
                    gexit_leaf = translate(
                        FC_XNU_PHASE53_GEXIT, roots['ttbr0'], roots['ttbr1'],
                        read_phase53_guarded_return_page)
                    return_leaf = translate(
                        FC_XNU_PHASE53_GENTER_RETURN, roots['ttbr0'],
                        roots['ttbr1'], read_phase53_guarded_return_page)
                    selector_live = iface.readmem(selector_leaf['pa'], 4)
                    genter_live = iface.readmem(genter_leaf['pa'], 4)
                    gexit_live = iface.readmem(gexit_leaf['pa'], 4)
                    return_live = iface.readmem(return_leaf['pa'], 4)
                    sptm_segment = layout['images']['sptm'][
                        'segments']['__TEXT_EXEC']
                    kernel_segment = layout['images']['kernelcache'][
                        'segments']['__TEXT_EXEC']
                    selector_source_offset = (kernel_segment['fileoff'] +
                        FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED -
                        kernel_segment['va'])
                    genter_source_offset = (kernel_segment['fileoff'] +
                        FC_XNU_PHASE53_GENTER_LINKED - kernel_segment['va'])
                    gexit_source_offset = (sptm_segment['fileoff'] +
                        FC_XNU_PHASE53_GEXIT_LINKED - sptm_segment['va'])
                    return_source_offset = (kernel_segment['fileoff'] +
                        FC_XNU_PHASE53_GENTER_RETURN_LINKED -
                        kernel_segment['va'])
                    gexit_source = sources['sptm'][
                        gexit_source_offset:gexit_source_offset + 4]
                    selector_source = sources['kernelcache'][
                        selector_source_offset:selector_source_offset + 4]
                    genter_source = sources['kernelcache'][
                        genter_source_offset:genter_source_offset + 4]
                    return_source = sources['kernelcache'][
                        return_source_offset:return_source_offset + 4]
                    expected_gexit = struct.pack(
                        '<I', FC_XNU_PHASE53_GEXIT_WORD)
                    expected_selector = struct.pack(
                        '<I', FC_XNU_PHASE53_GENTER_PREVIOUS_WORD)
                    expected_genter = struct.pack(
                        '<I', FC_XNU_PHASE53_GENTER_WORD)
                    expected_return = struct.pack(
                        '<I', FC_XNU_PHASE53_GENTER_RETURN_WORD)
                    current_range = phase53_allocation_trace_state['range0']
                    segment_start = phase53_allocation_trace_state[
                        'segment_start']
                    checks.update(
                        gexit_source=gexit_source == expected_gexit,
                        gexit_live=(gexit_live == expected_gexit and
                                    gexit_live == gexit_source),
                        selector_source=selector_source == expected_selector,
                        selector_live=(selector_live == expected_selector and
                                       selector_live == selector_source),
                        genter_source=genter_source == expected_genter,
                        genter_live=(genter_live == expected_genter and
                                     genter_live == genter_source),
                        return_source=return_source == expected_return,
                        return_live=(return_live == expected_return and
                                     return_live == return_source),
                        gexit_level_three=gexit_leaf['level'] == 3,
                        gexit_access_flag=gexit_leaf['access_flag'],
                        selector_level_three=selector_leaf['level'] == 3,
                        selector_access_flag=selector_leaf['access_flag'],
                        genter_level_three=genter_leaf['level'] == 3,
                        genter_access_flag=genter_leaf['access_flag'],
                        return_level_three=return_leaf['level'] == 3,
                        return_access_flag=return_leaf['access_flag'],
                        filter_outside=(not fast_status['active'] and
                            fast_status['status'] ==
                                FC_VEL2_STEP_FILTER_OUTSIDE),
                        filter_bounded=(0 < fast_status['steps'] <=
                            FC_XNU_PHASE53_FAST_STEPS),
                        filter_last_pc=fast_status['last_pc'] == ctx.elr,
                        filter_previous_pc=fast_status['previous_pc'] ==
                            FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS,
                        filter_segment=(
                            fast_status['first_pc'] == segment_start and
                            fast_status['expected_first_pc'] == segment_start and
                            fast_status['range0_hits'] +
                                fast_status['range1_hits'] ==
                                fast_status['steps']),
                        filter_contract=(
                            current_range == FC_TXM_RUNTIME_TEXT and
                            fast_status['range0_start'] == current_range[0] and
                            fast_status['range0_end'] == current_range[1] and
                            fast_status['range1_start'] ==
                                FC_SPTM_RUNTIME_TEXT[0] and
                            fast_status['range1_end'] ==
                                FC_SPTM_RUNTIME_TEXT[1] and
                            fast_status['terminal_pc'] ==
                                phase53_allocation_trace_state['terminal_pc'] and
                            fast_status['max_steps'] ==
                                FC_XNU_PHASE53_FAST_STEPS))
                    transition.update(
                        gexit_pa=hex(gexit_leaf['pa']),
                        gexit_source_hex=gexit_source.hex(),
                        gexit_live_hex=gexit_live.hex(),
                        selector_pa=hex(selector_leaf['pa']),
                        selector_source_hex=selector_source.hex(),
                        selector_live_hex=selector_live.hex(),
                        genter_pa=hex(genter_leaf['pa']),
                        genter_source_hex=genter_source.hex(),
                        genter_live_hex=genter_live.hex(),
                        return_pa=hex(return_leaf['pa']),
                        return_source_hex=return_source.hex(),
                        return_live_hex=return_live.hex(),
                        prior_status=fast_status)
                    if all(checks.values()):
                        enabled_status = txm_sstep_fast_path.enable(
                            FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
                            phase53_allocation_trace_state['terminal_pc'],
                            FC_XNU_PHASE53_FAST_STEPS, ctx.elr)
                        phase53_allocation_trace_state.update(
                            range0=FC_XNU_RUNTIME_TEXT,
                            segment_start=ctx.elr)
                        transition.update(
                            enable_status=enabled_status, checks=checks,
                            complete=True)
                        phase53_allocation_trace_state[
                            'world_transitions'].append(transition)
                        report['xnu_phase53_allocation_trace'][
                            'world_transitions'] = list(
                                phase53_allocation_trace_state[
                                    'world_transitions'])
                        event.update(
                            kind='phase53-guarded-service-return', pc=ctx.elr,
                            esr=int(ctx.esr), spsr=int(ctx.spsr),
                            regs=list(ctx.regs), far=ctx.far, sp=list(ctx.sp),
                            checks=checks)
                        ctx.spsr.SS = 1
                        u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                        iface.writemem(info, ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    else:
                        transition.update(checks=checks, complete=False)
                        phase53_allocation_trace_state['active'] = False
                        report['xnu_phase53_allocation_trace'][
                            'world_transition_rejection'] = transition
                        report['stop_reason'] = (
                            'phase53-guarded-service-return-gate-rejected')
                except Exception as transition_error:
                    checks['gate_readback'] = False
                    transition.update(
                        checks=checks, error=str(transition_error),
                        complete=False)
                    phase53_allocation_trace_state['active'] = False
                    report['xnu_phase53_allocation_trace'][
                        'world_transition_rejection'] = transition
                    report['stop_reason'] = (
                        'phase53-guarded-service-return-gate-rejected')
            elif (phase53_retype_survey_state.get('active') and
                  reason == START.EXCEPTION_LOWER and code == EXC.SYNC and
                  int(native_ctx.esr if handoff_state.get('native') else
                      iface.readstruct(info, ExcInfo).esr) >> 26 == 0x32):
                ctx = (native_ctx if handoff_state.get('native') else
                       iface.readstruct(info, ExcInfo))
                state = phase53_retype_survey_state
                stage_name = state['stage']
                specs = {
                    'seek-entry': (
                        FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY,
                        FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED,
                        FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_WORD),
                    'seek-genter': (
                        FC_XNU_PHASE53_GENTER,
                        FC_XNU_PHASE53_GENTER_LINKED,
                        FC_XNU_PHASE53_GENTER_WORD),
                    'seek-wrapper-retab': (
                        FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB,
                        FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED,
                        FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_WORD),
                }
                expected_pc, linked_pc, expected_word = specs[stage_name]
                checks = {'expected_pc': ctx.elr == expected_pc}
                stage_record = dict(stage=stage_name, pc=hex(ctx.elr))
                try:
                    roots = state['roots']
                    def read_survey_page(table):
                        if (table & (PAGE - 1) or
                                not base <= table < table + PAGE <=
                                    base + guest_size):
                            raise ValueError(
                                'Phase53 survey table outside owned RAM')
                        return iface.readmem(table, PAGE)
                    def capture_fte_neighborhood(physical_address):
                        pointer_leaf = translate(
                            FC_SPTM_PHASE53_FTE_BASE_POINTER,
                            roots['ttbr0'], roots['ttbr1'], read_survey_page)
                        pointer_raw = iface.readmem(pointer_leaf['pa'], 8)
                        fte_base = struct.unpack('<Q', pointer_raw)[0]
                        center_va = fte_base + (
                            ((physical_address - base) >> 10) &
                            0x3ffffffffffff0)
                        records = []
                        for delta in (-16, 0, 16):
                            va = center_va + delta
                            leaf = translate(va, roots['ttbr0'], roots['ttbr1'],
                                             read_survey_page)
                            raw = iface.readmem(leaf['pa'], 16)
                            records.append(dict(
                                delta=delta, va=hex(va), pa=hex(leaf['pa']),
                                hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest(),
                                in_flight_ops=(struct.unpack('<H', raw[:2])[0]
                                    if len(raw) == 16 else None),
                                type=(raw[2] if len(raw) == 16 else None),
                                complete=len(raw) == 16,
                                level_three=leaf['level'] == 3,
                                access_flag=leaf['access_flag']))
                        return dict(
                            base_pointer_va=hex(
                                FC_SPTM_PHASE53_FTE_BASE_POINTER),
                            base_pointer_pa=hex(pointer_leaf['pa']),
                            base_pointer_hex=pointer_raw.hex(),
                            pointer_level_three=pointer_leaf['level'] == 3,
                            pointer_access_flag=pointer_leaf['access_flag'],
                            fte_base=hex(fte_base), center_va=hex(center_va),
                            records=records)
                    fast_status = txm_sstep_fast_path.status()
                    code_leaf = translate(ctx.elr, roots['ttbr0'],
                                          roots['ttbr1'], read_survey_page)
                    code_live = iface.readmem(code_leaf['pa'], 4)
                    kernel_segment = layout['images']['kernelcache'][
                        'segments']['__TEXT_EXEC']
                    source_offset = (kernel_segment['fileoff'] + linked_pc -
                                     kernel_segment['va'])
                    source_word = sources['kernelcache'][
                        source_offset:source_offset + 4]
                    expected_code = struct.pack('<I', expected_word)
                    aggregate_steps = (state['aggregate_steps'] +
                                       fast_status['steps'])
                    checks.update(
                        source_word=source_word == expected_code,
                        live_word=(code_live == expected_code and
                                   code_live == source_word),
                        level_three=code_leaf['level'] == 3,
                        access_flag=code_leaf['access_flag'],
                        filter_terminal=(not fast_status['active'] and
                            fast_status['status'] ==
                                FC_VEL2_STEP_FILTER_TERMINAL and
                            fast_status['last_pc'] == expected_pc),
                        filter_bounded=(0 < fast_status['steps'] <=
                            FC_XNU_PHASE53_FAST_STEPS),
                        filter_contract=(
                            fast_status['first_pc'] == state['segment_start'] and
                            fast_status['expected_first_pc'] ==
                                state['segment_start'] and
                            fast_status['range0_hits'] +
                                fast_status['range1_hits'] ==
                                fast_status['steps'] and
                            fast_status['range0_start'] == state['range0'][0] and
                            fast_status['range0_end'] == state['range0'][1] and
                            fast_status['range1_start'] ==
                                FC_SPTM_RUNTIME_TEXT[0] and
                            fast_status['range1_end'] ==
                                FC_SPTM_RUNTIME_TEXT[1] and
                            fast_status['terminal_pc'] == expected_pc and
                            fast_status['max_steps'] ==
                                FC_XNU_PHASE53_FAST_STEPS),
                        aggregate_budget=(aggregate_steps <=
                            FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS))
                    stage_record.update(
                        source_hex=source_word.hex(), live_hex=code_live.hex(),
                        pa=hex(code_leaf['pa']), filter_status=fast_status,
                        aggregate_steps=aggregate_steps)
                    next_stage = next_pc = None
                    if stage_name == 'seek-entry':
                        args = tuple(int(ctx.regs[index]) for index in range(4))
                        pac_mask = (1 << 40) - 1
                        caller_return = ((FC_XNU_RUNTIME_TEXT[0] & ~pac_mask) |
                                         (int(ctx.regs[30]) & pac_mask))
                        caller_callsite = caller_return - 4
                        caller_linked = (
                            FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED +
                            caller_callsite -
                            FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY)
                        caller_leaf = translate(
                            caller_callsite, roots['ttbr0'], roots['ttbr1'],
                            read_survey_page)
                        caller_live = iface.readmem(caller_leaf['pa'], 4)
                        caller_offset = (kernel_segment['fileoff'] +
                                         caller_linked - kernel_segment['va'])
                        caller_source = sources['kernelcache'][
                            caller_offset:caller_offset + 4]
                        caller_word = (struct.unpack('<I', caller_source)[0]
                                       if len(caller_source) == 4 else 0)
                        immediate = caller_word & 0x3ffffff
                        if immediate & (1 << 25):
                            immediate -= 1 << 26
                        caller_target = caller_callsite + (immediate << 2)
                        if (args[0] == 0 or args[0] & (PAGE - 1) or
                                not base <= args[0] < base + guest_size):
                            raise ValueError(
                                'Phase53 survey physical address is not an owned page')
                        if args[1] > 0xff or args[2] > 0xff:
                            raise ValueError(
                                'Phase53 survey frame type is not u8')
                        fte_before = capture_fte_neighborhood(args[0])
                        center = fte_before['records'][1]
                        checks.update(
                            pa_aligned=args[0] != 0 and
                                args[0] & (PAGE - 1) == 0,
                            pa_owned=base <= args[0] < base + guest_size,
                            type_from_u8=args[1] <= 0xff,
                            type_to_u8=args[2] <= 0xff,
                            caller_in_xnu=FC_XNU_RUNTIME_TEXT[0] <=
                                caller_callsite < FC_XNU_RUNTIME_TEXT[1],
                            caller_source_bl=(caller_word & 0xfc000000) ==
                                0x94000000,
                            caller_live=caller_live == caller_source,
                            caller_targets_wrapper=caller_target ==
                                FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY,
                            caller_level_three=caller_leaf['level'] == 3,
                            caller_access_flag=caller_leaf['access_flag'],
                            fte_pointer_level_three=
                                fte_before['pointer_level_three'],
                            fte_pointer_access_flag=
                                fte_before['pointer_access_flag'],
                            fte_records_complete=all(item['complete'] for item in
                                fte_before['records']),
                            fte_records_level_three=all(
                                item['level_three'] for item in
                                fte_before['records']),
                            fte_records_access_flag=all(
                                item['access_flag'] for item in
                                fte_before['records']),
                            fte_center_unlocked=center['in_flight_ops'] == 0,
                            fte_center_type=center['type'] == (args[1] & 0xff),
                            rearm_budget=state['rearms'] <
                                FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS)
                        current_call = dict(
                            index=state['completed_calls'],
                            args=[hex(value) for value in args],
                            pa=hex(args[0]), type_from=hex(args[1] & 0xffffffff),
                            type_to=hex(args[2] & 0xffffffff),
                            flags=hex(args[3]), x30=hex(int(ctx.regs[30])),
                            caller_return=hex(caller_return),
                            caller_callsite=hex(caller_callsite),
                            caller_linked=hex(caller_linked),
                            caller_source_hex=caller_source.hex(),
                            caller_live_hex=caller_live.hex(),
                            frame_table_before=fte_before)
                        state['current_call'] = current_call
                        next_stage = 'seek-genter'
                        next_pc = FC_XNU_PHASE53_GENTER
                    elif stage_name == 'seek-genter':
                        current_call = state['current_call']
                        expected_args = tuple(int(value, 0) for value in
                                              current_call['args'])
                        selector_leaf = translate(
                            FC_XNU_PHASE53_GENTER_PREVIOUS, roots['ttbr0'],
                            roots['ttbr1'], read_survey_page)
                        selector_live = iface.readmem(selector_leaf['pa'], 4)
                        selector_offset = (kernel_segment['fileoff'] +
                            FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED -
                            kernel_segment['va'])
                        selector_source = sources['kernelcache'][
                            selector_offset:selector_offset + 4]
                        expected_selector = struct.pack(
                            '<I', FC_XNU_PHASE53_GENTER_PREVIOUS_WORD)
                        checks.update(
                            selector_source=selector_source == expected_selector,
                            selector_live=(selector_live == expected_selector and
                                           selector_live == selector_source),
                            selector_level_three=selector_leaf['level'] == 3,
                            selector_access_flag=selector_leaf['access_flag'],
                            genter_selector=int(ctx.regs[16]) == 1,
                            args_unchanged=tuple(int(ctx.regs[index]) for index in
                                range(4)) == expected_args,
                            filter_previous_pc=fast_status['previous_pc'] ==
                                FC_XNU_PHASE53_GENTER_PREVIOUS,
                            rearm_budget=state['rearms'] <
                                FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS)
                        current_call['genter'] = dict(
                            selector_source_hex=selector_source.hex(),
                            selector_live_hex=selector_live.hex())
                        next_stage = 'seek-genter-return'
                        next_pc = FC_XNU_PHASE53_GENTER_RETURN
                    elif stage_name == 'seek-wrapper-retab':
                        current_call = state['current_call']
                        args = tuple(int(value, 0) for value in
                                     current_call['args'])
                        fte_after = capture_fte_neighborhood(args[0])
                        center = fte_after['records'][1]
                        before = current_call['frame_table_before']
                        checks.update(
                            filter_previous_pc=fast_status['previous_pc'] ==
                                FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_PREVIOUS,
                            restored_caller=(int(ctx.regs[30]) &
                                ((1 << 40) - 1)) ==
                                (int(current_call['x30'], 0) &
                                 ((1 << 40) - 1)),
                            fte_base_stable=fte_after['fte_base'] ==
                                before['fte_base'],
                            fte_center_stable=fte_after['center_va'] ==
                                before['center_va'],
                            fte_pointer_level_three=
                                fte_after['pointer_level_three'],
                            fte_pointer_access_flag=
                                fte_after['pointer_access_flag'],
                            fte_records_complete=all(item['complete'] for item in
                                fte_after['records']),
                            fte_records_level_three=all(
                                item['level_three'] for item in
                                fte_after['records']),
                            fte_records_access_flag=all(
                                item['access_flag'] for item in
                                fte_after['records']),
                            fte_center_unlocked=center['in_flight_ops'] == 0,
                            fte_center_type=center['type'] == (args[2] & 0xff))
                        current_call['frame_table_after'] = fte_after
                    stage_record['checks'] = checks
                    stage_record['complete'] = all(checks.values())
                    if stage_name == 'seek-entry':
                        state['calls'].append(state['current_call'])
                    state['current_call'][stage_name] = stage_record
                    report['xnu_phase53_retype_survey']['calls'] = list(
                        state['calls'])
                    if stage_record['complete'] and next_stage is not None:
                        enabled_status = txm_sstep_fast_path.enable(
                            FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT, next_pc,
                            FC_XNU_PHASE53_FAST_STEPS, ctx.elr)
                        state.update(
                            stage=next_stage, range0=FC_XNU_RUNTIME_TEXT,
                            segment_start=ctx.elr, terminal_pc=next_pc,
                            aggregate_steps=aggregate_steps,
                            rearms=state['rearms'] + 1)
                        stage_record['next_enable_status'] = enabled_status
                        report['xnu_phase53_retype_survey'].update(
                            current_stage=next_stage, terminal_pc=hex(next_pc),
                            aggregate_steps=aggregate_steps,
                            rearms=state['rearms'])
                        event.update(kind='phase53-survey-' + stage_name,
                                     pc=ctx.elr, checks=checks)
                        ctx.spsr.SS = 1
                        u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                        iface.writemem(info, ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    elif stage_record['complete']:
                        state['aggregate_steps'] = aggregate_steps
                        state['completed_calls'] += 1
                        target_type = int(state['current_call']['type_to'], 0)
                        target_found = target_type in \
                            FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES
                        primary_target = (
                            int(state['current_call']['type_from'], 0) == 0xb and
                            target_type == 0x14)
                        state['current_call'].update(
                            complete=True, target_found=target_found,
                            primary_target=primary_target)
                        report['xnu_phase53_retype_survey'].update(
                            completed_calls=state['completed_calls'],
                            aggregate_steps=aggregate_steps,
                            target_found=target_found,
                            primary_target_found=primary_target,
                            calls=list(state['calls']))
                        state['active'] = False
                        if target_found:
                            report['xnu_phase53_retype_survey']['complete'] = True
                            report['stop_reason'] = (
                                'phase53-retype-survey-target-reached')
                        elif state['completed_calls'] >= state['limit']:
                            report['xnu_phase53_retype_survey'][
                                'limit_reached'] = True
                            report['stop_reason'] = (
                                'phase53-retype-survey-call-limit-reached')
                        elif state['rearms'] >= \
                                FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS:
                            report['stop_reason'] = (
                                'phase53-retype-survey-rearm-limit-reached')
                        else:
                            enabled_status = txm_sstep_fast_path.enable(
                                FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
                                FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY,
                                FC_XNU_PHASE53_FAST_STEPS, ctx.elr)
                            state.update(
                                active=True, stage='seek-entry',
                                range0=FC_XNU_RUNTIME_TEXT,
                                segment_start=ctx.elr,
                                terminal_pc=
                                    FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY,
                                rearms=state['rearms'] + 1)
                            stage_record['next_enable_status'] = enabled_status
                            report['xnu_phase53_retype_survey'].update(
                                current_stage='seek-entry',
                                terminal_pc=hex(
                                    FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY),
                                rearms=state['rearms'])
                            event.update(
                                kind='phase53-survey-next-call', pc=ctx.elr,
                                checks=checks)
                            ctx.spsr.SS = 1
                            u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                            iface.writemem(info, ExcInfo.build(ctx))
                            report.pop('stop_reason', None)
                            ret = EXC_RET.HANDLED
                    else:
                        state['active'] = False
                        report['xnu_phase53_retype_survey'][
                            'rejection'] = stage_record
                        report['stop_reason'] = (
                            'phase53-retype-survey-' + stage_name +
                            '-gate-rejected')
                except Exception as survey_gate_error:
                    checks['gate_readback'] = False
                    stage_record.update(checks=checks, complete=False,
                                        error=str(survey_gate_error))
                    state['active'] = False
                    report['xnu_phase53_retype_survey'][
                        'rejection'] = stage_record
                    report['stop_reason'] = (
                        'phase53-retype-survey-' + stage_name +
                        '-gate-rejected')
            elif (phase53_allocation_trace_state.get('active') and
                  reason == START.EXCEPTION_LOWER and code == EXC.SYNC and
                  int(native_ctx.esr if handoff_state.get('native') else
                      iface.readstruct(info, ExcInfo).esr) >> 26 == 0x32):
                ctx = native_ctx if handoff_state.get('native') else iface.readstruct(
                    info, ExcInfo)
                stage_name = phase53_allocation_trace_state.get(
                    'stage', 'allocation-call')
                stage_specs = {
                    'allocation-call': (
                        FC_XNU_PHASE53_ALLOC_CALL,
                        FC_XNU_PHASE53_ALLOC_CALL_LINKED,
                        FC_XNU_PHASE53_ALLOC_CALL_WORD,
                        'internal-allocation-call',
                        FC_XNU_PHASE53_ALLOC_INTERNAL_CALL),
                    'internal-allocation-call': (
                        FC_XNU_PHASE53_ALLOC_INTERNAL_CALL,
                        FC_XNU_PHASE53_ALLOC_INTERNAL_CALL_LINKED,
                        FC_XNU_PHASE53_ALLOC_INTERNAL_CALL_WORD,
                        'allocation-return', FC_XNU_PHASE53_ALLOC_RETURN),
                    'allocation-return': (
                        FC_XNU_PHASE53_ALLOC_RETURN,
                        FC_XNU_PHASE53_ALLOC_RETURN_LINKED,
                        FC_XNU_PHASE53_ALLOC_RETURN_WORD,
                        'post-ubfiz', FC_XNU_PHASE53_POST_UBFIZ),
                    'post-ubfiz': (
                        FC_XNU_PHASE53_POST_UBFIZ,
                        FC_XNU_PHASE53_POST_UBFIZ_LINKED,
                        FC_XNU_PHASE53_POST_UBFIZ_WORD,
                        'retype-call', FC_XNU_PHASE53_RETYPE_CALL),
                    'retype-call': (
                        FC_XNU_PHASE53_RETYPE_CALL,
                        FC_XNU_PHASE53_RETYPE_CALL_LINKED,
                        FC_XNU_PHASE53_RETYPE_CALL_WORD,
                        'genter', FC_XNU_PHASE53_GENTER),
                    'genter': (
                        FC_XNU_PHASE53_GENTER,
                        FC_XNU_PHASE53_GENTER_LINKED,
                        FC_XNU_PHASE53_GENTER_WORD,
                        'retype-return', FC_XNU_PHASE53_RETYPE_RETURN),
                    'retype-return': (
                        FC_XNU_PHASE53_RETYPE_RETURN,
                        FC_XNU_PHASE53_RETYPE_RETURN_LINKED,
                        FC_XNU_PHASE53_RETYPE_RETURN_WORD,
                        None, None),
                }
                expected_pc, linked_pc, expected_word, next_stage, next_pc = (
                    stage_specs[stage_name])
                stage_record = dict(
                    stage=stage_name,
                    pc=hex(ctx.elr), esr=hex(int(ctx.esr)),
                    spsr=hex(int(ctx.spsr)), sp_el0=hex(int(ctx.sp[0])),
                    x0=hex(int(ctx.regs[0])), x1=hex(int(ctx.regs[1])),
                    x2=hex(int(ctx.regs[2])), x3=hex(int(ctx.regs[3])),
                    x16=hex(int(ctx.regs[16])), x21=hex(int(ctx.regs[21])),
                    x30=hex(int(ctx.regs[30])))
                checks = {
                    'lower_sync': reason == START.EXCEPTION_LOWER and code == EXC.SYNC,
                    'software_step': int(ctx.esr) >> 26 == 0x32,
                    'exact_pc': ctx.elr == expected_pc,
                }
                try:
                    fast_status = txm_sstep_fast_path.status()
                    roots = phase53_allocation_trace_state['roots']
                    def read_phase53_page(table):
                        if (table & (PAGE - 1) or
                                not base <= table < table + PAGE <= base + guest_size):
                            raise ValueError('Phase53 table outside owned RAM')
                        return iface.readmem(table, PAGE)
                    code_leaf = translate(ctx.elr, roots['ttbr0'], roots['ttbr1'],
                                          read_phase53_page)
                    code_live = iface.readmem(code_leaf['pa'], 4)
                    kernel_segment = layout['images']['kernelcache'][
                        'segments']['__TEXT_EXEC']
                    code_source_offset = (kernel_segment['fileoff'] + linked_pc -
                                          kernel_segment['va'])
                    code_source = sources['kernelcache'][
                        code_source_offset:code_source_offset + 4]
                    actual_linked_pc = linked_pc + ctx.elr - expected_pc
                    actual_source_offset = (kernel_segment['fileoff'] +
                        actual_linked_pc - kernel_segment['va'])
                    actual_source = sources['kernelcache'][
                        actual_source_offset:actual_source_offset + 4]
                    expected_code = struct.pack('<I', expected_word)
                    segment_start = phase53_allocation_trace_state[
                        'segment_start']
                    current_range = phase53_allocation_trace_state['range0']
                    checks.update(
                        source_word=code_source == expected_code,
                        live_word=(code_live == expected_code and
                                   code_live == code_source),
                        level_three=code_leaf['level'] == 3,
                        access_flag=code_leaf['access_flag'],
                        filter_terminal=(not fast_status['active'] and
                            fast_status['status'] == FC_VEL2_STEP_FILTER_TERMINAL and
                            fast_status['last_pc'] == expected_pc),
                        filter_bounded=(0 < fast_status['steps'] <=
                            FC_XNU_PHASE53_FAST_STEPS),
                        filter_contract=(
                            fast_status['first_pc'] == segment_start and
                            fast_status['expected_first_pc'] == segment_start and
                            fast_status['range0_hits'] +
                                fast_status['range1_hits'] ==
                                fast_status['steps'] and
                            fast_status['range0_start'] == current_range[0] and
                            fast_status['range0_end'] == current_range[1] and
                            current_range == FC_XNU_RUNTIME_TEXT and
                            fast_status['range1_start'] == FC_SPTM_RUNTIME_TEXT[0] and
                            fast_status['range1_end'] == FC_SPTM_RUNTIME_TEXT[1] and
                            fast_status['terminal_pc'] == expected_pc and
                            fast_status['max_steps'] ==
                                FC_XNU_PHASE53_FAST_STEPS))
                    if stage_name == 'post-ubfiz':
                        allocated_pa = int(ctx.regs[21])
                        checks.update(
                            ubfiz_previous=fast_status['previous_pc'] ==
                                FC_XNU_PHASE53_UBFIZ_PC,
                            allocated_pa_aligned=allocated_pa != 0 and
                                allocated_pa & (PAGE - 1) == 0,
                            allocated_pa_owned=base <= allocated_pa <
                                base + guest_size)
                        phase53_allocation_trace_state.update(
                            allocated_pa=allocated_pa,
                            fte_capture_available=False)
                        try:
                            pointer_leaf = translate(
                                FC_SPTM_PHASE53_FTE_BASE_POINTER,
                                roots['ttbr0'], roots['ttbr1'],
                                read_phase53_page)
                            pointer_raw = iface.readmem(pointer_leaf['pa'], 8)
                            fte_base = struct.unpack('<Q', pointer_raw)[0]
                            fte_va = fte_base + (((allocated_pa - base) >> 10) &
                                                  0x3ffffffffffff0)
                            fte_leaf = translate(
                                fte_va, roots['ttbr0'], roots['ttbr1'],
                                read_phase53_page)
                            fte_before = iface.readmem(fte_leaf['pa'], 16)
                            capture_checks = dict(
                                pointer_level_three=pointer_leaf['level'] == 3,
                                pointer_access_flag=pointer_leaf['access_flag'],
                                fte_level_three=fte_leaf['level'] == 3,
                                fte_access_flag=fte_leaf['access_flag'],
                                record_complete=len(fte_before) == 16,
                                record_unlocked=(len(fte_before) == 16 and
                                                 fte_before[:2] == b'\0\0'),
                                record_type_from=(len(fte_before) == 16 and
                                                  fte_before[2] == 0xb))
                            capture_complete = all(capture_checks.values())
                            phase53_allocation_trace_state.update(
                                fte_capture_available=capture_complete,
                                fte_base=fte_base, fte_va=fte_va,
                                fte_pa=fte_leaf['pa'], fte_before=fte_before)
                            stage_record['frame_table_before'] = dict(
                                captured=capture_complete,
                                allocated_pa=hex(allocated_pa),
                                base_pointer_va=hex(
                                    FC_SPTM_PHASE53_FTE_BASE_POINTER),
                                base_pointer_pa=hex(pointer_leaf['pa']),
                                base_pointer_hex=pointer_raw.hex(),
                                fte_base=hex(fte_base), fte_va=hex(fte_va),
                                fte_pa=hex(fte_leaf['pa']),
                                hex=fte_before.hex(),
                                sha256=hashlib.sha256(fte_before).hexdigest(),
                                checks=capture_checks)
                        except Exception as frame_table_capture_error:
                            stage_record['frame_table_before'] = dict(
                                captured=False,
                                allocated_pa=hex(allocated_pa),
                                base_pointer_va=hex(
                                    FC_SPTM_PHASE53_FTE_BASE_POINTER),
                                error=str(frame_table_capture_error))
                    elif stage_name == 'retype-call':
                        checks.update(
                            retype_pa=int(ctx.regs[0]) ==
                                phase53_allocation_trace_state['allocated_pa'],
                            retype_from=int(ctx.regs[1]) & 0xffffffff == 0xb,
                            retype_to=int(ctx.regs[2]) & 0xffffffff == 0x29,
                            retype_flags=int(ctx.regs[3]) == 0)
                    elif stage_name == 'genter':
                        checks.update(
                            genter_selector=int(ctx.regs[16]) == 1,
                            genter_previous=fast_status['previous_pc'] ==
                                FC_XNU_PHASE53_GENTER_PREVIOUS)
                    elif stage_name == 'allocation-return':
                        phase53_allocation_trace_state['allocator_result'] = int(
                            ctx.regs[0])
                        stage_record['allocator_result'] = hex(int(ctx.regs[0]))
                    elif stage_name == 'retype-return':
                        allocated_pa = phase53_allocation_trace_state[
                            'allocated_pa']
                        checks['allocated_pa_stable'] = int(ctx.regs[21]) == allocated_pa
                        if phase53_allocation_trace_state.get(
                                'fte_capture_available'):
                            checks['retype_record_pointer'] = (
                                int(ctx.regs[0]) ==
                                phase53_allocation_trace_state['fte_va'])
                            pointer_leaf = translate(
                                FC_SPTM_PHASE53_FTE_BASE_POINTER,
                                roots['ttbr0'], roots['ttbr1'],
                                read_phase53_page)
                            pointer_raw = iface.readmem(pointer_leaf['pa'], 8)
                            fte_base = struct.unpack('<Q', pointer_raw)[0]
                            fte_va = fte_base + (((allocated_pa - base) >> 10) &
                                                  0x3ffffffffffff0)
                            fte_leaf = translate(
                                fte_va, roots['ttbr0'], roots['ttbr1'],
                                read_phase53_page)
                            fte_after = iface.readmem(fte_leaf['pa'], 16)
                            fte_before = phase53_allocation_trace_state[
                                'fte_before']
                            changed = [dict(
                                offset=i, before=fte_before[i],
                                after=fte_after[i],
                                xor=fte_before[i] ^ fte_after[i])
                                for i in range(16)
                                if fte_before[i] != fte_after[i]]
                            checks.update(
                                fte_base_stable=fte_base ==
                                    phase53_allocation_trace_state['fte_base'],
                                fte_va_stable=fte_va ==
                                    phase53_allocation_trace_state['fte_va'],
                                fte_pa_stable=fte_leaf['pa'] ==
                                    phase53_allocation_trace_state['fte_pa'],
                                fte_record_complete=len(fte_after) == 16,
                                fte_record_unlocked=fte_after[:2] == b'\0\0',
                                fte_type_from=fte_before[2] == 0xb,
                                fte_type_to=fte_after[2] == 0x29)
                            stage_record['frame_table_after'] = dict(
                                captured=True,
                                base_pointer_hex=pointer_raw.hex(),
                                fte_base=hex(fte_base), fte_va=hex(fte_va),
                                fte_pa=hex(fte_leaf['pa']),
                                hex=fte_after.hex(),
                                sha256=hashlib.sha256(
                                    fte_after).hexdigest(),
                                changed=bool(changed), changed_bytes=changed,
                                type_before=hex(fte_before[2]),
                                type_after=hex(fte_after[2]),
                                retype_result=hex(int(ctx.regs[0])),
                                retype_status=hex(int(ctx.regs[0])))
                        else:
                            stage_record['frame_table_after'] = dict(
                                captured=False,
                                reason='pre-retype snapshot unavailable',
                                retype_result=hex(int(ctx.regs[0])),
                                retype_status=hex(int(ctx.regs[0])))
                    stage_record.update(
                        pa=hex(code_leaf['pa']),
                        expected_pc=hex(expected_pc),
                        source_pc=hex(expected_pc),
                        source_hex=code_source.hex(),
                        actual_source_pc=hex(ctx.elr),
                        actual_source_hex=actual_source.hex(),
                        live_hex=code_live.hex(), filter_status=fast_status)
                    if stage_name == 'allocation-call':
                        stage_record['target_pc'] = hex(
                            FC_XNU_PHASE53_ALLOC_ENTRY)
                except Exception as allocation_gate_error:
                    checks['gate_readback'] = False
                    stage_record['error'] = str(allocation_gate_error)
                stage_record['checks'] = checks
                stage_record['complete'] = all(checks.values())
                report['xnu_phase53_allocation_trace'].setdefault(
                    'stages', []).append(stage_record)
                event.update(kind='phase53-' + stage_name, pc=ctx.elr,
                             esr=int(ctx.esr), spsr=int(ctx.spsr),
                             regs=list(ctx.regs), far=ctx.far, sp=list(ctx.sp),
                             checks=checks)
                if stage_record['complete'] and next_stage is not None:
                    try:
                        next_first_pc = ctx.elr
                        enabled_status = txm_sstep_fast_path.enable(
                            FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT, next_pc,
                            FC_XNU_PHASE53_FAST_STEPS, next_first_pc)
                        phase53_allocation_trace_state.update(
                            stage=next_stage, range0=FC_XNU_RUNTIME_TEXT,
                            segment_start=next_first_pc, terminal_pc=next_pc)
                        stage_record['next_enable_status'] = enabled_status
                        report['xnu_phase53_allocation_trace'].update(
                            current_stage=next_stage, terminal_pc=hex(next_pc))
                        ctx.spsr.SS = 1
                        u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                        iface.writemem(info, ExcInfo.build(ctx))
                        report.pop('stop_reason', None)
                        ret = EXC_RET.HANDLED
                    except Exception as next_enable_error:
                        phase53_allocation_trace_state['active'] = False
                        stage_record['next_enable_error'] = str(next_enable_error)
                        report['stop_reason'] = ('phase53-' + stage_name +
                                                 '-enable-failed')
                else:
                    phase53_allocation_trace_state['active'] = False
                    if stage_record['complete']:
                        frame_table_after = stage_record.get(
                            'frame_table_after', {})
                        report['xnu_phase53_allocation_trace'].update(
                            complete=True, sequence_complete=True,
                            frame_table_evidence=bool(
                                frame_table_after.get('captured')),
                            frame_table_mutation_observed=(
                                frame_table_after.get('changed')
                                if frame_table_after.get('captured') else None),
                            retype_result=hex(int(ctx.regs[0])),
                            retype_status=hex(int(ctx.regs[0])))
                        if getattr(a, 'xnu_phase53_retype_survey', False):
                            try:
                                survey_enable = txm_sstep_fast_path.enable(
                                    FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
                                    FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY,
                                    FC_XNU_PHASE53_FAST_STEPS, ctx.elr)
                                phase53_retype_survey_state.update(
                                    active=True,
                                    roots=phase53_allocation_trace_state['roots'],
                                    range0=FC_XNU_RUNTIME_TEXT,
                                    segment_start=ctx.elr,
                                    terminal_pc=
                                        FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY,
                                    stage='seek-entry', completed_calls=0,
                                    aggregate_steps=0, rearms=1, calls=[],
                                    limit=a.xnu_phase53_retype_survey_limit,
                                    world_transitions=[])
                                report['xnu_phase53_retype_survey'] = dict(
                                    requested=True, activated=True,
                                    current_stage='seek-entry',
                                    terminal_pc=hex(
                                        FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY),
                                    expected_first_pc=hex(ctx.elr),
                                    call_limit=a.xnu_phase53_retype_survey_limit,
                                    aggregate_step_limit=
                                        FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS,
                                    rearm_limit=
                                        FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS,
                                    target_types=[hex(value) for value in
                                        FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES],
                                    primary_target='0xb->0x14',
                                    enable_status=survey_enable, calls=[])
                                stage_record['survey_enable_status'] = (
                                    survey_enable)
                                event['kind'] = 'phase53-retype-survey-start'
                                ctx.spsr.SS = 1
                                u.msr(MDSCR_EL1,
                                      u.mrs(MDSCR_EL1) | 1)
                                iface.writemem(info, ExcInfo.build(ctx))
                                report.pop('stop_reason', None)
                                ret = EXC_RET.HANDLED
                            except Exception as survey_enable_error:
                                phase53_retype_survey_state['active'] = False
                                report['xnu_phase53_retype_survey'] = dict(
                                    requested=True, activated=False,
                                    error=str(survey_enable_error))
                                report['stop_reason'] = (
                                    'phase53-retype-survey-enable-failed')
                        else:
                            report['stop_reason'] = (
                                'phase53-retype-return-reached')
                    else:
                        report['stop_reason'] = ('phase53-' + stage_name +
                                                 '-gate-rejected')
            elif (txm_validator_trace_state.get('active') and
                  txm_validator_trace_state.get('phase') == 'completion' and
                  txm_validator_trace_state.get('fast_path_armed') and
                  handoff_state.get('native') and
                  reason == START.EXCEPTION_LOWER and code == EXC.SYNC and
                  int(native_ctx.esr) == FC_XNU_TXM_HANDLER_CMD1_MDSCR_ESR and
                  native_ctx.elr == FC_XNU_TXM_HANDLER_CMD1_MDSCR_PC):
                ctx = native_ctx
                debug_gate = dict(
                    pc=hex(ctx.elr), esr=hex(int(ctx.esr)),
                    spsr=hex(int(ctx.spsr)), x9=hex(int(ctx.regs[9])))
                checks = {
                    'exact_pc': ctx.elr == FC_XNU_TXM_HANDLER_CMD1_MDSCR_PC,
                    'exact_esr': int(ctx.esr) == FC_XNU_TXM_HANDLER_CMD1_MDSCR_ESR,
                    'tdcc_only': int(ctx.regs[9]) ==
                        FC_XNU_TXM_HANDLER_CMD1_MDSCR_VALUE,
                }
                try:
                    roots = txm_validator_trace_state['roots']
                    def read_fast_debug_page(table):
                        if (table & (PAGE - 1) or
                                not base <= table < table + PAGE <= base + guest_size):
                            raise ValueError('MDSCR table outside owned RAM')
                        return iface.readmem(table, PAGE)
                    debug_leaf = translate(ctx.elr, roots['ttbr0'], roots['ttbr1'],
                                           read_fast_debug_page)
                    debug_live = iface.readmem(debug_leaf['pa'], 4)
                    debug_source_offset = ctx.elr - FC_IMAGE_BASE
                    debug_source = sources['sptm'][debug_source_offset:
                                                   debug_source_offset + 4]
                    expected_debug = struct.pack(
                        '<I', FC_XNU_TXM_HANDLER_CMD1_MDSCR_WORD)
                    fast_status = txm_sstep_fast_path.status()
                    checks.update(
                        source_word=debug_source == expected_debug,
                        live_word=(debug_live == expected_debug and
                                   debug_live == debug_source),
                        level_three=debug_leaf['level'] == 3,
                        access_flag=debug_leaf['access_flag'],
                        filter_running=(fast_status['active'] and
                            fast_status['status'] == FC_VEL2_STEP_FILTER_RUNNING),
                        filter_bounded=(0 < fast_status['steps'] <=
                            FC_TXM_COMPLETION_FAST_STEPS),
                        filter_last_pc=fast_status['last_pc'] == ctx.elr,
                        filter_previous_pc=(fast_status['previous_pc'] ==
                            ctx.elr - 8),
                        filter_contract=(fast_status['terminal_pc'] ==
                            FC_XNU_TXM_HANDLER_CMD1_RETAB and
                            fast_status['expected_first_pc'] ==
                            FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR))
                    debug_gate.update(
                        source_hex=debug_source.hex(), live_hex=debug_live.hex(),
                        pa=hex(debug_leaf['pa']), filter_status=fast_status)
                except Exception as debug_gate_error:
                    checks['gate_readback'] = False
                    debug_gate['error'] = str(debug_gate_error)
                debug_gate['checks'] = checks
                report['xnu_txm_sstep_fast_path']['mdscr_tdcc'] = debug_gate
                if all(checks.values()):
                    debug_effect = guest_debug.access(
                        (2, 0, 0, 2, 2), False,
                        FC_XNU_TXM_HANDLER_CMD1_MDSCR_VALUE)
                    event.update(kind=debug_effect['kind'], native_handoff=True,
                                 firmware_step_filter_rearmed=True,
                                 pc=ctx.elr, esr=int(ctx.esr), spsr=int(ctx.spsr),
                                 regs=list(ctx.regs), far=ctx.far, sp=list(ctx.sp),
                                 sysreg=dict(encoding=[2, 0, 0, 2, 2],
                                     name='MDSCR_EL1', read=False, rt=9,
                                     value=debug_effect['value']))
                    report['guest_debug'] = guest_debug.snapshot()
                    ctx.elr += 4
                    ctx.spsr.SS = 1
                    u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
                else:
                    report['stop_reason'] = 'cmd1-fast-path-mdscr-gate-rejected'
            elif (txm_validator_trace_state['active'] and
                  not native_sptm_callback and
                  (not handoff_state.get('native') or
                   int(native_ctx.esr) >> 26 == 0x32)):
                ctx = native_ctx if handoff_state.get('native') else iface.readstruct(
                    info, ExcInfo)
                txm_validator_trace_state['steps'] += 1
                trace_step = txm_validator_trace_state['steps']
                trace_phase = txm_validator_trace_state['phase']
                in_txm_text = 0xfffffe0017024000 <= ctx.elr < 0xfffffe0017068000
                checks = {
                    'lower_sync': reason == START.EXCEPTION_LOWER and code == EXC.SYNC,
                    'software_step': int(ctx.esr) >> 26 == 0x32,
                    'txm_text_or_return': (in_txm_text
                        or ctx.elr in (txm_validator_trace_state['return_pc'],
                                      txm_validator_trace_state['response_stop'],
                                      FC_XNU_TXM_HANDLER_CMD1_RETAB,
                                      FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN)),
                }
                record = dict(index=trace_step, pc=hex(ctx.elr),
                              sp_el0=hex(int(ctx.sp[0])), spsr=hex(int(ctx.spsr)),
                              x0=hex(int(ctx.regs[0])), x1=hex(int(ctx.regs[1])),
                              x30=hex(int(ctx.regs[30])), checks=checks)
                probe = report[txm_validator_trace_state['report_key']]
                fast_status = None
                retab_transition = False
                if txm_validator_trace_state.get('fast_path_armed'):
                    try:
                        fast_status = txm_sstep_fast_path.status()
                        expected_terminal = (FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN
                            if txm_validator_trace_state.get('retab_crossed')
                            else FC_XNU_TXM_HANDLER_CMD1_RETAB)
                        checks['fast_path_forwarded_terminal'] = (
                            not fast_status['active'] and
                            fast_status['status'] == FC_VEL2_STEP_FILTER_TERMINAL and
                            fast_status['last_pc'] == ctx.elr and
                            ctx.elr == expected_terminal)
                    except Exception as fast_status_error:
                        checks['fast_path_forwarded_terminal'] = False
                        record['fast_path_status_error'] = str(fast_status_error)
                    if fast_status is not None:
                        record['fast_path_status'] = fast_status
                if (trace_phase == 'completion' and
                        not txm_validator_trace_state.get('retab_crossed') and
                        ctx.elr == FC_XNU_TXM_HANDLER_CMD1_RETAB and
                        fast_status is not None):
                    retab_checks = {
                        'exact_spsr': int(ctx.spsr) ==
                            FC_XNU_TXM_HANDLER_CMD1_RETAB_SPSR,
                        'authenticated_return_target': (
                            int(ctx.regs[30]) & ((1 << 40) - 1) ==
                            FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN &
                            ((1 << 40) - 1)),
                        'prior_filter_terminal': (
                            not fast_status['active'] and
                            fast_status['status'] == FC_VEL2_STEP_FILTER_TERMINAL and
                            fast_status['last_pc'] == ctx.elr and
                            fast_status['previous_pc'] ==
                                FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS and
                            0 < fast_status['steps'] <=
                                FC_TXM_COMPLETION_FAST_STEPS and
                            fast_status['terminal_pc'] ==
                                FC_XNU_TXM_HANDLER_CMD1_RETAB),
                    }
                    retab_gate = dict(pc=hex(ctx.elr), x30=hex(int(ctx.regs[30])),
                                      spsr=hex(int(ctx.spsr)),
                                      prior_status=fast_status)
                    try:
                        roots = txm_validator_trace_state['roots']
                        def read_retab_page(table):
                            if (table & (PAGE - 1) or
                                    not base <= table < table + PAGE <= base + guest_size):
                                raise ValueError('RETAB table outside owned RAM')
                            return iface.readmem(table, PAGE)
                        retab_leaf = translate(ctx.elr, roots['ttbr0'], roots['ttbr1'],
                                               read_retab_page)
                        retab_live = iface.readmem(retab_leaf['pa'], 4)
                        kernel_segment = layout['images']['kernelcache'][
                            'segments']['__TEXT_EXEC']
                        retab_source_offset = (kernel_segment['fileoff'] +
                            FC_XNU_TXM_HANDLER_CMD1_RETAB_LINKED -
                            kernel_segment['va'])
                        retab_source = sources['kernelcache'][
                            retab_source_offset:retab_source_offset + 4]
                        expected_retab = struct.pack(
                            '<I', FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD)
                        retab_checks.update(
                            source_word=retab_source == expected_retab,
                            live_word=(retab_live == expected_retab and
                                       retab_live == retab_source),
                            level_three=retab_leaf['level'] == 3,
                            access_flag=retab_leaf['access_flag'])
                        retab_gate.update(pa=hex(retab_leaf['pa']),
                                          source_hex=retab_source.hex(),
                                          live_hex=retab_live.hex())
                    except Exception as retab_gate_error:
                        retab_checks['gate_readback'] = False
                        retab_gate['error'] = str(retab_gate_error)
                    retab_gate['checks'] = retab_checks
                    record['retab_gate'] = retab_gate
                    retab_transition = all(retab_checks.values())
                    checks['retab_transition'] = retab_transition
                record['phase'] = trace_phase
                validator_trace = probe.setdefault('validator_trace', [])
                validator_trace.append(record)
                event.update(kind='txm-handler-' + trace_phase + '-trace', pc=ctx.elr,
                             esr=int(ctx.esr), spsr=int(ctx.spsr), regs=list(ctx.regs),
                             far=ctx.far, sp=list(ctx.sp), checks=checks,
                             validator_trace_step=trace_step)
                returned = (trace_phase == 'validator'
                    and ctx.elr == txm_validator_trace_state['return_pc'])
                if returned:
                    protected_after = iface.readmem(
                        txm_validator_trace_state['protected_pa'],
                        txm_validator_trace_state['protected_size'])
                    checks.update(
                        expected_return_sp=(int(ctx.sp[0])
                            == txm_validator_trace_state['expected_sp']),
                        expected_result=(int(ctx.regs[0]) & 0xffffffff
                            == txm_validator_trace_state['expected_result']),
                        caller_frame_preserved=(protected_after
                            == txm_validator_trace_state['protected_before']))
                    record.update(returned=True,
                        protected_after_sha256=hashlib.sha256(
                            protected_after).hexdigest())
                validator_complete = returned and all(checks.values())
                continue_to_response = (validator_complete
                    and txm_validator_trace_state['boundary'] in (
                        'response-trace', 'cmd1-completion-trace'))
                response_done = (trace_phase == 'response'
                    and ctx.elr == txm_validator_trace_state['response_stop'])
                if response_done:
                    frame_pa = txm_validator_trace_state['metadata_frame_pa']
                    response = iface.readmem(frame_pa, 0x38)
                    marker = iface.readmem(
                        txm_validator_trace_state['protected_pa'] + 0x18, 8)
                    expected_pointer = txm_validator_trace_state['response_pointer']
                    checks.update(
                        expected_response_sp=(int(ctx.sp[0])
                            == txm_validator_trace_state['expected_sp']),
                        response_result_zero=(response[8:16] == b'\x00' * 8),
                        response_type_three=(response[0x18:0x20]
                            == struct.pack('<Q', 3)),
                        response_pointer=(response[0x20:0x28]
                            == struct.pack('<Q', expected_pointer)),
                        response_global_four=(response[0x28:0x30]
                            == struct.pack('<Q', FC_XNU_TXM_HANDLER_GLOBAL + 4)),
                        response_global_eight=(response[0x30:0x38]
                            == struct.pack('<Q', FC_XNU_TXM_HANDLER_GLOBAL + 8)),
                        completion_slot_zero=(marker == b'\x00' * 8))
                    record.update(response_hex=response.hex(),
                                  completion_slot_hex=marker.hex())
                response_complete = response_done and all(checks.values())
                continue_to_completion = (response_complete
                    and txm_validator_trace_state['boundary']
                        == 'cmd1-completion-trace')
                fast_arm_gate = (trace_phase == 'completion'
                    and getattr(a, 'xnu_txm_sstep_fast_path', False)
                    and not txm_validator_trace_state.get('fast_path_armed')
                    and ctx.elr == FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC)
                if fast_arm_gate:
                    try:
                        roots = txm_validator_trace_state['roots']
                        def read_fast_gate_page(table):
                            if (table & (PAGE - 1) or
                                    not base <= table < table + PAGE <= base + guest_size):
                                raise ValueError(
                                    'Completion SVC table outside owned RAM')
                            return iface.readmem(table, PAGE)
                        svc_leaf = translate(ctx.elr, roots['ttbr0'], roots['ttbr1'],
                                             read_fast_gate_page)
                        svc_live = iface.readmem(svc_leaf['pa'], 4)
                        txm_segment = layout['images']['txm']['segments']['__TEXT_EXEC']
                        svc_linked = (FC_XNU_TXM_HANDLER_HELPER_LINKED +
                                      FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC -
                                      FC_XNU_TXM_HANDLER_HELPER)
                        svc_source_offset = (txm_segment['fileoff'] + svc_linked -
                                             txm_segment['va'])
                        svc_source = sources['txm'][svc_source_offset:
                                                    svc_source_offset + 4]
                        expected_svc = struct.pack(
                            '<I', FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC_WORD)
                        checks.update(
                            completion_svc_level_three=svc_leaf['level'] == 3,
                            completion_svc_access_flag=svc_leaf['access_flag'],
                            completion_svc_source=svc_source == expected_svc,
                            completion_svc_live=(svc_live == expected_svc and
                                                 svc_live == svc_source))
                        record.update(
                            completion_svc_linked=hex(svc_linked),
                            completion_svc_pa=hex(svc_leaf['pa']),
                            completion_svc_source_hex=svc_source.hex(),
                            completion_svc_live_hex=svc_live.hex())
                    except Exception as fast_gate_error:
                        checks['completion_svc_gate'] = False
                        record['completion_svc_gate_error'] = str(fast_gate_error)
                completion_done = (trace_phase == 'completion'
                    and ctx.elr == FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN)
                if completion_done:
                    retab_record = report.get('xnu_txm_sstep_fast_path', {}).get(
                        'retab_transition', {})
                    prior_fast_status = retab_record.get('prior_status')
                    claim_after_completion = iface.readmem(
                        txm_validator_trace_state['metadata_frame_pa'] + 0x58, 1)
                    checks.update(
                        xnu_return_pc=(ctx.elr
                            == FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN),
                        claim_released=(claim_after_completion == b'\x00'))
                    if getattr(a, 'xnu_txm_sstep_fast_path', False):
                        checks.update(
                            fast_path_terminal=(fast_status is not None and
                                not fast_status['active'] and
                                fast_status['status'] == FC_VEL2_STEP_FILTER_TERMINAL),
                            fast_path_bounded=(fast_status is not None and
                                prior_fast_status is not None and
                                fast_status['steps'] == 0 and
                                0 < prior_fast_status['steps'] <=
                                    FC_TXM_COMPLETION_FAST_STEPS),
                            fast_path_crossed_both_worlds=(
                                prior_fast_status is not None and
                                prior_fast_status['range0_hits'] > 0 and
                                prior_fast_status['range1_hits'] > 0),
                            fast_path_contract=(fast_status is not None and
                                prior_fast_status is not None and
                                prior_fast_status['first_pc'] ==
                                    FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR and
                                prior_fast_status['expected_first_pc'] ==
                                    FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR and
                                prior_fast_status['range0_start'] ==
                                    FC_TXM_RUNTIME_TEXT[0] and
                                prior_fast_status['range0_end'] ==
                                    FC_TXM_RUNTIME_TEXT[1] and
                                prior_fast_status['range1_start'] ==
                                    FC_SPTM_RUNTIME_TEXT[0] and
                                prior_fast_status['range1_end'] ==
                                    FC_SPTM_RUNTIME_TEXT[1] and
                                prior_fast_status['terminal_pc'] ==
                                    FC_XNU_TXM_HANDLER_CMD1_RETAB and
                                fast_status['first_pc'] == 0 and
                                fast_status['expected_first_pc'] ==
                                    FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN and
                                fast_status['range0_start'] ==
                                    FC_XNU_RUNTIME_TEXT[0] and
                                fast_status['range0_end'] ==
                                    FC_XNU_RUNTIME_TEXT[1] and
                                fast_status['range1_start'] ==
                                    FC_SPTM_RUNTIME_TEXT[0] and
                                fast_status['range1_end'] ==
                                    FC_SPTM_RUNTIME_TEXT[1] and
                                fast_status['terminal_pc'] ==
                                    FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN and
                                fast_status['max_steps'] ==
                                    FC_TXM_COMPLETION_FAST_STEPS))
                    record['claim_after_completion_hex'] = (
                        claim_after_completion.hex())
                complete = (validator_complete
                    if txm_validator_trace_state['boundary'] == 'validator-trace'
                    else (completion_done and all(checks.values())
                        if txm_validator_trace_state['boundary']
                            == 'cmd1-completion-trace'
                        else response_complete))
                exhausted = trace_step >= txm_validator_trace_state['limit']
                phase53_continue = (complete and
                    getattr(a, 'xnu_phase53_allocation_trace', False))
                if continue_to_response:
                    txm_validator_trace_state['phase'] = 'response'
                    probe['validator_result'] = dict(record)
                    ctx.spsr.SS = 1
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
                elif continue_to_completion:
                    txm_validator_trace_state['phase'] = 'completion'
                    probe['response_result'] = dict(record)
                    ctx.spsr.SS = 1
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
                elif fast_arm_gate and all(checks.values()):
                    try:
                        enabled_status = txm_sstep_fast_path.enable(
                            FC_TXM_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
                            FC_XNU_TXM_HANDLER_CMD1_RETAB,
                            FC_TXM_COMPLETION_FAST_STEPS,
                            FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR)
                        txm_validator_trace_state['fast_path_armed'] = True
                        report['xnu_txm_sstep_fast_path'].update(
                            activated=True, activated_at_pc=hex(ctx.elr),
                            activated_at_trace_step=trace_step,
                            enable_status=enabled_status,
                            activation_record=dict(record))
                        ctx.spsr.SS = 1
                        iface.writemem(info, ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    except Exception as fast_enable_error:
                        checks['fast_path_enable'] = False
                        record['fast_path_enable_error'] = str(fast_enable_error)
                        report['xnu_txm_sstep_fast_path'][
                            'activation_error'] = str(fast_enable_error)
                        txm_validator_trace_state['active'] = False
                        report['stop_reason'] = 'xnu-txm-sstep-fast-path-enable-failed'
                elif retab_transition:
                    try:
                        prior_status = dict(fast_status)
                        enabled_status = txm_sstep_fast_path.enable(
                            FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
                            FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN,
                            FC_TXM_COMPLETION_FAST_STEPS,
                            FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN)
                        txm_validator_trace_state.update(
                            retab_crossed=True,
                            fast_path_prior_steps=prior_status['steps'])
                        transition_record = dict(
                            record, prior_status=prior_status,
                            enable_status=enabled_status,
                            expected_first_pc=hex(
                                FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN))
                        report['xnu_txm_sstep_fast_path'][
                            'retab_transition'] = transition_record
                        event['kind'] = 'cmd1-retab-transition'
                        ctx.spsr.SS = 1
                        u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                        iface.writemem(info, ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    except Exception as retab_enable_error:
                        record['retab_enable_error'] = str(retab_enable_error)
                        txm_validator_trace_state['active'] = False
                        report['stop_reason'] = (
                            'cmd1-retab-fast-path-enable-failed')
                elif phase53_continue:
                    boundary = txm_validator_trace_state['boundary']
                    prior_steps = txm_validator_trace_state.get(
                        'fast_path_prior_steps', 0)
                    cmd1_result = dict(
                        record, boundary=boundary,
                        extension_instructions=(39 + trace_step + prior_steps +
                            (fast_status['steps'] if fast_status is not None else 0)),
                        validator_trace_steps=trace_step,
                        validator_returned=True, response_completed=True,
                        cmd1_xnu_return=True, complete=True)
                    probe['result'] = cmd1_result
                    probe['complete'] = True
                    txm_validator_trace_state['active'] = False
                    try:
                        allocation_enable = txm_sstep_fast_path.enable(
                            FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
                            FC_XNU_PHASE53_ALLOC_CALL,
                            FC_XNU_PHASE53_FAST_STEPS,
                            FC_XNU_PHASE53_AFTER_CMD1_FIRST)
                        phase53_allocation_trace_state.update(
                            active=True,
                            roots=txm_validator_trace_state['roots'],
                            range0=FC_XNU_RUNTIME_TEXT,
                            segment_start=FC_XNU_PHASE53_AFTER_CMD1_FIRST,
                            stage='allocation-call',
                            terminal_pc=FC_XNU_PHASE53_ALLOC_CALL,
                            world_transitions=[])
                        report['xnu_phase53_allocation_trace'] = dict(
                            requested=True, activated=True,
                            from_pc=hex(ctx.elr),
                            expected_first_pc=hex(
                                FC_XNU_PHASE53_AFTER_CMD1_FIRST),
                            terminal_pc=hex(FC_XNU_PHASE53_ALLOC_CALL),
                            target_pc=hex(FC_XNU_PHASE53_ALLOC_ENTRY),
                            current_stage='allocation-call',
                            enable_status=allocation_enable,
                            cmd1_result=cmd1_result)
                        report['xnu_txm_sstep_fast_path'][
                            'allocation_transition'] = dict(
                                prior_status=fast_status,
                                enable_status=allocation_enable)
                        event['kind'] = 'phase53-allocation-trace-start'
                        ctx.spsr.SS = 1
                        u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                        iface.writemem(info, ExcInfo.build(ctx))
                        report.pop('stop_reason', None)
                        ret = EXC_RET.HANDLED
                    except Exception as allocation_enable_error:
                        report['xnu_phase53_allocation_trace'] = dict(
                            requested=True, activated=False,
                            error=str(allocation_enable_error))
                        report['stop_reason'] = (
                            'phase53-allocation-fast-path-enable-failed')
                elif complete or exhausted or not all(checks.values()):
                    txm_validator_trace_state['active'] = False
                    u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) & ~1)
                    boundary = txm_validator_trace_state['boundary']
                    result = dict(record, boundary=boundary,
                                  extension_instructions=(39 + trace_step +
                                    txm_validator_trace_state.get(
                                        'fast_path_prior_steps', 0) +
                                    (fast_status['steps']
                                     if fast_status is not None else 0)),
                                  validator_trace_steps=trace_step,
                                  validator_returned=(validator_complete
                                    or 'validator_result' in probe),
                                  response_completed=((response_complete or
                                    'response_result' in probe)
                                    if boundary in ('response-trace',
                                        'cmd1-completion-trace') else None),
                                  cmd1_xnu_return=(complete
                                    if boundary == 'cmd1-completion-trace' else None),
                                  complete=complete)
                    probe['result'] = result
                    probe['complete'] = complete
                    report['stop_reason'] = ('txm-handler-' + boundary + '-complete'
                        if complete else ('txm-handler-' + boundary + '-limit'
                        if exhausted else 'txm-handler-' + boundary + '-mismatch'))
                else:
                    ctx.spsr.SS = 1
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
            elif txm_context_step_state['active']:
                ctx = native_ctx if handoff_state.get('native') else iface.readstruct(info, ExcInfo)
                expected = txm_context_step_state['expected_states'][
                    txm_context_step_state['index']]
                observed_sp = int(ctx.sp[0])
                step_record_error = None
                first_touch = None
                claim_after = None
                observed_memory = {}
                metadata_page_after = None
                page_diff_offsets = None
                checks = {
                    'lower_sync': reason == START.EXCEPTION_LOWER and code == EXC.SYNC,
                    'software_step': int(ctx.esr) == 0xcb000022,
                    'expected_pc': ctx.elr == expected['pc'],
                    'expected_spsr': int(ctx.spsr) == expected['spsr'],
                    'expected_sp_el0': observed_sp == expected['sp'],
                    'x16_unchanged': int(ctx.regs[16]) == FC_XNU_TXM_CONTEXT_SELECTOR,
                    'x18_unchanged': int(ctx.regs[18]) == FC_XNU_TXM_CONTEXT_X18,
                }
                checks.update({'x%d' % register: int(ctx.regs[register]) == value
                    for register, value in expected['regs'].items()})
                captured_snapshot = {}
                for register in expected.get('capture_regs', ()):
                    capture_ok = all(checks.values())
                    checks['capture_x%d' % register] = capture_ok
                    if capture_ok:
                        value = int(ctx.regs[register])
                        txm_context_step_state['captured_regs'][register] = value
                        captured_snapshot['x%d' % register] = hex(value)
                for register in expected.get('same_captured_regs', ()):
                    value = txm_context_step_state['captured_regs'].get(register)
                    checks['captured_x%d_unchanged' % register] = (
                        value is not None and int(ctx.regs[register]) == value)
                for register, source_register in expected.get(
                        'captured_reg_values', {}).items():
                    value = txm_context_step_state['captured_regs'].get(source_register)
                    checks['x%d_from_captured_x%d' % (register, source_register)] = (
                        value is not None and int(ctx.regs[register]) == value)
                save_register_pairs = ((26, 25), (24, 23), (22, 21),
                                       (20, 19), (29, 30))
                for pair_index, registers in enumerate(
                        save_register_pairs[:expected.get('saved_pairs', 0)]):
                    try:
                        values = [txm_context_step_state['captured_regs'][register]
                                  for register in registers]
                        observed = iface.readmem(
                            txm_context_step_state['metadata_frame_pa'] - 0x70
                                + 0x20 + pair_index * 0x10, 0x10)
                        name = 'save_pair_%d' % pair_index
                        observed_memory[name] = observed.hex()
                        checks['memory_' + name] = observed == struct.pack('<QQ', *values)
                    except Exception as error:
                        checks['memory_save_pair_%d' % pair_index] = False
                        step_record_error = str(error)
                for name, expected_hex in expected.get('memory', {}).items():
                    try:
                        offset, width = txm_context_step_state['metadata_offsets'][name]
                        observed = iface.readmem(
                            txm_context_step_state['metadata_frame_pa'] + offset, width)
                        observed_memory[name] = observed.hex()
                        checks['memory_' + name] = observed == bytes.fromhex(expected_hex)
                    except Exception as error:
                        checks['memory_' + name] = False
                        step_record_error = str(error)
                if (txm_context_step_state['report_key'] in
                        ('xnu_txm_context_entry_register_prefix',
                         'xnu_txm_context_stack_claim_one_step',
                         'xnu_txm_context_stack_metadata_init',
                         'xnu_txm_context_x18_branch_one_step',
                         'xnu_txm_context_outbound_branch_one_step',
                         'xnu_txm_handler_boundary')
                        and txm_context_step_state['index'] + 1
                            == len(txm_context_step_state['expected_states'])):
                    try:
                        def final_owned_page(pa):
                            if (pa & (PAGE - 1) or
                                    not base <= pa < pa + PAGE <= base + guest_size):
                                raise ValueError('Final TXM prefix table outside owned RAM')
                            page = iface.readmem(pa, PAGE)
                            if len(page) != PAGE:
                                raise ValueError('Truncated final TXM prefix table')
                            return page
                        first_touch = translate(txm_context_step_state['first_touch_va'],
                            txm_context_step_state['roots']['ttbr0'],
                            txm_context_step_state['roots']['ttbr1'], final_owned_page)
                        checks['first_touch_mapping'] = (
                            first_touch['level'] == 3 and first_touch['access_flag']
                            and first_touch['pa'] == txm_context_step_state['first_touch_pa'])
                        if (txm_context_step_state['report_key']
                                == 'xnu_txm_context_stack_claim_one_step'):
                            claim_after = iface.readmem(first_touch['pa'], 1)
                            checks['stack_claimed_zero_to_one'] = claim_after == b'\x01'
                        elif (txm_context_step_state['report_key'] in
                                ('xnu_txm_context_stack_metadata_init',
                                 'xnu_txm_context_x18_branch_one_step',
                                 'xnu_txm_context_outbound_branch_one_step',
                                 'xnu_txm_handler_boundary')):
                            claim_after = iface.readmem(first_touch['pa'], 1)
                            checks['stack_claimed_zero_to_one'] = claim_after == b'\x01'
                            metadata_page_after = iface.readmem(
                                txm_context_step_state['stack_page_pa'], PAGE)
                            expected_page = bytearray(
                                txm_context_step_state['metadata_page_before'])
                            frame_offset = (txm_context_step_state['metadata_frame_pa']
                                - txm_context_step_state['stack_page_pa'])
                            expected_page[frame_offset] = 1
                            expected_page[frame_offset + 4:frame_offset + 8] = b'\x00' * 4
                            expected_page[frame_offset + 0x58] = 1
                            expected_page[frame_offset + 0x79] = 0
                            if txm_context_step_state['handler_boundary'] in (
                                    'register-saves', 'local-setup', 'validator-entry',
                                    'validator-trace', 'response-trace',
                                    'cmd1-completion-trace'):
                                for pair_index, registers in enumerate(save_register_pairs):
                                    values = [txm_context_step_state['captured_regs'][register]
                                              for register in registers]
                                    offset = frame_offset - 0x70 + 0x20 + pair_index * 0x10
                                    expected_page[offset:offset + 0x10] = struct.pack(
                                        '<QQ', *values)
                            if txm_context_step_state['handler_boundary'] in (
                                    'local-setup', 'validator-entry', 'validator-trace',
                                    'response-trace', 'cmd1-completion-trace'):
                                expected_page[frame_offset - 0x70 + 0x18:
                                              frame_offset - 0x70 + 0x20] = struct.pack('<Q', 1)
                            if txm_context_step_state['handler_boundary'] in (
                                    'validator-entry', 'validator-trace', 'response-trace',
                                    'cmd1-completion-trace'):
                                expected_page[frame_offset - 0x70:
                                              frame_offset - 0x68] = struct.pack(
                                                  '<Q', FC_XNU_TXM_CONTEXT_STACK)
                                expected_page[frame_offset - 0x68:
                                              frame_offset - 0x58] = struct.pack(
                                                  '<QQ', PAGE, PAGE)
                            page_diff_offsets = [index for index, (before, after) in enumerate(
                                zip(txm_context_step_state['metadata_page_before'],
                                    metadata_page_after)) if before != after]
                            checks['metadata_final_values'] = (
                                metadata_page_after[frame_offset] == 1
                                and metadata_page_after[frame_offset + 4:frame_offset + 8]
                                    == b'\x00' * 4
                                and metadata_page_after[frame_offset + 0x58] == 1
                                and metadata_page_after[frame_offset + 0x79] == 0)
                            checks['metadata_no_unexpected_page_writes'] = (
                                metadata_page_after == bytes(expected_page))
                    except Exception as error:
                        first_touch = None
                        checks['first_touch_mapping'] = False
                        step_record_error = str(error)
                step_record = dict(
                    index=txm_context_step_state['index'], expected_pc=hex(expected['pc']),
                    observed_pc=hex(ctx.elr), expected_sp=hex(expected['sp']),
                    observed_sp_el0=hex(observed_sp), esr=hex(int(ctx.esr)),
                    spsr=hex(int(ctx.spsr)), checks=checks,
                    verified=all(checks.values()))
                if step_record_error is not None:
                    step_record['mapping_error'] = step_record_error
                if first_touch is not None:
                    step_record['first_touch_mapping'] = first_touch
                if claim_after is not None:
                    step_record['claim_after_hex'] = claim_after.hex()
                if observed_memory:
                    step_record['observed_memory_hex'] = observed_memory
                if captured_snapshot:
                    step_record['captured_regs'] = captured_snapshot
                if (txm_context_step_state['report_key'] in
                        ('xnu_txm_context_stack_metadata_init',
                         'xnu_txm_context_x18_branch_one_step',
                         'xnu_txm_context_outbound_branch_one_step',
                         'xnu_txm_handler_boundary')
                        and txm_context_step_state['index'] + 1
                            == len(txm_context_step_state['expected_states'])
                        and metadata_page_after is not None):
                    step_record.update(
                        metadata_page_after_sha256=hashlib.sha256(
                            metadata_page_after).hexdigest(),
                        metadata_page_diff_offsets=[hex(offset)
                            for offset in page_diff_offsets])
                probe = report[txm_context_step_state['report_key']]
                probe.setdefault('steps', []).append(step_record)
                event.update(kind=txm_context_step_state['event_kind'], pc=ctx.elr,
                             esr=int(ctx.esr), spsr=int(ctx.spsr), regs=list(ctx.regs),
                             far=ctx.far, sp=list(ctx.sp), checks=checks)
                if all(checks.values()) and expected.get('begin_validator_trace'):
                    txm_context_step_state['active'] = False
                    protected_pa = txm_context_step_state['metadata_frame_pa'] - 0x70
                    protected_size = 0x70 + 0x7a
                    txm_validator_trace_state.update(
                        active=True, phase='validator', steps=0, limit=2048,
                        boundary=txm_context_step_state['handler_boundary'],
                        return_pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0xa4,
                        response_stop=FC_XNU_TXM_HANDLER_RESPONSE_STOP,
                        expected_sp=expected['sp'], expected_result=0x2d,
                        metadata_frame_pa=txm_context_step_state['metadata_frame_pa'],
                        response_pointer=(int.from_bytes(
                            txm_context_step_state['response_pointer_before'], 'little')
                            if txm_context_step_state.get('response_pointer_before')
                            is not None else None),
                        protected_pa=protected_pa,
                        protected_before=iface.readmem(protected_pa, protected_size),
                        protected_size=protected_size,
                        roots=dict(txm_context_step_state['roots']),
                        report_key=txm_context_step_state['report_key'])
                    step_record.update(boundary=txm_context_step_state['handler_boundary'],
                                       validator_call_entered=True)
                    probe['validator_entry'] = step_record
                    ctx.spsr.SS = 1
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
                elif (all(checks.values()) and txm_context_step_state['index'] + 1
                        < len(txm_context_step_state['expected_states'])):
                    txm_context_step_state['index'] += 1
                    ctx.spsr.SS = 1
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
                else:
                    txm_context_step_state['active'] = False
                    u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) & ~1)
                    step_record['exactly_one_instruction'] = (
                        txm_context_step_state['report_key']
                            == 'xnu_txm_context_entry_one_step' and all(checks.values()))
                    if (txm_context_step_state['report_key']
                            == 'xnu_txm_context_x18_branch_one_step'):
                        branch_verified = (all(checks.values()) and ctx.elr
                            == FC_XNU_TXM_CONTEXT_TARGET + 0x7c)
                        step_record.update(
                            extension_instructions=(1 if branch_verified else None),
                            branch_taken=branch_verified,
                            fallthrough_svc_not_executed=branch_verified,
                            outbound_branch_executed=(False if branch_verified else None))
                    elif (txm_context_step_state['report_key']
                            == 'xnu_txm_context_outbound_branch_one_step'):
                        outbound_verified = (all(checks.values()) and ctx.elr
                            == FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET)
                        step_record.update(
                            extension_instructions=(1 if outbound_verified else None),
                            outbound_branch_taken=outbound_verified,
                            pacibsp_executed=(False if outbound_verified else None))
                    elif (txm_context_step_state['report_key']
                            == 'xnu_txm_handler_boundary'):
                        boundary = txm_context_step_state['handler_boundary']
                        terminal_offsets = {'prologue': 8, 'register-saves': 0x20,
                                            'local-setup': 0x44,
                                            'validator-entry': 0xa0}
                        boundary_verified = (all(checks.values())
                            and ctx.elr == FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET
                                + terminal_offsets[boundary])
                        extension_counts = {'prologue': 2, 'register-saves': 8,
                                            'local-setup': 23,
                                            'validator-entry': 39}
                        step_record.update(
                            boundary=boundary,
                            extension_instructions=(extension_counts[boundary]
                                if boundary_verified else None),
                            pacibsp_executed=boundary_verified,
                            stack_allocation_bytes=(0x70 if boundary_verified else None),
                            saved_register_pairs=(5 if boundary_verified
                                and boundary != 'prologue' else
                                (0 if boundary_verified else None)),
                            helper_roundtrip_executed=(boundary_verified
                                if boundary in ('local-setup', 'validator-entry') else False),
                            local_marker_stored=(boundary_verified
                                if boundary in ('local-setup', 'validator-entry') else False),
                            global_guard_zero=(boundary_verified
                                if boundary == 'validator-entry' else None),
                            validator_tuple_stored=(boundary_verified
                                if boundary == 'validator-entry' else None),
                            first_stp_executed=(boundary_verified
                                if boundary != 'prologue' else
                                (False if boundary_verified else None)))
                    probe['result'] = step_record
                    probe['complete'] = all(checks.values())
                    report['stop_reason'] = (txm_context_step_state['complete_reason']
                        if all(checks.values()) else txm_context_step_state['mismatch_reason'])
            elif handoff_state.get('native') and native_xnu_pperm_site is not None:
                ctx = native_ctx
                index, (_, _, _, operation) = native_xnu_pperm_site
                event.update(kind='xnu-pperm-guest-window', pc=ctx.elr,
                             esr=int(ctx.esr), spsr=int(ctx.spsr), regs=list(ctx.regs),
                             far=ctx.far, sp=list(ctx.sp), operation=operation,
                             site_index=index)
                if index == 0 and xnu_pperm_state['step'] == 4:
                    if (xnu_pperm_state['modified'] or
                            xnu_pperm_state['completed'] != xnu_pperm_state['started']):
                        raise ValueError('XNU PPERM prior window incomplete')
                    if xnu_pperm_state['completed'] >= a.xnu_pperm_guest_window_limit:
                        raise PpermWindowLimit('XNU PPERM guest window limit exhausted')
                    xnu_pperm_state['step'] = 0
                if index != xnu_pperm_state['step']:
                    raise ValueError('XNU PPERM callback order mismatch')
                reg = HV.MSR_REDIRECTS[SPRR_PPERM_EL1]
                if operation.startswith('read'):
                    raw = int(u.mrs(reg))
                    nibble = (raw >> 8) & 0xf
                    expected = 0xa if index == 0 else 0xb
                    if nibble != expected:
                        raise ValueError('XNU PPERM read nibble mismatch')
                    if index == 0:
                        if xnu_pperm_state['previous'] is None:
                            xnu_pperm_state['previous'] = raw
                        elif raw != xnu_pperm_state['previous']:
                            raise ValueError('XNU PPERM baseline A drift')
                        xnu_pperm_state['started'] += 1
                    else:
                        expected_raw = ((xnu_pperm_state['previous'] & ~(0xf << 8))
                                        | (0xb << 8))
                        if raw != expected_raw:
                            raise ValueError('XNU PPERM post-copy full value mismatch')
                        xnu_pperm_state['modified'] = True
                        report['xnu_pperm_guest_window']['memcpy_crossed'] = True
                        report['xnu_pperm_guest_window']['memcpy_crossed_windows'] += 1
                    ctx.regs[8] = raw
                    readback = raw
                else:
                    requested = int(ctx.regs[8])
                    previous = xnu_pperm_state['previous']
                    expected = ((previous & ~(0xf << 8)) | ((0xb if index == 1 else 0xa) << 8))
                    if requested != expected:
                        raise ValueError('XNU PPERM write value mismatch')
                    if index == 1:
                        xnu_pperm_state['modified'] = True
                    u.msr(reg, requested)
                    readback = int(u.mrs(reg))
                    if readback != requested:
                        raise ValueError('XNU PPERM full readback mismatch')
                    if index == 3:
                        xnu_pperm_state['modified'] = False
                        xnu_pperm_state['completed'] += 1
                xnu_pperm_state['step'] += 1
                report['xnu_pperm_guest_window']['started_windows'] = xnu_pperm_state['started']
                report['xnu_pperm_guest_window']['completed_windows'] = xnu_pperm_state['completed']
                report['xnu_pperm_guest_window']['sequence'].append(dict(
                    step=index, operation=operation, raw=readback,
                    index2_nibble=(readback >> 8) & 0xf))
                ctx.elr += 0  # HVC reports the following PC already
                iface.writemem(info, ExcInfo.build(ctx))
                event.update(raw=readback, memcpy_crossed=index >= 2,
                             window=xnu_pperm_state['started'])
                ret = EXC_RET.HANDLED
            elif handoff_state.get('native') and native_xnu_agt_callback:
                ctx = iface.readstruct(info, ExcInfo)
                requested = int(ctx.regs[8])
                if requested != 3:
                    event.update(kind='xnu-agtcnt-rdir-rejected', register='AGTCNTRDIR_EL12',
                                 read=False, value=requested)
                    report['stop_reason'] = 'xnu-agtcnt-rdir-contract'
                else:
                    previous = int(u.mrs(AGTCNTRDIR_EL12))
                    if xnu_agt_state['previous'] is None:
                        xnu_agt_state['previous'] = previous
                    u.msr(AGTCNTRDIR_EL12, requested)
                    xnu_agt_state['writes'] += 1
                    event.update(kind='xnu-guest-register', register='AGTCNTRDIR_EL12',
                                 read=False, value=requested, previous=previous,
                                 source_pc=hex(ctx.elr - 4), bank='guest-el12')
                    report.setdefault('xnu_guest_registers', []).append(dict(
                        register='AGTCNTRDIR_EL12', previous=previous, value=requested,
                        source_pc=hex(ctx.elr - 4), bank='guest-el12'))
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
            elif handoff_state.get('native') and native_xnu_apple_timer_callback:
                ctx = native_ctx
                requested = int(ctx.regs[8])
                if requested != 2:
                    event.update(kind='xnu-apple-physical-timer-hypothesis-rejected',
                                 reason_detail='requested-value-mismatch', value=requested)
                    report['stop_reason'] = 'xnu-apple-physical-timer-hypothesis'
                else:
                    previous = int(u.mrs(FC_XNU_APPLE_PHYS_TIMER_EL02))
                    if previous != FC_XNU_APPLE_PHYS_TIMER_OBSERVED_PRIOR:
                        event.update(kind='xnu-apple-physical-timer-hypothesis-rejected',
                                     reason_detail='candidate-prior-mismatch',
                                     observed_prior_raw=previous,
                                     expected_prior_raw=FC_XNU_APPLE_PHYS_TIMER_OBSERVED_PRIOR)
                        report['stop_reason'] = 'xnu-apple-physical-timer-hypothesis'
                    else:
                        if xnu_apple_timer_state['previous'] is None:
                            xnu_apple_timer_state['previous'] = previous
                        u.msr(FC_XNU_APPLE_PHYS_TIMER_EL02, requested)
                        readback = int(u.mrs(FC_XNU_APPLE_PHYS_TIMER_EL02))
                        xnu_apple_timer_state['writes'] += 1
                        ctx.elr += 4
                        hypothesis = dict(
                            enabled=True, register='S3_4_C15_C4_3',
                            candidate_encoding=list(FC_XNU_APPLE_PHYS_TIMER_EL02),
                            observed_prior_raw=previous, requested_raw=requested,
                            readback_raw=readback, source_pc=hex(ctx.elr - 4),
                            routing_established=False, bit_semantics_established=False,
                            physical_s3_1_bank_touched=False)
                        report['xnu_apple_physical_timer_hypothesis'] = hypothesis
                        event.update(kind='xnu-apple-physical-timer-hypothesis', **hypothesis)
                        iface.writemem(info, ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
            elif handoff_state.get('native') and native_xnu_cntp_ctl_callback:
                ctx = native_ctx
                requested = int(ctx.regs[8])
                if requested != 2:
                    event.update(kind='xnu-cntp-ctl-contract-rejected',
                                 register='CNTP_CTL_EL02', read=False, value=requested)
                    report['stop_reason'] = 'xnu-cntp-ctl-contract'
                else:
                    previous = int(u.mrs(CNTP_CTL_EL02))
                    if xnu_cntp_ctl_state['previous'] is None:
                        xnu_cntp_ctl_state['previous'] = previous
                    u.msr(CNTP_CTL_EL02, requested)
                    xnu_cntp_ctl_state['writes'] += 1
                    ctx.elr += 4
                    event.update(kind='xnu-guest-register', register='CNTP_CTL_EL02',
                                 read=False, value=requested, previous=previous,
                                 source_pc=hex(ctx.elr - 4), bank='guest-el02',
                                 host_timer_bank_touched=False)
                    report.setdefault('xnu_guest_registers', []).append(dict(
                        register='CNTP_CTL_EL02', previous=previous, value=requested,
                        source_pc=hex(ctx.elr - 4), bank='guest-el02',
                        host_timer_bank_touched=False))
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
            elif (handoff_state.get('native') and native_dockchannel_site is not None
                  and reason == START.EXCEPTION_LOWER and code == EXC.SYNC):
                ctx = native_ctx
                dockchannel_site = native_dockchannel_site
                fault_write = bool((int(ctx.esr) >> 6) & 1)
                ipa = p.hv_translate(ctx.far, True, fault_write)
                page = ipa & ~(PAGE - 1) if ipa else 0
                expected_page = dockchannel_site['ipa']
                od = report.setdefault('on_demand_stage2',
                    dict(count=0, samples=[], capped=False, stage1_faults=0))
                # Only this exact DT-verified device page can bypass the native stop.
                if ipa != dockchannel_site['expected_ipa']:
                    event.update(kind='xnu-native-exception', pc=ctx.elr,
                                 esr=int(ctx.esr), spsr=int(ctx.spsr),
                                 regs=list(ctx.regs), far=ctx.far, sp=list(ctx.sp),
                                 fault_ipa=ipa or 0,
                                 note='not the verified dockchannel-uart page')
                    report['stop_reason'] = 'xnu-native-exception'
                    report['handoff']['last_pc'] = hex(ctx.elr)
                elif od['count'] >= a.on_demand_stage2:
                    od['capped'] = True
                    event.update(kind='on-demand-stage2-exhausted', fault_va=ctx.far,
                                 fault_ipa=page, mmio=True)
                    report['stop_reason'] = 'on-demand-stage2-exhausted'
                elif p.hv_map(page, page | HV.PTE_ATTRIBUTES | HV.PTE_VALID,
                              PAGE, 1) < 0:
                    event.update(kind='dockchannel-uart-map-failed', fault_va=ctx.far,
                                 fault_ipa=page)
                    report['stop_reason'] = 'dockchannel-uart-map-failed'
                else:
                    u.exec('dsb ishst; tlbi vmalls12e1is; dsb ish; isb')
                    od['count'] += 1
                    sample = dict(va=ctx.far, ipa=page, host=page,
                                  write=fault_write, mmio=True, identity=True,
                                  site=dockchannel_site['name'], size=PAGE,
                                  device_size=dockchannel_site['device_size'],
                                  mapped_device_size=dockchannel_site['mapped_device_size'],
                                  extra_before=dockchannel_site['extra_before'],
                                  extra_after=dockchannel_site['extra_after'])
                    if len(od['samples']) < 64:
                        od['samples'].append(sample)
                    for mapping in report['xnu_dockchannel_uart_mmio']['mappings']:
                        if mapping['name'] == dockchannel_site['name']:
                            mapping.update(mapped=True, fault_va=ctx.far,
                                           fault_ipa=ipa, write=fault_write)
                            break
                    event.update(kind='dockchannel-uart-map', fault_va=ctx.far,
                                 fault_ipa=page, identity=True, size=PAGE,
                                 site=dockchannel_site['name'])
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
            elif (handoff_state.get('native') and native_panic_carveout
                  and reason == START.EXCEPTION_LOWER and code == EXC.SYNC):
                ctx = native_ctx
                ipa = p.hv_translate(ctx.far, True, False)
                od = report.setdefault('on_demand_stage2',
                    dict(count=0, samples=[], capped=False, stage1_faults=0))
                if ipa != panic_carveout['ipa']:
                    event.update(kind='xnu-native-exception', pc=ctx.elr,
                                 esr=int(ctx.esr), spsr=int(ctx.spsr), regs=list(ctx.regs),
                                 far=ctx.far, sp=list(ctx.sp), fault_ipa=ipa or 0,
                                 note='panic carveout translated IPA mismatch')
                    report['stop_reason'] = 'xnu-native-exception'
                    report['handoff']['last_pc'] = hex(ctx.elr)
                elif od['count'] + panic_carveout['pages'] > a.on_demand_stage2:
                    od['capped'] = True
                    event.update(kind='on-demand-stage2-exhausted', fault_va=ctx.far,
                                 fault_ipa=ipa, pages=panic_carveout['pages'])
                    report['stop_reason'] = 'on-demand-stage2-exhausted'
                elif p.hv_map(panic_carveout['ipa'],
                              panic_carveout['private_host'] | HV.PTE_ATTRIBUTES | HV.PTE_VALID,
                              panic_carveout['size'], 1) < 0:
                    event.update(kind='panic-carveout-map-failed', fault_va=ctx.far,
                                 fault_ipa=ipa)
                    report['stop_reason'] = 'panic-carveout-map-failed'
                else:
                    u.exec('dsb ishst; tlbi vmalls12e1is; dsb ish; isb')
                    od['count'] += panic_carveout['pages']
                    sample = dict(va=ctx.far, ipa=panic_carveout['ipa'],
                                  host=panic_carveout['private_host'],
                                  size=panic_carveout['size'], pages=panic_carveout['pages'],
                                  write=False, private_copy=True, original_writes=False)
                    if len(od['samples']) < 64:
                        od['samples'].append(sample)
                    report['xnu_private_panic_carveout'].update(
                        mapped=True, fault_va=ctx.far, fault_ipa=ipa)
                    event.update(kind='panic-carveout-private-map', **sample)
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
            elif (handoff_state.get('native') and native_socd_trace
                  and reason == START.EXCEPTION_LOWER and code == EXC.SYNC):
                ctx = native_ctx
                ipa = p.hv_translate(ctx.far, True, True)
                od = report.setdefault('on_demand_stage2',
                    dict(count=0, samples=[], capped=False, stage1_faults=0))
                expected_ipa = socd_trace['source']
                if ipa != expected_ipa or report['xnu_private_socd_trace']['mapped']:
                    event.update(kind='xnu-native-exception', pc=ctx.elr,
                                 esr=int(ctx.esr), spsr=int(ctx.spsr), regs=list(ctx.regs),
                                 far=ctx.far, sp=list(ctx.sp), fault_ipa=ipa or 0,
                                 note='SOCd translated IPA or first-map mismatch')
                    report['stop_reason'] = 'xnu-native-exception'
                    report['handoff']['last_pc'] = hex(ctx.elr)
                elif od['count'] + 1 > a.on_demand_stage2:
                    od['capped'] = True
                    event.update(kind='on-demand-stage2-exhausted', fault_va=ctx.far,
                                 fault_ipa=ipa, pages=1)
                    report['stop_reason'] = 'on-demand-stage2-exhausted'
                elif p.hv_map(socd_trace['ipa'],
                              socd_trace['private_host'] | HV.PTE_ATTRIBUTES | HV.PTE_VALID,
                              PAGE, 1) < 0:
                    event.update(kind='socd-trace-map-failed', fault_va=ctx.far, fault_ipa=ipa)
                    report['stop_reason'] = 'socd-trace-map-failed'
                else:
                    u.exec('dsb ishst; tlbi vmalls12e1is; dsb ish; isb')
                    od['count'] += 1
                    sample = dict(va=ctx.far, ipa=socd_trace['ipa'],
                                  fault_ipa=ipa, host=socd_trace['private_host'], size=PAGE,
                                  pages=1, write=True, private_copy=True, original_writes=False)
                    if len(od['samples']) < 64:
                        od['samples'].append(sample)
                    report['xnu_private_socd_trace'].update(
                        mapped=True, fault_va=ctx.far, fault_ipa=ipa)
                    event.update(kind='socd-trace-private-map', **sample)
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
            elif (handoff_state.get('native') and not native_sptm_callback
                  and reason == START.EXCEPTION_LOWER and code == EXC.SYNC
                  and int(native_ctx.esr) >> 26 == 0x18):
                # Native XNU can re-enter SPTM paths that use the same guest debug
                # controls seen during the stepped prefix. Keep those accesses in the
                # existing disabled-debug model; never expose the host MDSCR/OS lock.
                ctx = native_ctx
                esr = int(ctx.esr)
                access = ESR_ISS_MSR(esr & 0x1ffffff)
                reg = (access.Op0, access.Op1, access.CRn, access.CRm, access.Op2)
                value = 0 if access.Rt == 31 else ctx.regs[access.Rt]
                event.update(pc=ctx.elr, esr=esr, far=ctx.far,
                             spsr=int(ctx.spsr), regs=list(ctx.regs), sp=list(ctx.sp),
                             sysreg=dict(encoding=list(reg), name=sysreg_rev.get(reg),
                                         read=bool(access.DIR), rt=access.Rt, value=value))
                debug_effect = guest_debug.access(reg, bool(access.DIR), value)
                if debug_effect is None:
                    event['kind'] = 'xnu-native-exception'
                    report['stop_reason'] = 'xnu-native-exception'
                    report['handoff']['last_pc'] = hex(ctx.elr)
                else:
                    if access.DIR and access.Rt != 31:
                        ctx.regs[access.Rt] = debug_effect['value']
                    event['kind'] = debug_effect['kind']
                    event['native_handoff'] = True
                    event['sysreg']['value'] = debug_effect['value']
                    report['guest_debug'] = guest_debug.snapshot()
                    if guest_debug.oslock is not None:
                        report['guest_oslock'] = guest_debug.oslock
                    ctx.elr += 4
                    ctx.spsr.SS = 0
                    iface.writemem(info, ExcInfo.build(ctx))
                    ret = EXC_RET.HANDLED
            elif handoff_state.get('native') and not native_sptm_callback:
                ctx = native_ctx
                event.update(kind='xnu-native-exception', pc=ctx.elr, esr=int(ctx.esr),
                             spsr=int(ctx.spsr), regs=list(ctx.regs), far=ctx.far, sp=list(ctx.sp))
                report['stop_reason'] = 'xnu-native-exception'
                report['handoff']['last_pc'] = hex(ctx.elr)
            elif handoff_state['active']:
                ctx = iface.readstruct(info, ExcInfo)
                event.update(kind='handoff-step', pc=ctx.elr, esr=int(ctx.esr),
                             spsr=int(ctx.spsr), regs=list(ctx.regs), far=ctx.far, sp=list(ctx.sp))
                handoff_state['events'] += 1
                report['handoff']['observed_events'] = handoff_state['events']
                report['handoff']['last_pc'] = hex(ctx.elr)
                if reason == START.EXCEPTION_LOWER and code == EXC.SYNC and int(ctx.esr) >> 26 == 0x32:
                    # A step at the entry can be completion of the native GEXIT;
                    # it does not prove an instruction in the target image retired.
                    if handoff_state.get('xnu'):
                        target = int(report['handoff']['target_pc'], 0)
                        if ctx.elr == target:
                            report['handoff']['entry_reached'] = True
                        elif report['handoff'].get('entry_reached'):
                            report['handoff']['instructions_executed'] = True
                    else:
                        report['handoff']['instructions_executed'] = True
                    if handoff_state['events'] < handoff_state.get('budget', a.handoff_steps):
                        ctx.spsr.SS = 1
                        iface.writemem(info, ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    elif (handoff_state.get('xnu') and a.xnu_run
                          and report['handoff'].get('instructions_executed')):
                        roots = dict(ttbr0=u.mrs(TTBR0_EL12), ttbr1=u.mrs(TTBR1_EL12))
                        continuation = classify_entry(ctx.elr, layout, base, guest_size,
                                                      roots, iface.readmem, sources)
                        if continuation['image'] == 'kernelcache' and continuation['bytes_match']:
                            report['handoff']['free_run_from'] = hex(ctx.elr)
                            fast_shadow_ready = True
                            if a.xnu_tpidr_gl2_fast_shadow:
                                initial_value = apple_shadow[tpidr_gl2_register]
                                try:
                                    enabled_status = tpidr_gl2_fast_shadow.enable(
                                        tpidr_gl2_shadow_tag_base, initial_value)
                                    report['xnu_tpidr_gl2_fast_shadow'].update(
                                        activated=True,
                                        initial_value=initial_value,
                                        initial_value_hex=hex(initial_value),
                                        enable_status=enabled_status,
                                        activated_at_trace_index=trace_count(report),
                                        activated_from_pc=hex(ctx.elr))
                                except Exception as fast_shadow_error:
                                    fast_shadow_ready = False
                                    report['xnu_tpidr_gl2_fast_shadow'][
                                        'activation_error'] = str(fast_shadow_error)
                                    report['stop_reason'] = (
                                        'xnu-tpidr-gl2-fast-shadow-enable-failed')
                            if fast_shadow_ready:
                                # This transition is deliberately after the accelerator's
                                # strict enable readback. A missing/malformed proxy API can
                                # therefore never release XNU into native execution.
                                handoff_state.update(active=False, native=True)
                                ctx.spsr.SS = 0
                                u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) & ~1)
                                iface.writemem(info, ExcInfo.build(ctx))
                                ret = EXC_RET.HANDLED
                        else:
                            report['stop_reason'] = 'xnu-native-unverified'
                    else:
                        report['stop_reason'] = 'handoff-instruction-budget'
                else:
                    report['stop_reason'] = 'handoff-exception'
            elif trace_count(report) >= a.steps:
                report['stop_reason'] = 'instruction-budget'
            elif reason in (START.EXCEPTION,START.EXCEPTION_LOWER) and code != EXC.SYNC:
                # IRQ/FIQ/SError can retain a stale ESR from an earlier sync trap.
                report['stop_reason'] = 'asynchronous-exception'
            elif reason in (START.EXCEPTION,START.EXCEPTION_LOWER):
                ctx = iface.readstruct(info,ExcInfo)
                esr = int(ctx.esr)
                event.update(pc=ctx.elr,esr=esr,far=ctx.far,spsr=int(ctx.spsr),regs=list(ctx.regs),sp=list(ctx.sp))
                if not entered and reason == START.EXCEPTION_LOWER and (
                    (esr == 0x5a007ffe and ctx.elr == entry+4) or
                    (esr >> 26 == 0x32 and ctx.elr == entry)):
                    entered = True
                    iface.writemem(entry,original)
                    p.dc_cvau(entry,4);p.ic_ivau(entry,4)
                    ctx.elr = entry
                    # Establish masked entry state before monitor vectors exist.
                    ctx.spsr.D = ctx.spsr.A = ctx.spsr.I = ctx.spsr.F = 1
                    ctx.spsr.SS = 1
                    iface.writemem(info,ExcInfo.build(ctx))
                    event['kind'] = 'entry-guard'
                    ret = EXC_RET.HANDLED
                elif entered and reason == START.EXCEPTION_LOWER and esr >> 26 == 0x32:
                    event['kind'] = 'instruction-step'
                    off = ctx.elr-base
                    effect = recognize_zero_loop(bytes(blob[off:off+12]),ctx.regs,ctx.elr,base,guest_size) if a.emulate_zero_loops and 0 <= off <= len(blob)-12 else None
                    if effect is not None:
                        # Match live bytes as well: self-modified code is never accelerated.
                        if iface.readmem(ctx.elr,12) == bytes(blob[off:off+12]):
                            p.memset64(effect['address'],0,effect['bytes'])
                            p.dc_cvau(effect['address'],effect['bytes'])
                            ctx.regs[1],ctx.regs[2] = effect['x1'],effect['x2']
                            ctx.elr = effect['pc']
                            ctx.spsr.N,ctx.spsr.Z,ctx.spsr.C,ctx.spsr.V = 0,1,1,0
                            event.update(kind='emulated-zero-loop',effects=effect)
                    # Multi-call: the patched idle is a genter loop. At each genter (FC_IDLE_PC)
                    # set x16 = the next selector; at each return (FC_IDLE_PC+4) capture x0.
                    gc_done = False
                    if multi_call_selectors is not None:
                        if ctx.elr == FC_IDLE_PC and not gc_state['in_call'] and gc_state['index'] < len(multi_call_selectors):
                            sel = multi_call_selectors[gc_state['index']]
                            ctx.regs[16] = sel
                            gc_state['in_call'] = True; gc_state['started'] = trace_count(report)
                            event.update(kind='guarded-call-genter', call_index=gc_state['index'], selector=hex(sel))
                        elif ctx.elr == FC_IDLE_PC + 4 and gc_state['in_call']:
                            report.setdefault('guarded_calls', []).append(dict(
                                index=gc_state['index'], selector=hex(multi_call_selectors[gc_state['index']]),
                                result=ctx.regs[0], steps=trace_count(report)-gc_state['started']))
                            event.update(kind='guarded-call-return', call_index=gc_state['index'], result=ctx.regs[0])
                            gc_state['in_call'] = False; gc_state['index'] += 1
                            if gc_state['index'] >= len(multi_call_selectors):
                                report['stop_reason'] = 'guarded-calls-complete'; gc_done = True
                        elif ctx.elr == FC_PANIC and gc_state['in_call']:
                            # Invalid/not-permitted call: SPTM's panic is noreturn (would hang/reboot).
                            # Halt here, BEFORE the panic runs, and record it (non-mutating, non-launching).
                            report.setdefault('guarded_calls', []).append(dict(
                                index=gc_state['index'], selector=hex(multi_call_selectors[gc_state['index']]),
                                result=None, panicked=True, steps=trace_count(report)-gc_state['started']))
                            event.update(kind='guarded-call-panic', call_index=gc_state['index'])
                            report['stop_reason'] = 'guarded-call-panic'; gc_done = True
                    if gc_done:
                        iface.writemem(info,ExcInfo.build(ctx))  # persist captured state; exit (no SS)
                    elif trace_count(report) < a.steps:
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    else:
                        report['stop_reason'] = 'instruction-budget'
                elif entered and a.free_run and a.real_guarded and reason == START.EXCEPTION_LOWER and esr >> 26 == 0x16 and (esr & 0xffff) == 0x4800:
                    report['eret_trap'] = dict(pc=hex(ctx.elr), spsr=hex(int(ctx.spsr)),
                                                      x3=hex(ctx.regs[3]), phase='before-bank-read')
                    save()
                    # The first boot eret targets TXM. Resolve actual guest mappings;
                    # a numeric VA range or a nonzero bank does not identify XNU.
                    elr_gl1 = spsr_gl1 = 0
                    try:
                        rg = sysreg_fwd['ELR_GL1']; rs = sysreg_fwd['SPSR_GL1']
                        if rg in HV.MSR_REDIRECTS:
                            elr_gl1 = int(u.mrs(HV.MSR_REDIRECTS[rg]))
                        if rs in HV.MSR_REDIRECTS:
                            spsr_gl1 = int(u.mrs(HV.MSR_REDIRECTS[rs]))
                    except Exception as bank_error:
                        event['eret_bank_error'] = str(bank_error)
                        elr_gl1 = spsr_gl1 = 0
                    event.update(kind='eret-guarded', target=hex(elr_gl1), target_spsr=hex(spsr_gl1))
                    report['eret_trap'].update(phase='banks-read', target=hex(elr_gl1), target_spsr=hex(spsr_gl1))
                    report['stop_reason'] = 'eret-unclassified-target'
                    if elr_gl1:
                        roots = dict(ttbr0=u.mrs(TTBR0_EL12), ttbr1=u.mrs(TTBR1_EL12))
                        classification = dict(status='classified', decision='rejected',
                            trap_pc=hex(ctx.elr), target_pc=hex(elr_gl1),
                            target_spsr=hex(spsr_gl1),
                            translation_roots={name: hex(value) for name, value in roots.items()})
                        try:
                            handoff = classify_entry(elr_gl1, layout, base, guest_size,
                                                     roots, iface.readmem, sources)
                            classification.update(handoff)
                            classification_ok = True
                        except Exception as classification_error:
                            classification.update(status='error', error=str(classification_error))
                            report.setdefault('eret_classifications', []).append(classification)
                            report['stop_reason'] = 'eret-classification-error'
                            classification_ok = False
                            handoff = dict(image=None, segment=None, entry_matches=False,
                                bytes_match=False, linked_pc=None, bytes_hex='',
                                target_pc=hex(elr_gl1), instructions_executed=False)
                        if classification_ok:
                            report.setdefault('eret_classifications', []).append(classification)
                        eret_record = dict(handoff, spsr=hex(spsr_gl1), via='ERET_HVC guarded banks')
                        completion_fast_status = None
                        completion_guarded_esr = None
                        completion_guarded_aspsr = None
                        if (classification_ok and
                                txm_validator_trace_state.get('active') and
                                txm_validator_trace_state.get('phase') == 'completion' and
                                txm_validator_trace_state.get('fast_path_armed') and
                                getattr(a, 'xnu_txm_sstep_fast_path', False)):
                            try:
                                completion_fast_status = txm_sstep_fast_path.status()
                                completion_guarded_esr = int(u.mrs(
                                    HV.MSR_REDIRECTS[ESR_GL1]))
                                completion_guarded_aspsr = int(u.mrs(
                                    HV.MSR_REDIRECTS[ASPSR_GL1]))
                                classification.update(
                                    completion_fast_status=completion_fast_status,
                                    guarded_esr=hex(completion_guarded_esr),
                                    guarded_aspsr=hex(completion_guarded_aspsr))
                            except Exception as completion_gate_error:
                                classification['completion_gate_error'] = str(
                                    completion_gate_error)
                        completion_eret = (classification_ok and
                            completion_fast_status is not None and
                            ctx.elr == FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET and
                            elr_gl1 == FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC + 4 and
                            spsr_gl1 == 0x800013c0 and
                            completion_guarded_esr ==
                                FC_XNU_TXM_HANDLER_CMD1_GUARDED_ESR and
                            completion_guarded_aspsr ==
                                FC_XNU_TXM_HANDLER_CMD1_GUARDED_ASPSR and
                            handoff['image'] == 'txm' and
                            handoff['segment'] == '__TEXT_EXEC' and
                            handoff['linked_pc'] ==
                                hex(FC_XNU_TXM_HANDLER_CMD1_RETURN_LINKED) and
                            handoff['bytes_match'] and
                            bytes.fromhex(handoff['bytes_hex']).startswith(
                                FC_XNU_TXM_HANDLER_CMD1_RETURN_BYTES) and
                            completion_fast_status['active'] and
                            completion_fast_status['status'] ==
                                FC_VEL2_STEP_FILTER_RUNNING and
                            0 < completion_fast_status['steps'] <=
                                FC_TXM_COMPLETION_FAST_STEPS and
                            completion_fast_status['first_pc'] ==
                                FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR and
                            completion_fast_status['last_pc'] == ctx.elr - 8 and
                            completion_fast_status['range0_hits'] == 0 and
                            completion_fast_status['range1_hits'] ==
                                completion_fast_status['steps'] and
                            completion_fast_status['terminal_pc'] ==
                                FC_XNU_TXM_HANDLER_CMD1_RETAB and
                            completion_fast_status['expected_first_pc'] ==
                                FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR)
                        entry_launch = (classification_ok and handoff['entry_matches'] and handoff['bytes_match']
                            and spsr_gl1 == 0x13c0
                            and handoff['image'] in ('txm', 'kernelcache'))
                        txm_return = (classification_ok and a.native_handoff and handoff['image'] == 'txm'
                            and (entry_launch or (handoff['segment'] in ('__TEXT_EXEC', '__TEXT_BOOT_EXEC')
                                and report.get('handoff', {}).get('image') == 'txm'
                                and ctx.elr == 0xfffffe00070a4edc
                                and handoff['linked_pc'] in TXM_WORLD_RETURN_LINKED
                                and len(report.get('txm_world_returns', [])) < 128
                                and sum(previous['linked_pc'] == handoff['linked_pc']
                                    for previous in report.get('txm_world_returns', [])) < 64
                                and handoff['bytes_match'] and handoff['bytes_hex'].startswith('ff0f5fd6')
                                and 0 <= spsr_gl1 < 1 << 32
                                and spsr_gl1 & ~0xf0000000 == 0x13c0)))
                        phase53_eret_candidate = bool(
                            phase53_allocation_trace_state.get('active') or
                            phase53_retype_survey_state.get('active'))
                        phase53_eret = False
                        if phase53_eret_candidate:
                            phase53_filter_state = (
                                phase53_retype_survey_state
                                if phase53_retype_survey_state.get('active')
                                else phase53_allocation_trace_state)
                            phase53_report_key = (
                                'xnu_phase53_retype_survey'
                                if phase53_retype_survey_state.get('active')
                                else 'xnu_phase53_allocation_trace')
                            transition = dict(
                                trap_pc=hex(ctx.elr), target_pc=hex(elr_gl1),
                                target_spsr=hex(spsr_gl1),
                                target_image=handoff.get('image'),
                                target_segment=handoff.get('segment'))
                            target_range = ({
                                'txm': FC_TXM_RUNTIME_TEXT,
                                'kernelcache': FC_XNU_RUNTIME_TEXT,
                            }.get(handoff.get('image')) if classification_ok
                                else None)
                            source_offset = ctx.elr - 4 - FC_IMAGE_BASE
                            source_eret = (sources.get('sptm', b'')[
                                source_offset:source_offset + 4]
                                if 0 <= source_offset <=
                                    len(sources.get('sptm', b'')) - 4 else b'')
                            transition_checks = {
                                'classified': classification_ok,
                                'trap_in_sptm_text':
                                    FC_SPTM_RUNTIME_TEXT[0] <= ctx.elr <
                                        FC_SPTM_RUNTIME_TEXT[1],
                                'source_eret': source_eret == struct.pack(
                                    '<I', FC_XNU_TXM_CONTEXT_ERET_WORD),
                                'target_world': target_range is not None,
                                'target_segment': handoff.get('segment') in
                                    ('__TEXT_EXEC', '__TEXT_BOOT_EXEC'),
                                'target_source_match':
                                    handoff.get('bytes_match') is True,
                                'target_pc_in_range': (target_range is not None and
                                    target_range[0] <= elr_gl1 < target_range[1]),
                                'target_mode': (spsr_gl1 & 15) in (0, 4, 5),
                            }
                            try:
                                prior_status = txm_sstep_fast_path.status()
                                current_range = phase53_filter_state['range0']
                                segment_start = phase53_filter_state[
                                    'segment_start']
                                survey_aggregate = (
                                    phase53_filter_state.get(
                                        'aggregate_steps', 0) +
                                    prior_status['steps'])
                                transition_checks.update(
                                    filter_running=(prior_status['active'] and
                                        prior_status['status'] ==
                                            FC_VEL2_STEP_FILTER_RUNNING),
                                    filter_bounded=(0 < prior_status['steps'] <=
                                        FC_XNU_PHASE53_FAST_STEPS),
                                    filter_last_pc=
                                        prior_status['last_pc'] == ctx.elr - 4,
                                    filter_segment=(
                                        prior_status['first_pc'] == segment_start and
                                        prior_status['expected_first_pc'] ==
                                            segment_start and
                                        prior_status['range0_hits'] +
                                            prior_status['range1_hits'] ==
                                            prior_status['steps']),
                                    filter_contract=(
                                        prior_status['range0_start'] ==
                                            current_range[0] and
                                        prior_status['range0_end'] ==
                                            current_range[1] and
                                        prior_status['range1_start'] ==
                                            FC_SPTM_RUNTIME_TEXT[0] and
                                        prior_status['range1_end'] ==
                                            FC_SPTM_RUNTIME_TEXT[1] and
                                        prior_status['terminal_pc'] ==
                                            phase53_filter_state[
                                                'terminal_pc'] and
                                        prior_status['max_steps'] ==
                                            FC_XNU_PHASE53_FAST_STEPS))
                                if phase53_retype_survey_state.get('active'):
                                    transition_checks.update(
                                        aggregate_budget=(survey_aggregate <=
                                            FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS),
                                        rearm_budget=(phase53_filter_state[
                                            'rearms'] <
                                            FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS))
                                if all(transition_checks.values()):
                                    enabled_status = txm_sstep_fast_path.enable(
                                        target_range, FC_SPTM_RUNTIME_TEXT,
                                        phase53_filter_state[
                                            'terminal_pc'],
                                        FC_XNU_PHASE53_FAST_STEPS, elr_gl1)
                                    phase53_filter_state['range0'] = target_range
                                    phase53_filter_state['segment_start'] = elr_gl1
                                    if phase53_retype_survey_state.get('active'):
                                        phase53_filter_state['aggregate_steps'] = (
                                            survey_aggregate)
                                        phase53_filter_state['rearms'] += 1
                                    transition.update(
                                        source_hex=source_eret.hex(),
                                        prior_status=prior_status,
                                        enable_status=enabled_status,
                                        checks=transition_checks,
                                        complete=True)
                                    phase53_filter_state[
                                        'world_transitions'].append(transition)
                                    report[phase53_report_key][
                                        'world_transitions'] = list(
                                            phase53_filter_state[
                                                'world_transitions'])
                                    if phase53_retype_survey_state.get('active'):
                                        report[phase53_report_key].update(
                                            aggregate_steps=survey_aggregate,
                                            rearms=phase53_filter_state['rearms'])
                                    phase53_eret = True
                                else:
                                    transition.update(
                                        source_hex=source_eret.hex(),
                                        prior_status=prior_status,
                                        checks=transition_checks,
                                        complete=False)
                            except Exception as transition_error:
                                transition_checks['filter_readback'] = False
                                transition.update(
                                    source_hex=source_eret.hex(),
                                    checks=transition_checks,
                                    error=str(transition_error), complete=False)
                            if not phase53_eret:
                                phase53_filter_state['active'] = False
                                report[phase53_report_key][
                                    'world_transition_rejection'] = transition
                                report['stop_reason'] = (
                                    'phase53-world-transition-gate-rejected')
                        txm_context_step = False
                        if (classification_ok and (a.xnu_txm_context_entry_one_step
                                or a.xnu_txm_context_entry_register_prefix
                                or a.xnu_txm_context_stack_claim_one_step
                                or a.xnu_txm_context_stack_metadata_init
                                or a.xnu_txm_context_x18_branch_one_step
                                or a.xnu_txm_context_outbound_branch_one_step
                                or a.xnu_txm_handler_boundary is not None)
                                and ctx.elr == FC_XNU_TXM_CONTEXT_ERET_PC
                                and not entry_launch and not txm_return
                                and not phase53_eret_candidate):
                            def owned_page(pa):
                                if (pa & (PAGE - 1) or
                                        not base <= pa < pa + PAGE <= base + guest_size):
                                    raise ValueError('TXM context-entry table outside owned guest RAM')
                                page = iface.readmem(pa, PAGE)
                                if len(page) != PAGE:
                                    raise ValueError('Truncated TXM context-entry table')
                                return page
                            handler_boundary = a.xnu_txm_handler_boundary
                            outbound = (a.xnu_txm_context_outbound_branch_one_step
                                or handler_boundary is not None)
                            gate_error = None
                            try:
                                target_mapping = translate(elr_gl1, roots['ttbr0'],
                                                           roots['ttbr1'], owned_page)
                                stack_mapping = translate(int(ctx.regs[0]), roots['ttbr0'],
                                                          roots['ttbr1'], owned_page)
                                outbound_mapping = (translate(
                                    FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET,
                                    roots['ttbr0'], roots['ttbr1'], owned_page)
                                    if outbound else None)
                                helper_mapping = (translate(
                                    FC_XNU_TXM_HANDLER_HELPER,
                                    roots['ttbr0'], roots['ttbr1'], owned_page)
                                    if handler_boundary in (
                                        'local-setup', 'validator-entry', 'validator-trace',
                                        'response-trace', 'cmd1-completion-trace')
                                    else None)
                                handler_global_mapping = (translate(
                                    FC_XNU_TXM_HANDLER_GLOBAL,
                                    roots['ttbr0'], roots['ttbr1'], owned_page)
                                    if handler_boundary in (
                                        'validator-entry', 'validator-trace', 'response-trace',
                                        'cmd1-completion-trace')
                                    else None)
                                response_pointer_mapping = (translate(
                                    FC_XNU_TXM_HANDLER_RESPONSE_POINTER,
                                    roots['ttbr0'], roots['ttbr1'], owned_page)
                                    if handler_boundary in (
                                        'response-trace', 'cmd1-completion-trace') else None)
                                pperm = int(u.mrs(HV.MSR_REDIRECTS[SPRR_PPERM_EL1]))
                                uperm = int(u.mrs(HV.MSR_REDIRECTS[SPRR_UPERM_EL0]))
                                mair = int(u.mrs(MAIR_EL12))
                                target_permissions = leaf_permissions(
                                    target_mapping['descriptor'], pperm, uperm, 'guarded')
                                stack_permissions = leaf_permissions(
                                    stack_mapping['descriptor'], pperm, uperm, 'guarded')
                                outbound_permissions = (leaf_permissions(
                                    outbound_mapping['descriptor'], pperm, uperm, 'guarded')
                                    if outbound_mapping is not None else None)
                                helper_permissions = (leaf_permissions(
                                    helper_mapping['descriptor'], pperm, uperm, 'guarded')
                                    if helper_mapping is not None else None)
                                handler_global_permissions = (leaf_permissions(
                                    handler_global_mapping['descriptor'], pperm, uperm, 'guarded')
                                    if handler_global_mapping is not None else None)
                                response_pointer_permissions = (leaf_permissions(
                                    response_pointer_mapping['descriptor'], pperm, uperm,
                                    'guarded') if response_pointer_mapping is not None else None)
                            except Exception as error:
                                target_mapping = stack_mapping = None
                                target_permissions = stack_permissions = None
                                outbound_mapping = outbound_permissions = None
                                helper_mapping = helper_permissions = None
                                handler_global_mapping = handler_global_permissions = None
                                response_pointer_mapping = response_pointer_permissions = None
                                pperm = uperm = mair = None
                                gate_error = str(error)
                            prefix = (a.xnu_txm_context_entry_register_prefix
                                or a.xnu_txm_context_stack_claim_one_step
                                or a.xnu_txm_context_stack_metadata_init
                                or a.xnu_txm_context_x18_branch_one_step
                                or a.xnu_txm_context_outbound_branch_one_step
                                or handler_boundary is not None)
                            claim = (a.xnu_txm_context_stack_claim_one_step
                                or a.xnu_txm_context_stack_metadata_init
                                or a.xnu_txm_context_x18_branch_one_step
                                or a.xnu_txm_context_outbound_branch_one_step
                                or handler_boundary is not None)
                            metadata = (a.xnu_txm_context_stack_metadata_init
                                or a.xnu_txm_context_x18_branch_one_step
                                or a.xnu_txm_context_outbound_branch_one_step
                                or handler_boundary is not None)
                            x18_branch = (a.xnu_txm_context_x18_branch_one_step
                                or a.xnu_txm_context_outbound_branch_one_step
                                or handler_boundary is not None)
                            target_bytes = bytes.fromhex(handoff.get('bytes_hex', ''))
                            sptm_segment = layout.get('images', {}).get('sptm', {}).get(
                                'segments', {}).get('__TEXT_EXEC', {})
                            sptm_source_offset = FC_XNU_TXM_CONTEXT_ERET_PC - 4 - FC_IMAGE_BASE
                            sptm_source_in_segment = (sptm_segment.get('fileoff', 0)
                                <= sptm_source_offset
                                and sptm_source_offset + 4 <= sptm_segment.get('fileoff', 0)
                                    + sptm_segment.get('filesize', 0))
                            source_eret = (sources.get('sptm', b'')[
                                sptm_source_offset:sptm_source_offset + 4]
                                if sptm_source_in_segment else b'')
                            txm_segment = layout.get('images', {}).get('txm', {}).get(
                                'segments', {}).get('__TEXT_EXEC', {})
                            outbound_source_offset = (txm_segment.get('fileoff', 0)
                                + FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED
                                - txm_segment.get('va', 0))
                            outbound_source_in_segment = (
                                txm_segment.get('va', 0)
                                    <= FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED
                                and FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED
                                    + len(FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)
                                    <= txm_segment.get('va', 0)
                                        + txm_segment.get('filesize', 0))
                            handler_source_size = ({
                                'local-setup': FC_XNU_TXM_HANDLER_LOCAL_SETUP_SIZE,
                                'validator-entry': FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE,
                                'validator-trace': FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE,
                                'response-trace': FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE,
                                'cmd1-completion-trace':
                                    FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE,
                            }.get(handler_boundary,
                                len(FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)))
                            outbound_source = sources.get('txm', b'')[
                                outbound_source_offset:outbound_source_offset
                                    + handler_source_size]
                            helper_source_offset = (txm_segment.get('fileoff', 0)
                                + FC_XNU_TXM_HANDLER_HELPER_LINKED
                                - txm_segment.get('va', 0))
                            helper_source = sources.get('txm', b'')[
                                helper_source_offset:helper_source_offset
                                    + len(FC_XNU_TXM_HANDLER_HELPER_BYTES)]
                            txm_prefix_source_offset = (txm_segment.get('fileoff', 0)
                                + int(FC_XNU_TXM_CONTEXT_LINKED, 16) + 4
                                - txm_segment.get('va', 0))
                            prefix_source = sources.get('txm', b'')[txm_prefix_source_offset:
                                txm_prefix_source_offset
                                    + len(FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES)]
                            claim_source_offset = (txm_prefix_source_offset
                                + len(FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES))
                            claim_source = sources.get('txm', b'')[
                                claim_source_offset:claim_source_offset + 4]
                            post_claim_source_offset = claim_source_offset + 4
                            post_claim_source = sources.get('txm', b'')[
                                post_claim_source_offset:post_claim_source_offset
                                    + len(FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES)]
                            x18_window_source_offset = (post_claim_source_offset
                                + len(FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES) - 4)
                            x18_window_source = sources.get('txm', b'')[
                                x18_window_source_offset:x18_window_source_offset
                                    + len(FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES)]
                            stack_owned_leaf = (stack_mapping is not None
                                and stack_mapping['level'] == 3
                                and stack_mapping['access_flag']
                                and not stack_mapping['read_only']
                                and stack_mapping['user_access']
                                and stack_mapping['pa'] & (PAGE - 1) == 0
                                and base <= stack_mapping['pa']
                                and stack_mapping['pa'] + PAGE <= base + guest_size)
                            outbound_owned_leaf = (outbound_mapping is not None
                                and outbound_mapping['level'] == 3
                                and outbound_mapping['access_flag']
                                and outbound_mapping['read_only']
                                and not outbound_mapping['pxn']
                                and base <= outbound_mapping['pa']
                                and (outbound_mapping['pa']
                                    + handler_source_size
                                    <= base + guest_size)
                                and ((outbound_mapping['pa'] & (PAGE - 1))
                                    + handler_source_size <= PAGE))
                            outbound_live_bytes = (iface.readmem(outbound_mapping['pa'],
                                    handler_source_size)
                                if outbound and outbound_owned_leaf else None)
                            helper_owned_leaf = (helper_mapping is not None
                                and helper_mapping['level'] == 3
                                and helper_mapping['access_flag']
                                and helper_mapping['read_only']
                                and not helper_mapping['pxn']
                                and base <= helper_mapping['pa']
                                and helper_mapping['pa'] + len(FC_XNU_TXM_HANDLER_HELPER_BYTES)
                                    <= base + guest_size
                                and ((helper_mapping['pa'] & (PAGE - 1))
                                    + len(FC_XNU_TXM_HANDLER_HELPER_BYTES) <= PAGE))
                            helper_live_bytes = (iface.readmem(helper_mapping['pa'],
                                    len(FC_XNU_TXM_HANDLER_HELPER_BYTES))
                                if helper_owned_leaf else None)
                            handler_global_owned_leaf = (handler_global_mapping is not None
                                and handler_global_mapping['level'] == 3
                                and handler_global_mapping['access_flag']
                                and base <= handler_global_mapping['pa'] < base + guest_size)
                            handler_global_before = (iface.readmem(
                                    handler_global_mapping['pa'], 1)
                                if handler_global_owned_leaf else None)
                            response_pointer_owned_leaf = (response_pointer_mapping is not None
                                and response_pointer_mapping['level'] == 3
                                and response_pointer_mapping['access_flag']
                                and base <= response_pointer_mapping['pa']
                                    <= base + guest_size - 8)
                            response_pointer_before = (iface.readmem(
                                    response_pointer_mapping['pa'], 8)
                                if response_pointer_owned_leaf else None)
                            first_touch_pa = (stack_mapping['pa'] + PAGE - 0x400 + 0x58
                                if stack_owned_leaf else None)
                            metadata_frame_pa = (stack_mapping['pa'] + PAGE - 0x400
                                if stack_owned_leaf else None)
                            claim_before = (iface.readmem(first_touch_pa, 1)
                                if claim and first_touch_pa is not None else None)
                            metadata_page_before = (iface.readmem(stack_mapping['pa'], PAGE)
                                if metadata and stack_owned_leaf else None)
                            metadata_offsets = dict(state=0, zero_word=4,
                                                    claim=0x58, zero_byte=0x79)
                            metadata_before = ({name: metadata_page_before[
                                    PAGE - 0x400 + offset:
                                    PAGE - 0x400 + offset + (4 if name == 'zero_word' else 1)]
                                for name, offset in metadata_offsets.items()}
                                if metadata_page_before is not None else {})
                            checks = {
                                'verified_xnu_handoff': (handoff_state.get('native')
                                    and report.get('handoff', {}).get('image') == 'kernelcache'
                                    and report.get('handoff', {}).get('instructions_executed') is True),
                                'trap_pc': ctx.elr == FC_XNU_TXM_CONTEXT_ERET_PC,
                                'source_eret': source_eret == struct.pack(
                                    '<I', FC_XNU_TXM_CONTEXT_ERET_WORD),
                                'caller_pstate': int(ctx.spsr) & ~0xf0000000 == 0x13c5,
                                'caller_x3': int(ctx.regs[3]) == 0,
                                'caller_selector_x16': int(ctx.regs[16]) == FC_XNU_TXM_CONTEXT_SELECTOR,
                                'caller_x18': int(ctx.regs[18]) == FC_XNU_TXM_CONTEXT_X18,
                                'target_pc': elr_gl1 == FC_XNU_TXM_CONTEXT_TARGET,
                                'target_spsr': spsr_gl1 == 0x13c0,
                                'target_image': handoff.get('image') == 'txm',
                                'target_segment': handoff.get('segment') == '__TEXT_EXEC',
                                'target_linked_pc': handoff.get('linked_pc') == FC_XNU_TXM_CONTEXT_LINKED,
                                'target_source_match': handoff.get('bytes_match') is True,
                                'target_bytes': target_bytes == FC_XNU_TXM_CONTEXT_BYTES,
                                'target_sha256': hashlib.sha256(target_bytes).hexdigest()
                                    == FC_XNU_TXM_CONTEXT_SHA256,
                                'stack_x0': int(ctx.regs[0]) == FC_XNU_TXM_CONTEXT_STACK,
                                'stack_aligned': int(ctx.regs[0]) & (PAGE - 1) == 0,
                                'target_mapping': (target_mapping is not None
                                    and target_mapping['level'] == 3
                                    and target_mapping['access_flag']
                                    and target_mapping['read_only']
                                    and not target_mapping['pxn']
                                    and base <= target_mapping['pa'] < base + guest_size),
                                'target_normal_wb': (target_mapping is not None and mair is not None
                                    and (mair >> (((target_mapping['descriptor'] >> 2) & 7) * 8))
                                        & 0xff == 0xff),
                                'target_no_hierarchical_restriction': (target_mapping is not None
                                    and target_permissions is not None
                                    and all(target_mapping[name] == target_permissions['native'][name]
                                        for name in ('read_only', 'user_access', 'pxn', 'uxn'))),
                                'target_guarded_gl0_rx': (target_permissions is not None
                                    and target_permissions['user_read']
                                    and not target_permissions['user_write']
                                    and target_permissions['user_execute']),
                                'stack_mapping': stack_owned_leaf,
                                'stack_normal_wb': (stack_mapping is not None and mair is not None
                                    and (mair >> (((stack_mapping['descriptor'] >> 2) & 7) * 8))
                                        & 0xff == 0xff),
                                'stack_no_hierarchical_restriction': (stack_mapping is not None
                                    and stack_permissions is not None
                                    and all(stack_mapping[name] == stack_permissions['native'][name]
                                        for name in ('read_only', 'user_access', 'pxn', 'uxn'))),
                                'stack_guarded_gl0_rw': (stack_permissions is not None
                                    and stack_permissions['user_read']
                                    and stack_permissions['user_write']
                                    and not stack_permissions['user_execute']),
                            }
                            if prefix:
                                checks['register_prefix_source'] = (
                                    prefix_source == FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES
                                    and hashlib.sha256(prefix_source).hexdigest()
                                        == FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_SHA256)
                            if claim:
                                checks['stack_claim_source'] = claim_source == struct.pack(
                                    '<I', FC_XNU_TXM_CONTEXT_CASB_WORD)
                                checks['stack_claim_initial_zero'] = claim_before == b'\x00'
                            if metadata:
                                checks['post_claim_source'] = (
                                    post_claim_source == FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES
                                    and hashlib.sha256(post_claim_source).hexdigest()
                                        == FC_XNU_TXM_CONTEXT_POST_CLAIM_SHA256)
                                checks['metadata_frame_in_stack_page'] = (
                                    metadata_frame_pa is not None
                                    and stack_mapping['pa'] <= metadata_frame_pa
                                    and metadata_frame_pa + 0x7a
                                        <= stack_mapping['pa'] + PAGE)
                                checks['metadata_initial_zero'] = (
                                    metadata_before.get('state') == b'\x00'
                                    and metadata_before.get('zero_word') == b'\x00' * 4
                                    and metadata_before.get('claim') == b'\x00'
                                    and metadata_before.get('zero_byte') == b'\x00')
                            if x18_branch:
                                checks['x18_branch_source'] = (
                                    x18_window_source == FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES
                                    and hashlib.sha256(x18_window_source).hexdigest()
                                        == FC_XNU_TXM_CONTEXT_X18_WINDOW_SHA256
                                    and x18_window_source[:4] == struct.pack(
                                        '<I', FC_XNU_TXM_CONTEXT_X18_CBNZ_WORD)
                                    and x18_window_source[-4:] == struct.pack(
                                        '<I', FC_XNU_TXM_CONTEXT_OUTBOUND_BRANCH_WORD))
                            if outbound:
                                checks['outbound_target_source'] = (
                                    outbound_source_in_segment
                                    and outbound_source[:len(
                                        FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)]
                                        == FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES
                                    and hashlib.sha256(outbound_source[:len(
                                        FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)]).hexdigest()
                                        == FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_SHA256)
                                branch_imm26 = FC_XNU_TXM_CONTEXT_OUTBOUND_BRANCH_WORD & 0x3ffffff
                                branch_delta = ((branch_imm26 ^ 0x2000000) - 0x2000000) << 2
                                checks['outbound_branch_target'] = (
                                    FC_XNU_TXM_CONTEXT_TARGET + 0x7c + branch_delta
                                        == FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET)
                                checks['outbound_target_mapping'] = outbound_owned_leaf
                                checks['outbound_target_normal_wb'] = (
                                    outbound_mapping is not None and mair is not None
                                    and (mair >> (((outbound_mapping['descriptor'] >> 2) & 7) * 8))
                                        & 0xff == 0xff)
                                checks['outbound_target_no_hierarchical_restriction'] = (
                                    outbound_mapping is not None
                                    and outbound_permissions is not None
                                    and all(outbound_mapping[name]
                                        == outbound_permissions['native'][name]
                                        for name in ('read_only', 'user_access', 'pxn', 'uxn')))
                                checks['outbound_target_guarded_gl0_rx'] = (
                                    outbound_permissions is not None
                                    and outbound_permissions['user_read']
                                    and not outbound_permissions['user_write']
                                    and outbound_permissions['user_execute'])
                                checks['outbound_target_live_bytes'] = (
                                    outbound_live_bytes is not None
                                    and outbound_live_bytes[:len(
                                        FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)]
                                        == FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES
                                    and outbound_live_bytes == outbound_source
                                    and hashlib.sha256(outbound_live_bytes[:len(
                                        FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)]).hexdigest()
                                        == FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_SHA256)
                            if handler_boundary is not None:
                                checks['handler_prologue_source'] = (
                                    outbound_source[:12] == FC_XNU_TXM_HANDLER_PROLOGUE_BYTES
                                    and outbound_live_bytes is not None
                                    and outbound_live_bytes[:12]
                                        == FC_XNU_TXM_HANDLER_PROLOGUE_BYTES
                                    and hashlib.sha256(outbound_live_bytes[:12]).hexdigest()
                                        == FC_XNU_TXM_HANDLER_PROLOGUE_SHA256)
                            if handler_boundary in (
                                    'local-setup', 'validator-entry', 'validator-trace',
                                    'response-trace', 'cmd1-completion-trace'):
                                checks['handler_local_setup_source'] = (
                                    len(outbound_source) >= FC_XNU_TXM_HANDLER_LOCAL_SETUP_SIZE
                                    and outbound_live_bytes == outbound_source
                                    and hashlib.sha256(outbound_source[:
                                        FC_XNU_TXM_HANDLER_LOCAL_SETUP_SIZE]).hexdigest()
                                        == FC_XNU_TXM_HANDLER_LOCAL_SETUP_SHA256)
                                checks['handler_helper_source'] = (
                                    helper_source == FC_XNU_TXM_HANDLER_HELPER_BYTES
                                    and hashlib.sha256(helper_source).hexdigest()
                                        == FC_XNU_TXM_HANDLER_HELPER_SHA256)
                                checks['handler_helper_mapping'] = helper_owned_leaf
                                checks['handler_helper_guarded_gl0_rx'] = (
                                    helper_permissions is not None
                                    and helper_permissions['user_read']
                                    and not helper_permissions['user_write']
                                    and helper_permissions['user_execute'])
                                checks['handler_helper_live_bytes'] = (
                                    helper_live_bytes == FC_XNU_TXM_HANDLER_HELPER_BYTES
                                    and helper_live_bytes == helper_source)
                            if handler_boundary in (
                                    'validator-entry', 'validator-trace', 'response-trace',
                                    'cmd1-completion-trace'):
                                checks['handler_validator_entry_source'] = (
                                    len(outbound_source)
                                        == FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE
                                    and hashlib.sha256(outbound_source).hexdigest()
                                        == FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SHA256)
                                checks['handler_global_mapping'] = handler_global_owned_leaf
                                checks['handler_global_guarded_gl0_read'] = (
                                    handler_global_permissions is not None
                                    and handler_global_permissions['user_read'])
                                checks['handler_global_initial_zero'] = (
                                    handler_global_before == b'\x00')
                            if handler_boundary in (
                                    'response-trace', 'cmd1-completion-trace'):
                                checks['handler_response_pointer_mapping'] = (
                                    response_pointer_owned_leaf)
                                checks['handler_response_pointer_guarded_gl0_read'] = (
                                    response_pointer_permissions is not None
                                    and response_pointer_permissions['user_read'])
                                checks['handler_response_pointer_read'] = (
                                    response_pointer_before is not None
                                    and len(response_pointer_before) == 8)
                            classification['checks'] = checks
                            if gate_error is not None:
                                classification['gate_error'] = gate_error
                            gate = dict(enabled=True, checks=checks,
                                trap_pc=hex(ctx.elr), target_pc=hex(elr_gl1),
                                target_spsr=hex(spsr_gl1), x0=hex(int(ctx.regs[0])),
                                x3=hex(int(ctx.regs[3])), x16=hex(int(ctx.regs[16])),
                                target_mapping=target_mapping, stack_mapping=stack_mapping,
                                target_guarded_permissions=target_permissions,
                                stack_guarded_permissions=stack_permissions,
                                pperm_el1=pperm, uperm_el0=uperm, mair_el12=mair,
                                expected_next_pc=hex(FC_XNU_TXM_CONTEXT_TARGET + 4),
                                expected_sp_el0=hex(FC_XNU_TXM_CONTEXT_STACK))
                            if claim:
                                gate.update(claim_va=hex(FC_XNU_TXM_CONTEXT_STACK
                                    + PAGE - 0x400 + 0x58),
                                    claim_pa=(hex(first_touch_pa)
                                        if first_touch_pa is not None else None),
                                    claim_before_hex=(claim_before.hex()
                                        if claim_before is not None else None))
                            if metadata:
                                gate.update(metadata_frame_va=hex(
                                        FC_XNU_TXM_CONTEXT_STACK + PAGE - 0x400),
                                    metadata_frame_pa=(hex(metadata_frame_pa)
                                        if metadata_frame_pa is not None else None),
                                    metadata_before_hex={name: value.hex()
                                        for name, value in metadata_before.items()},
                                    metadata_page_before_sha256=(hashlib.sha256(
                                        metadata_page_before).hexdigest()
                                        if metadata_page_before is not None else None),
                                    metadata_writes=[
                                        dict(va=hex(FC_XNU_TXM_CONTEXT_STACK + PAGE
                                                - 0x400 + 4),
                                             pa=(hex(metadata_frame_pa + 4)
                                                 if metadata_frame_pa is not None else None),
                                             width=4, value_hex='00000000'),
                                        dict(va=hex(FC_XNU_TXM_CONTEXT_STACK + PAGE
                                                - 0x400 + 0x79),
                                             pa=(hex(metadata_frame_pa + 0x79)
                                                 if metadata_frame_pa is not None else None),
                                             width=1, value_hex='00'),
                                        dict(va=hex(FC_XNU_TXM_CONTEXT_STACK + PAGE - 0x400),
                                             pa=(hex(metadata_frame_pa)
                                                 if metadata_frame_pa is not None else None),
                                             width=1, value_hex='01')])
                            if x18_branch:
                                gate.update(
                                    x18_branch_pc=hex(FC_XNU_TXM_CONTEXT_TARGET + 0x6c),
                                    x18_branch_linked=hex(
                                        int(FC_XNU_TXM_CONTEXT_LINKED, 16) + 0x6c),
                                    x18_branch_word=hex(FC_XNU_TXM_CONTEXT_X18_CBNZ_WORD),
                                    x18_taken_target_pc=hex(
                                        FC_XNU_TXM_CONTEXT_TARGET + 0x7c),
                                    x18_taken_target_linked=hex(
                                        int(FC_XNU_TXM_CONTEXT_LINKED, 16) + 0x7c),
                                    x18_taken_target_word=hex(
                                        FC_XNU_TXM_CONTEXT_OUTBOUND_BRANCH_WORD),
                                    expected_fallthrough_skipped=True,
                                    expected_stop_before_outbound_branch=True)
                            if outbound:
                                gate.update(
                                    outbound_target_pc=hex(
                                        FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET),
                                    outbound_target_linked=hex(
                                        FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED),
                                    outbound_target_mapping=outbound_mapping,
                                    outbound_target_guarded_permissions=outbound_permissions,
                                    outbound_target_sha256=
                                        FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_SHA256,
                                    outbound_target_live_bytes_hex=(
                                        outbound_live_bytes.hex()
                                        if outbound_live_bytes is not None else None),
                                    outbound_target_live_sha256=(hashlib.sha256(
                                        outbound_live_bytes).hexdigest()
                                        if outbound_live_bytes is not None else None),
                                    expected_stop_before_pacibsp=True)
                            if handler_boundary is not None:
                                terminal_offset = {'prologue': 8, 'register-saves': 0x20,
                                                   'local-setup': 0x44,
                                                   'validator-entry': 0xa0,
                                                   'validator-trace': 0xa4,
                                                   'response-trace': 0x4b4,
                                                   'cmd1-completion-trace': 0x4b4}[handler_boundary]
                                gate.update(
                                    boundary=handler_boundary,
                                    handler_entry_pc=hex(
                                        FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET),
                                    handler_prologue_sha256=
                                        FC_XNU_TXM_HANDLER_PROLOGUE_SHA256,
                                    expected_terminal_pc=hex(
                                        FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET
                                            + terminal_offset),
                                    expected_terminal_sp=hex(
                                        FC_XNU_TXM_CONTEXT_STACK + PAGE - 0x400 - 0x70))
                                if handler_boundary == 'prologue':
                                    gate['expected_stop_before_first_stp'] = True
                                elif handler_boundary == 'register-saves':
                                    gate.update(expected_saved_register_pairs=5,
                                                expected_stop_before_argument_moves=True)
                                elif handler_boundary == 'local-setup':
                                    gate.update(
                                        handler_local_setup_sha256=
                                            FC_XNU_TXM_HANDLER_LOCAL_SETUP_SHA256,
                                        handler_helper_pc=hex(FC_XNU_TXM_HANDLER_HELPER),
                                        handler_helper_sha256=
                                            FC_XNU_TXM_HANDLER_HELPER_SHA256,
                                        expected_local_marker_va=hex(
                                            FC_XNU_TXM_CONTEXT_STACK + PAGE - 0x400
                                                - 0x70 + 0x18),
                                        expected_stop_before_global_adrp=True)
                                else:
                                    gate.update(
                                        handler_validator_entry_sha256=
                                            FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SHA256,
                                        handler_global_va=hex(FC_XNU_TXM_HANDLER_GLOBAL),
                                        handler_global_mapping=handler_global_mapping,
                                        handler_global_guarded_permissions=
                                            handler_global_permissions,
                                        handler_global_before_hex=(
                                            handler_global_before.hex()
                                            if handler_global_before is not None else None),
                                        expected_validator_selector=0x2d,
                                        expected_stop_before_validator_call=True)
                                    if handler_boundary in (
                                            'response-trace', 'cmd1-completion-trace'):
                                        gate.update(
                                            response_pointer_va=hex(
                                                FC_XNU_TXM_HANDLER_RESPONSE_POINTER),
                                            response_pointer_mapping=response_pointer_mapping,
                                            response_pointer_before_hex=(
                                                response_pointer_before.hex()
                                                if response_pointer_before is not None else None),
                                            expected_response_stop=hex(
                                                FC_XNU_TXM_HANDLER_RESPONSE_STOP),
                                            expected_stop_before_completion_call=True)
                            report_key = ('xnu_txm_handler_boundary'
                                if handler_boundary is not None
                                else ('xnu_txm_context_outbound_branch_one_step' if outbound
                                else ('xnu_txm_context_x18_branch_one_step' if x18_branch
                                else ('xnu_txm_context_stack_metadata_init' if metadata
                                else ('xnu_txm_context_stack_claim_one_step' if claim
                                else ('xnu_txm_context_entry_register_prefix' if prefix
                                      else 'xnu_txm_context_entry_one_step'))))))
                            report[report_key] = gate
                            if all(checks.values()):
                                txm_context_step = True
                                classification['decision'] = ('txm-handler-' + handler_boundary
                                    if handler_boundary is not None
                                    else ('txm-context-outbound-branch-one-step'
                                    if outbound else ('txm-context-x18-branch-one-step'
                                    if x18_branch else ('txm-context-stack-metadata-init'
                                    if metadata else ('txm-context-stack-claim'
                                    if claim else ('txm-context-register-prefix'
                                                   if prefix else 'txm-context-one-step'))))))
                            else:
                                report['stop_reason'] = 'txm-context-entry-gate-rejected'
                        if completion_eret:
                            classification['decision'] = 'cmd1-completion-eret'
                            report['xnu_txm_sstep_fast_path'][
                                'completion_eret'] = dict(
                                    trap_pc=hex(ctx.elr), target_pc=hex(elr_gl1),
                                    target_spsr=hex(spsr_gl1),
                                    guarded_esr=hex(completion_guarded_esr),
                                    guarded_aspsr=hex(completion_guarded_aspsr),
                                    status=completion_fast_status,
                                    checks_passed=True)
                            report['stop_reason'] = 'cmd1-completion-eret'
                        elif phase53_eret:
                            classification['decision'] = 'phase53-world-transition'
                            report['stop_reason'] = 'phase53-world-transition'
                        elif entry_launch:
                            classification['decision'] = 'entry-launch'
                            report['handoff'] = eret_record
                            report['stop_reason'] = 'handoff-' + ('xnu' if handoff['image'] == 'kernelcache' else 'txm') + '-entry'
                        elif txm_return:
                            classification['decision'] = 'txm-world-return'
                            report.setdefault('txm_world_returns', []).append(eret_record)
                            report['stop_reason'] = 'txm-world-return'
                        if txm_context_step:
                            stack = FC_XNU_TXM_CONTEXT_STACK
                            expected_states = [
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x04, sp=stack,
                                     regs={0: stack}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x08, sp=stack, regs={0: 1}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x0c, sp=stack, regs={0: 1}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x10, sp=stack, regs={0: 1}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x14, sp=stack,
                                     regs={0: 1, 8: stack}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x18, sp=stack,
                                     regs={0: 1, 8: 0}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x28, sp=stack,
                                     regs={0: 1, 8: 0}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x2c, sp=stack,
                                     regs={0: 1, 8: stack}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x30, sp=stack,
                                     regs={0: 1, 8: stack}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x34, sp=stack,
                                     regs={0: 1, 8: stack + PAGE}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x38, sp=stack,
                                     regs={0: 1, 8: stack + PAGE - 0x400}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x3c,
                                     sp=stack + PAGE - 0x400,
                                     regs={0: 1, 8: stack + PAGE - 0x400}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x40,
                                     sp=stack + PAGE - 0x400,
                                     regs={0: 1, 8: stack + PAGE - 0x400 + 0x58}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x44,
                                     sp=stack + PAGE - 0x400,
                                     regs={0: 1, 8: stack + PAGE - 0x400 + 0x58, 9: 0}),
                                dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x48,
                                     sp=stack + PAGE - 0x400,
                                     regs={0: 1, 8: stack + PAGE - 0x400 + 0x58,
                                           9: 0, 10: 1}),
                            ]
                            for state_index, state in enumerate(expected_states):
                                state['spsr'] = (0x13c0 if state_index < 2 else 0x200013c0)
                            if claim:
                                expected_states.append(dict(
                                    pc=FC_XNU_TXM_CONTEXT_TARGET + 0x4c,
                                    sp=stack + PAGE - 0x400, spsr=0x200013c0,
                                    regs={0: 1, 8: stack + PAGE - 0x400 + 0x58,
                                          9: 0, 10: 1},
                                    memory={'claim': '01'}))
                            if metadata:
                                frame = stack + PAGE - 0x400
                                common = {0: 1, 8: frame + 0x58, 9: 0, 10: 1}
                                expected_states.extend([
                                    dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x5c,
                                         sp=frame, spsr=0x200013c0,
                                         regs=dict(common), memory={'claim': '01'}),
                                    dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x60,
                                         sp=frame, spsr=0x200013c0,
                                         regs=dict(common),
                                         memory={'claim': '01', 'zero_word': '00000000'}),
                                    dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x64,
                                         sp=frame, spsr=0x200013c0,
                                         regs=dict(common),
                                         memory={'claim': '01', 'zero_word': '00000000',
                                                 'zero_byte': '00'}),
                                    dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x68,
                                         sp=frame, spsr=0x200013c0,
                                         regs={0: 1, 8: 1, 9: 0, 10: 1},
                                         memory={'claim': '01', 'zero_word': '00000000',
                                                 'zero_byte': '00'}),
                                    dict(pc=FC_XNU_TXM_CONTEXT_TARGET + 0x6c,
                                         sp=frame, spsr=0x200013c0,
                                         regs={0: 1, 8: 1, 9: 0, 10: 1},
                                         memory={'state': '01', 'claim': '01',
                                                 'zero_word': '00000000',
                                                 'zero_byte': '00'}),
                                ])
                            if x18_branch:
                                expected_states.append(dict(
                                    pc=FC_XNU_TXM_CONTEXT_TARGET + 0x7c,
                                    sp=frame, spsr=0x200013c0,
                                    regs={0: 1, 8: 1, 9: 0, 10: 1},
                                    memory={'state': '01', 'claim': '01',
                                            'zero_word': '00000000',
                                            'zero_byte': '00'}))
                            if outbound:
                                outbound_state = dict(
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET,
                                    sp=frame, spsr=0x200013c0,
                                    regs={0: 1, 8: 1, 9: 0, 10: 1},
                                    memory={'state': '01', 'claim': '01',
                                            'zero_word': '00000000',
                                            'zero_byte': '00'})
                                if handler_boundary is not None:
                                    outbound_state['capture_regs'] = tuple(range(30))
                                expected_states.append(outbound_state)
                            if handler_boundary is not None:
                                expected_states.extend([
                                    dict(pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 4,
                                         sp=frame, spsr=0x200013c0,
                                         regs={0: 1, 8: 1, 9: 0, 10: 1},
                                         capture_regs=(30,),
                                         same_captured_regs=tuple(range(30)),
                                         memory={'state': '01', 'claim': '01',
                                                 'zero_word': '00000000',
                                                 'zero_byte': '00'}),
                                    dict(pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 8,
                                         sp=frame - 0x70, spsr=0x200013c0,
                                         regs={0: 1, 8: 1, 9: 0, 10: 1},
                                         same_captured_regs=tuple(range(31)),
                                         memory={'state': '01', 'claim': '01',
                                                 'zero_word': '00000000',
                                                 'zero_byte': '00'}),
                                ])
                            if handler_boundary in (
                                    'register-saves', 'local-setup', 'validator-entry',
                                    'validator-trace', 'response-trace',
                                    'cmd1-completion-trace'):
                                handler_sp = frame - 0x70
                                handler_memory = {'state': '01', 'claim': '01',
                                                  'zero_word': '00000000',
                                                  'zero_byte': '00'}
                                for pair_index in range(5):
                                    expected_states.append(dict(
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET
                                            + 0x0c + pair_index * 4,
                                        sp=handler_sp, spsr=0x200013c0,
                                        regs={0: 1, 8: 1, 9: 0, 10: 1},
                                        same_captured_regs=tuple(range(31)),
                                        saved_pairs=pair_index + 1,
                                        memory=dict(handler_memory)))
                                expected_states.append(dict(
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x20,
                                    sp=handler_sp, spsr=0x200013c0,
                                    regs={0: 1, 8: 1, 9: 0, 10: 1,
                                          29: handler_sp + 0x60},
                                    same_captured_regs=tuple(
                                        register for register in range(31)
                                        if register != 29),
                                    saved_pairs=5, memory=dict(handler_memory)))
                            if handler_boundary in (
                                    'local-setup', 'validator-entry', 'validator-trace',
                                    'response-trace', 'cmd1-completion-trace'):
                                moved = {}
                                for offset, destination, source in (
                                        (0x24, 23, 5), (0x28, 24, 4),
                                        (0x2c, 22, 3), (0x30, 21, 2),
                                        (0x34, 20, 1), (0x38, 25, 0)):
                                    moved[destination] = source
                                    expected_states.append(dict(
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + offset,
                                        sp=handler_sp, spsr=0x200013c0,
                                        regs={29: handler_sp + 0x60},
                                        same_captured_regs=tuple(
                                            register for register in range(31)
                                            if register not in set(moved) | {29}),
                                        captured_reg_values=dict(moved), saved_pairs=5,
                                        memory=dict(handler_memory)))
                                return_pc = FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x3c
                                common_helper = dict(
                                    sp=handler_sp, spsr=0x200013c0,
                                    same_captured_regs=tuple(
                                        register for register in range(31)
                                        if register not in set(moved) | {29, 30}),
                                    captured_reg_values=dict(moved), saved_pairs=5,
                                    memory=dict(handler_memory))
                                helper_states = (
                                    (FC_XNU_TXM_HANDLER_HELPER, 1),
                                    (FC_XNU_TXM_HANDLER_HELPER + 4, 1),
                                    (FC_XNU_TXM_HANDLER_HELPER + 8, handler_sp),
                                    (FC_XNU_TXM_HANDLER_HELPER + 0x0c, stack),
                                    (FC_XNU_TXM_HANDLER_HELPER + 0x10, stack + PAGE),
                                    (FC_XNU_TXM_HANDLER_HELPER + 0x14, frame),
                                    (return_pc, frame),
                                )
                                for helper_index, (helper_pc, x0_value) in enumerate(
                                        helper_states):
                                    state = dict(common_helper)
                                    state.update(pc=helper_pc,
                                        regs={0: x0_value, 29: handler_sp + 0x60,
                                              30: return_pc})
                                    if helper_index >= 2:
                                        state['same_captured_regs'] = tuple(
                                            register for register in
                                                state['same_captured_regs'] if register != 0)
                                    expected_states.append(state)
                                post_helper_preserved = tuple(
                                    register for register in
                                        common_helper['same_captured_regs']
                                    if register not in (0, 8))
                                expected_states.append(dict(common_helper,
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x40,
                                    regs={0: frame, 8: 1, 29: handler_sp + 0x60,
                                          30: return_pc},
                                    same_captured_regs=post_helper_preserved))
                                local_memory = dict(handler_memory)
                                local_memory['local_marker'] = '0100000000000000'
                                expected_states.append(dict(common_helper,
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x44,
                                    regs={0: frame, 8: 1, 29: handler_sp + 0x60,
                                          30: return_pc}, memory=local_memory,
                                    same_captured_regs=post_helper_preserved))
                            if handler_boundary in (
                                    'validator-entry', 'validator-trace', 'response-trace',
                                    'cmd1-completion-trace'):
                                global_page = FC_XNU_TXM_HANDLER_GLOBAL & ~(PAGE - 1)
                                validator_preserved = tuple(register for register in
                                    post_helper_preserved if register != 26)
                                validator_common = dict(
                                    sp=handler_sp, saved_pairs=5,
                                    captured_reg_values=dict(moved),
                                    memory=local_memory)
                                expected_states.extend([
                                    dict(validator_common,
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x48,
                                        spsr=0x200013c0,
                                        regs={0: frame, 8: 1, 26: global_page,
                                              29: handler_sp + 0x60, 30: return_pc},
                                        same_captured_regs=validator_preserved),
                                    dict(validator_common,
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x4c,
                                        spsr=0x200013c0,
                                        regs={0: frame, 8: 1,
                                              26: FC_XNU_TXM_HANDLER_GLOBAL,
                                              29: handler_sp + 0x60, 30: return_pc},
                                        same_captured_regs=validator_preserved),
                                    dict(validator_common,
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x50,
                                        spsr=0x200013c0,
                                        regs={0: frame, 8: 0,
                                              26: FC_XNU_TXM_HANDLER_GLOBAL,
                                              29: handler_sp + 0x60, 30: return_pc},
                                        same_captured_regs=validator_preserved),
                                ])
                                route_preserved = tuple(register for register in
                                    validator_preserved if register != 9)
                                expected_states.extend([
                                    dict(validator_common,
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x54,
                                        spsr=0x200013c0,
                                        regs={0: frame, 8: 0,
                                              26: FC_XNU_TXM_HANDLER_GLOBAL,
                                              29: handler_sp + 0x60, 30: return_pc},
                                        same_captured_regs=validator_preserved),
                                    dict(validator_common,
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x58,
                                        spsr=0x200013c0,
                                        regs={0: frame, 8: 0, 9: handler_sp + 0x18,
                                              26: FC_XNU_TXM_HANDLER_GLOBAL,
                                              29: handler_sp + 0x60, 30: return_pc},
                                        same_captured_regs=route_preserved),
                                    dict(validator_common,
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x5c,
                                        spsr=0x800013c0,
                                        regs={0: frame, 8: stack, 9: handler_sp + 0x18,
                                              26: FC_XNU_TXM_HANDLER_GLOBAL,
                                              29: handler_sp + 0x60, 30: return_pc},
                                        same_captured_regs=route_preserved),
                                    dict(validator_common,
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x74,
                                        spsr=0x800013c0,
                                        regs={0: frame, 8: stack, 9: handler_sp + 0x18,
                                              26: FC_XNU_TXM_HANDLER_GLOBAL,
                                              29: handler_sp + 0x60, 30: return_pc},
                                        same_captured_regs=route_preserved),
                                    dict(validator_common,
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x78,
                                        spsr=0x800013c0,
                                        regs={0: frame, 8: stack, 9: handler_sp + 0x18,
                                              26: FC_XNU_TXM_HANDLER_GLOBAL,
                                              29: handler_sp + 0x60, 30: return_pc},
                                        same_captured_regs=route_preserved),
                                    dict(validator_common,
                                        pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x84,
                                        spsr=0x800013c0,
                                        regs={0: frame, 8: stack, 9: handler_sp + 0x18,
                                              26: FC_XNU_TXM_HANDLER_GLOBAL,
                                              29: handler_sp + 0x60, 30: return_pc},
                                        same_captured_regs=route_preserved),
                                ])
                                after_x19 = tuple(register for register in
                                    route_preserved if register != 19)
                                expected_states.append(dict(validator_common,
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x88,
                                    spsr=0x800013c0,
                                    regs={0: frame, 8: stack, 9: handler_sp + 0x18,
                                          19: frame, 26: FC_XNU_TXM_HANDLER_GLOBAL,
                                          29: handler_sp + 0x60, 30: return_pc},
                                    same_captured_regs=after_x19))
                                validator_memory = dict(local_memory,
                                    validator_base=struct.pack('<Q', stack).hex())
                                expected_states.append(dict(validator_common,
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x8c,
                                    spsr=0x800013c0,
                                    regs={0: frame, 8: stack, 9: handler_sp + 0x18,
                                          19: frame, 26: FC_XNU_TXM_HANDLER_GLOBAL,
                                          29: handler_sp + 0x60, 30: return_pc},
                                    same_captured_regs=after_x19,
                                    memory=validator_memory))
                                expected_states.append(dict(validator_common,
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x90,
                                    spsr=0x800013c0,
                                    regs={0: frame, 8: PAGE, 9: handler_sp + 0x18,
                                          19: frame, 26: FC_XNU_TXM_HANDLER_GLOBAL,
                                          29: handler_sp + 0x60, 30: return_pc},
                                    same_captured_regs=after_x19,
                                    memory=validator_memory))
                                expected_states.append(dict(validator_common,
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x94,
                                    spsr=0x800013c0,
                                    regs={0: frame, 8: PAGE, 9: handler_sp + 0x18,
                                          19: frame, 26: FC_XNU_TXM_HANDLER_GLOBAL,
                                          29: handler_sp + 0x60, 30: return_pc},
                                    same_captured_regs=after_x19,
                                    memory=validator_memory))
                                validator_sizes = dict(validator_memory,
                                    validator_sizes=struct.pack('<QQ', PAGE, PAGE).hex())
                                expected_states.append(dict(validator_common,
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x98,
                                    spsr=0x800013c0,
                                    regs={0: frame, 8: PAGE, 9: handler_sp + 0x18,
                                          19: frame, 26: FC_XNU_TXM_HANDLER_GLOBAL,
                                          29: handler_sp + 0x60, 30: return_pc},
                                    same_captured_regs=after_x19,
                                    memory=validator_sizes))
                                expected_states.append(dict(validator_common,
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0x9c,
                                    spsr=0x800013c0,
                                    regs={0: handler_sp, 8: PAGE,
                                          9: handler_sp + 0x18, 19: frame,
                                          26: FC_XNU_TXM_HANDLER_GLOBAL,
                                          29: handler_sp + 0x60, 30: return_pc},
                                    same_captured_regs=after_x19,
                                    memory=validator_sizes))
                                final_preserved = tuple(register for register in
                                    after_x19 if register != 1)
                                expected_states.append(dict(validator_common,
                                    pc=FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0xa0,
                                    spsr=0x800013c0,
                                    regs={0: handler_sp, 1: 0x2d, 8: PAGE,
                                          9: handler_sp + 0x18, 19: frame,
                                          26: FC_XNU_TXM_HANDLER_GLOBAL,
                                          29: handler_sp + 0x60, 30: return_pc},
                                    same_captured_regs=final_preserved,
                                    memory=validator_sizes))
                                if handler_boundary in (
                                        'validator-trace', 'response-trace',
                                        'cmd1-completion-trace'):
                                    expected_states.append(dict(validator_common,
                                        pc=0xfffffe0017030b64,
                                        sp=handler_sp, spsr=0x800013c0,
                                        regs={0: handler_sp, 1: 0x2d, 8: PAGE,
                                              9: handler_sp + 0x18, 19: frame,
                                              26: FC_XNU_TXM_HANDLER_GLOBAL,
                                              29: handler_sp + 0x60,
                                              30: FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0xa4},
                                        same_captured_regs=final_preserved,
                                        captured_reg_values=dict(moved), saved_pairs=5,
                                        memory=validator_sizes,
                                        begin_validator_trace=True))
                            if not prefix:
                                expected_states = expected_states[:1]
                            txm_context_step_state.update(active=True, index=0,
                                expected_states=expected_states, report_key=report_key,
                                roots=dict(roots),
                                first_touch_va=FC_XNU_TXM_CONTEXT_STACK + PAGE - 0x400 + 0x58,
                                first_touch_pa=first_touch_pa,
                                stack_page_pa=(stack_mapping['pa']
                                    if stack_mapping is not None else None),
                                metadata_frame_pa=metadata_frame_pa,
                                metadata_page_before=metadata_page_before,
                                response_pointer_before=response_pointer_before,
                                handler_boundary=handler_boundary,
                                captured_regs={},
                                metadata_offsets={'state': (0, 1), 'zero_word': (4, 4),
                                                  'claim': (0x58, 1),
                                                  'zero_byte': (0x79, 1),
                                                  'local_marker': (-0x58, 8),
                                                  'validator_base': (-0x70, 8),
                                                  'validator_sizes': (-0x68, 16)},
                                event_kind=(('txm-handler-' + handler_boundary)
                                    if handler_boundary is not None
                                    else ('txm-context-outbound-branch-one-step' if outbound
                                    else ('txm-context-x18-branch-one-step' if x18_branch
                                    else ('txm-context-stack-metadata-init' if metadata
                                    else ('txm-context-stack-claim-one-step' if claim
                                    else ('txm-context-entry-register-prefix' if prefix
                                          else 'txm-context-entry-one-step')))))),
                                complete_reason=(('txm-handler-' + handler_boundary + '-complete')
                                    if handler_boundary is not None
                                    else ('txm-context-outbound-branch-one-step-complete'
                                    if outbound else ('txm-context-x18-branch-one-step-complete'
                                    if x18_branch else ('txm-context-stack-metadata-init-complete'
                                    if metadata else ('txm-context-stack-claim-one-step-complete'
                                    if claim else ('txm-context-entry-register-prefix-complete'
                                                   if prefix else 'txm-context-entry-one-step-complete')))))),
                                mismatch_reason=(('txm-handler-' + handler_boundary + '-mismatch')
                                    if handler_boundary is not None
                                    else ('txm-context-outbound-branch-one-step-mismatch'
                                    if outbound else ('txm-context-x18-branch-one-step-mismatch'
                                    if x18_branch else ('txm-context-stack-metadata-init-mismatch'
                                    if metadata else ('txm-context-stack-claim-one-step-mismatch'
                                    if claim else ('txm-context-entry-register-prefix-mismatch'
                                                   if prefix else 'txm-context-entry-one-step-mismatch')))))))
                            ctx.elr = elr_gl1
                            ctx.spsr = type(ctx.spsr)(spsr_gl1)
                            ctx.spsr.SS = 1
                            u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                            iface.writemem(info, ExcInfo.build(ctx))
                            report.pop('stop_reason', None)
                            ret = EXC_RET.HANDLED
                        elif completion_eret:
                            ctx.elr = elr_gl1
                            ctx.spsr = type(ctx.spsr)(spsr_gl1)
                            ctx.spsr.SS = 1
                            u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                            iface.writemem(info, ExcInfo.build(ctx))
                            report.pop('stop_reason', None)
                            ret = EXC_RET.HANDLED
                        elif phase53_eret:
                            ctx.elr = elr_gl1
                            ctx.spsr = type(ctx.spsr)(spsr_gl1)
                            ctx.spsr.SS = 1
                            u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                            iface.writemem(info, ExcInfo.build(ctx))
                            report.pop('stop_reason', None)
                            event['kind'] = 'phase53-world-transition'
                            ret = EXC_RET.HANDLED
                        elif entry_launch or txm_return:
                            resume_txm = txm_return
                            if (a.handoff_steps and entry_launch) or resume_txm:
                                ctx.elr = elr_gl1
                                ctx.spsr = type(ctx.spsr)(spsr_gl1)
                                if resume_txm:
                                    eret_record['native_resume'] = True
                                else:
                                    handoff_state['active'] = True
                                    ctx.spsr.SS = 1
                                    u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                                iface.writemem(info, ExcInfo.build(ctx))
                                report.pop('stop_reason', None)
                                ret = EXC_RET.HANDLED
                    else:
                        report['stop_reason'] = 'eret-unknown-target'
                        report['eret_unknown'] = dict(pc=hex(ctx.elr), note='ELR_GL1 read 0; stopped without emulating eret')
                elif entered and a.free_run and reason == START.EXCEPTION_LOWER and esr >> 26 == 0x16 and (esr & 0xfff0) == 0x6080:
                    report['stop_reason'] = 'unexpected-eret-overlay'
                elif entered and reason == START.EXCEPTION_LOWER and esr >> 26 == 0x16 and (esr & 0xff80) == 0x6000:
                    imm = esr & 0xffff
                    read, rt, sctlr = bool(imm & 0x20), imm & 31, bool(imm & 0x40)
                    value = 0 if rt == 31 else ctx.regs[rt]
                    event.update(kind='probe-control', register='SCTLR_EL2' if sctlr else 'HCR_EL2', read=read, value=value)
                    accepted = False
                    # A deliberately rejected recognized profile may pause once for a local
                    # policy decision, then retry this same trap with the flag enabled.
                    for attempt in range(2):
                        if read:
                            if rt != 31:
                                ctx.regs[rt] = shadow_sctlr if sctlr else shadow_hcr
                            accepted = True
                        elif not sctlr and value in (0,0x408000000) and (not shadow_sctlr & 1 or value == shadow_hcr):
                            shadow_hcr = value
                            accepted = True
                        elif sctlr and value in (0,0x30d00800):
                            # No active guest translation/cache regime in this entry-only probe.
                            if shadow_sctlr & 1:
                                u.msr(SCTLR_EL12,0x30d00800)
                                u.exec('isb; dsb ishst; tlbi vmalle1is; dsb ish; isb')
                            shadow_sctlr = value
                            accepted = True
                        elif sctlr and a.allow_monitor_mmu and value == 0x02001010fc14793d and shadow_hcr == 0x408000000 and shadow_sprr_config == 0:
                            controls = dict(tcr=u.mrs(TCR_EL12),ttbr0=u.mrs(TTBR0_EL12),ttbr1=u.mrs(TTBR1_EL12),mair=u.mrs(MAIR_EL12))
                            report['monitor_mmu_controls'] = controls
                            # The entry contract is validated ONCE, at the genuine first
                            # monitor MMU enable. SPTM re-writes this same SCTLR value during
                            # later world switches (e.g. the guarded context-save at 0xa4dc0+),
                            # where the mode is EL1h and SP_EL1 is mid-restore (0) -- re-running
                            # the entry check there wrongly rejects a valid transition
                            # (attempt-33). After the first validation, just apply the write.
                            if not monitor_mmu_validated:
                                if (int(ctx.spsr) & 15) not in (4, 5):
                                    raise ValueError('Unsupported physical guest mode for monitor entry')
                                active_sp = ctx.sp[0] if int(ctx.spsr) & 15 == 4 else ctx.sp[1]
                                checked = validate_monitor_entry(
                                    controls, ctx.elr, active_sp, base+args_off, base, guest_size,
                                    lambda addr: iface.readmem(addr,PAGE), pan=bool(int(ctx.spsr) & (1 << 22)),
                                    on_check=lambda name, addr: report.update(
                                        monitor_mmu_check_pending=dict(name=name, va=addr)))
                                report['monitor_mmu_address_checks'] = checked
                                monitor_mmu_validated = True
                                event['kind'] = 'monitor-mmu-enabled'
                            else:
                                event['kind'] = 'monitor-mmu-reentry'
                            u.exec('dsb ishst; tlbi vmalle1is; dsb ish; isb')
                            u.msr(SCTLR_EL12,value)
                            u.exec('isb')
                            shadow_sctlr = value
                            accepted = True
                        if accepted or attempt or not (sctlr and not read and value == 0x02001010fc14793d
                                                       and shadow_hcr == 0x408000000 and shadow_sprr_config == 0
                                                       and pause_guard('monitor-translation-contract', 'allow_monitor_mmu', event)):
                            break
                    if accepted:
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    else:
                        report['stop_reason'] = 'monitor-translation-contract'
                elif entered and reason == START.EXCEPTION_LOWER and esr >> 26 == 0x16 and (esr & 0xfff0) in (0x6090, 0x60a0):
                    imm = esr & 0xf
                    exiting = (esr & 0xfff0) == 0x60a0
                    was_guarded = gxf_state['guarded']
                    event.update(kind='guarded-instruction', instruction='gexit' if exiting else 'genter', imm=imm, guarded_before=was_guarded)
                    mode = int(ctx.spsr) & 15
                    if not a.virtual_gxf:
                        report['stop_reason'] = 'unsupported-exception'
                    elif not gxf_state['config'] & 1 or mode not in (4, 5) or (exiting and not was_guarded) or (not exiting and not apple_shadow[GXF_ENTRY_EL1]):
                        report['stop_reason'] = 'unsupported-guarded-transition'
                    elif exiting:
                        link_pc, link_pstate = u.mrs(ELR_EL12), u.mrs(SPSR_EL12)
                        # Capture the guarded bank, then restore the ordinary EL1 exception bank.
                        for gl, el in gxf_banks.items():
                            apple_shadow[gl] = u.mrs(el)
                        for el, saved in gxf_state['el_bank'].items():
                            u.msr(el, saved)
                        ctx.sp[1], gxf_state['sp_bank'] = gxf_state['sp_bank'], ctx.sp[1]
                        gxf_state['guarded'] = False
                        gxf_state['gexit'] += 1
                        ctx.elr = link_pc
                        ctx.spsr = type(ctx.spsr)(link_pstate)
                        event.update(kind='virtual-gexit', link_pc=link_pc, link_pstate=link_pstate)
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    else:
                        link_pc, link_pstate = ctx.elr, int(ctx.spsr)
                        if not was_guarded:
                            gxf_state['el_bank'] = {el: u.mrs(el) for el in gxf_banks.values()}
                            for gl, el in gxf_banks.items():
                                if gl != VBAR_GL1 or apple_shadow[gl]:
                                    u.msr(el, apple_shadow[gl])
                            ctx.sp[1], gxf_state['sp_bank'] = gxf_state['sp_bank'], ctx.sp[1]
                            gxf_state['guarded'] = True
                        u.msr(SPSR_EL12, link_pstate)
                        u.msr(ELR_EL12, link_pc)
                        u.msr(ESR_EL12, 0xfe010000 | imm)
                        apple_shadow[ASPSR_GL1] = (apple_shadow[ASPSR_GL1] | 1) if was_guarded else (apple_shadow[ASPSR_GL1] & ~1)
                        gxf_state['genter'] += 1
                        ctx.elr = apple_shadow[GXF_ENTRY_EL1]
                        ctx.spsr = type(ctx.spsr)(((link_pstate | 0x3c0) & ~0xf) | 5)
                        event.update(kind='virtual-genter', entry=ctx.elr, link_pc=link_pc, link_pstate=link_pstate,
                                     vector_swapped=bool(apple_shadow[VBAR_GL1]))
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    gxf_report().update(guarded=gxf_state['guarded'], genter=gxf_state['genter'], gexit=gxf_state['gexit'],
                                                 last_transition_index=trace_count(report))
                elif entered and reason == START.EXCEPTION_LOWER and esr >> 26 == 0x16 and (esr & 0xc000) == 0x8000:
                    imm = esr & 0xffff
                    reg = extra_regs[(imm & 0x3fff)>>6]
                    read, rt = bool(imm & 0x20), imm & 31
                    value = 0 if rt == 31 else ctx.regs[rt]
                    event.update(kind='probe-el2-register', register=sysreg_rev.get(reg, 'AGTCNTVOFF_EL2 (observed encoding)' if reg == apple_cntvoff else 'S3_%d_C%d_C%d_%d' % reg[1:]), read=read, value=value)
                    if a.real_guarded and reg in real_redirect:
                        # R2 SYSREG_MAP: redirect the guest's EL1 access to its EL12/GL12 alias,
                        # which reaches the guest's EL1 bank from EL2 (the vel2 HV's own mechanism).
                        xnu_gexit = (a.native_handoff and not read and reg == ASPSR_GL1
                            and value == 0 and ctx.elr == FC_XNU_GEXIT)
                        if xnu_gexit:
                            # The final SPTM launch is a native GEXIT, not an ERET.  The
                            # rewritten ASPSR_GL1 write immediately before it is our last
                            # existing trap.  Verify the already-written guarded banks and
                            # stop before executing GEXIT; attempt 48 independently proved
                            # that resuming here transfers to this PC (and then faults there).
                            elr_gl1 = int(u.mrs(HV.MSR_REDIRECTS[ELR_GL1]))
                            spsr_gl1 = int(u.mrs(HV.MSR_REDIRECTS[SPSR_GL1]))
                            roots = dict(ttbr0=u.mrs(TTBR0_EL12), ttbr1=u.mrs(TTBR1_EL12))
                            handoff = classify_entry(elr_gl1, layout, base, guest_size,
                                                     roots, iface.readmem, sources)
                            # Capture the live launch bank before teardown changes it.  In
                            # real mode the permission shadows are intentionally stale:
                            # accesses go straight to the hypervisor's guest aliases.
                            launch = dict(va=elr_gl1, saved_pstate=spsr_gl1,
                                          callback_pstate=int(ctx.spsr),
                                          permission_source='live guest aliases',
                                          controls=dict(roots), table_pages=[])
                            report['xnu_launch_permissions'] = launch
                            for name, register in (('tcr', TCR_EL12), ('mair', MAIR_EL12),
                                                   ('sctlr', SCTLR_EL12)):
                                try:
                                    launch['controls'][name] = int(u.mrs(register))
                                except Exception as capture_error:
                                    launch[name + '_error'] = str(capture_error)
                            for name, register in (('pperm_el1', SPRR_PPERM_EL1),
                                                   ('uperm_el0', SPRR_UPERM_EL0)):
                                try:
                                    launch[name] = int(u.mrs(HV.MSR_REDIRECTS[register]))
                                except Exception as capture_error:
                                    launch[name + '_error'] = str(capture_error)
                            def read_launch_page(table):
                                data = iface.readmem(table, PAGE)
                                filename = 'xnu-launch-%x.bin' % table
                                capture.save_input(filename, data)
                                launch['table_pages'].append(dict(pa=table, input=filename))
                                return data
                            try:
                                leaf = translate(elr_gl1, roots['ttbr0'], roots['ttbr1'], read_launch_page)
                                launch['mapping'] = leaf
                                if 'pperm_el1' in launch and 'uperm_el0' in launch:
                                    for world in ('ordinary', 'guarded'):
                                        launch[world] = leaf_permissions(leaf['descriptor'],
                                            launch['pperm_el1'], launch['uperm_el0'], world)
                            except Exception as capture_error:
                                launch['mapping_error'] = str(capture_error)
                            verified = (handoff['image'] == 'kernelcache'
                                and handoff['entry_matches'] and handoff['bytes_match']
                                and spsr_gl1 == 0x13c9)
                            event.update(kind='xnu-gexit-handoff', target=hex(elr_gl1),
                                         target_spsr=hex(spsr_gl1), verified=verified)
                            if verified:
                                report['handoff'] = dict(handoff, spsr=hex(spsr_gl1),
                                    via='native GEXIT launch boundary',
                                    source_pc=hex(FC_XNU_GEXIT), instructions_executed=False)
                                report['stop_reason'] = 'handoff-xnu-entry'
                                if a.xnu_steps:
                                    if (not launch.get('ordinary', {}).get('kernel_execute')
                                            or any(key.endswith('_error') for key in launch)):
                                        report['stop_reason'] = 'xnu-launch-permission-unverified'
                                    else:
                                        # Synthetic CurrentEL reports EL2, but native GEXIT
                                        # must return to physical EL1h.  Attempt 48's EL2h
                                        # request instead set PSTATE.IL and stayed EL1t.
                                        physical_spsr = 0x13c5 | (1 << 21)
                                        u.msr(HV.MSR_REDIRECTS[SPSR_GL1], physical_spsr)
                                        u.msr(HV.MSR_REDIRECTS[ASPSR_GL1], 0)
                                        u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                                        report['handoff']['physical_spsr'] = hex(physical_spsr)
                                        report['handoff']['native_resume'] = True
                                        handoff_state.update(active=True, events=0,
                                                             xnu=True, budget=a.xnu_steps)
                                        ctx.spsr.SS = 1
                                        iface.writemem(info, ExcInfo.build(ctx))
                                        report.pop('stop_reason', None)
                                        ret = EXC_RET.HANDLED
                            else:
                                report['stop_reason'] = 'xnu-gexit-unverified'
                        elif read:
                            if rt != 31:
                                ctx.regs[rt] = u.mrs(HV.MSR_REDIRECTS[reg])
                        else:
                            alias = HV.MSR_REDIRECTS[reg]
                            u.msr(alias, value)
                            if reg == VBAR_GL1:
                                readback = int(u.mrs(alias))
                                if readback != value:
                                    raise ValueError('Guarded VBAR readback mismatch')
                                guarded_vbar = readback
                                report.setdefault('real_guarded_vbar', []).append(dict(
                                    index=trace_count(report), requested=value,
                                    readback=readback))
                                event['readback'] = readback
                            if reg == SPRR_CONFIG_EL1:
                                enable = report.setdefault('sprr_real_enable', dict(enforced=True, events=[]))
                                enable['events'].append(dict(index=trace_count(report), value=value,
                                    controls=dict(tcr=u.mrs(TCR_EL12), ttbr0=u.mrs(TTBR0_EL12),
                                                  ttbr1=u.mrs(TTBR1_EL12), mair=u.mrs(MAIR_EL12)),
                                    enable=bool(value & 1), lock_config=bool(value & 2),
                                    lock_perm=bool(value & 0x10), lock_kernel_perm=bool(value & 0x20)))
                        if not xnu_gexit:
                            event['kind'] = 'real-guarded-redirect'
                            ctx.spsr.SS = 1
                            iface.writemem(info, ExcInfo.build(ctx))
                            ret = EXC_RET.HANDLED
                    elif reg in translation_banks:
                        bank = translation_banks[reg]
                        current_value = u.mrs(bank)
                        if a.free_run:
                            # Free-run trusts the monitor: apply translation-control writes
                            # (TCR/TTBR/MAIR to the guest EL1 regime) and continue, without
                            # the boot-time root-switch validation. SPTM reconfigures the
                            # regime during its world switch to XNU; applying the redirected
                            # write is what actually lets the launch proceed.
                            if read:
                                if rt != 31:
                                    ctx.regs[rt] = current_value
                            elif value != current_value:
                                u.exec('dsb ishst')
                                u.msr(bank, value)
                                u.exec('isb; dsb ishst; tlbi vmalle1is; dsb ish; isb')
                            event['kind'] = 'free-run-translation-control'
                            iface.writemem(info, ExcInfo.build(ctx))
                            ret = EXC_RET.HANDLED
                        elif not read and shadow_sctlr & 1 and value != current_value:
                            for attempt in range(2):
                                if a.allow_live_ttbr and bank in (TTBR0_EL12, TTBR1_EL12):
                                    controls = dict(tcr=u.mrs(TCR_EL12),ttbr0=u.mrs(TTBR0_EL12),ttbr1=u.mrs(TTBR1_EL12),mair=u.mrs(MAIR_EL12))
                                    mode = int(ctx.spsr) & 15
                                    if mode not in (4,5):
                                        raise ValueError('Unsupported guest mode for live root switch')
                                    sequence = len(report.get('live_ttbr_switches', []))
                                    def read_switch_page(address):
                                        data = iface.readmem(address,PAGE)
                                        capture.save_input(f'ttbr-{sequence}-{address:x}.bin', data)
                                        return data
                                    checked = validate_root_switch(controls,
                                        'ttbr0' if bank == TTBR0_EL12 else 'ttbr1', value,
                                        ctx.elr, ctx.sp[mode-4], u.mrs(VBAR_EL12), base, guest_size,
                                        read_switch_page, pan=bool(int(ctx.spsr) & (1 << 22)))
                                    switch = dict(previous_controls=controls, validation=checked, applied=False)
                                    report.setdefault('live_ttbr_switches', []).append(switch)
                                    # The guest is stopped: order its table stores, publish the root,
                                    # then invalidate the guest stage-1 TLB before continuation.
                                    u.exec('dsb ishst')
                                    u.msr(bank,value)
                                    u.exec('isb; dsb ishst; tlbi vmalle1is; dsb ish; isb')
                                    if u.mrs(bank) != value:
                                        raise ValueError('Live root readback mismatch')
                                    switch['applied'] = True
                                    report['monitor_mmu_controls'] = checked['controls']
                                    event['kind'] = 'validated-live-ttbr-switch'
                                    ctx.spsr.SS = 1
                                    iface.writemem(info,ExcInfo.build(ctx))
                                    ret = EXC_RET.HANDLED
                                    break
                                if not attempt and bank in (TTBR0_EL12, TTBR1_EL12) and pause_guard('live-translation-control-change', 'allow_live_ttbr', event):
                                    continue
                                report['stop_reason'] = 'live-translation-control-change'
                                break
                        else:
                            if read and rt != 31:
                                ctx.regs[rt] = current_value
                            elif not read and not shadow_sctlr & 1:
                                u.msr(bank,value)
                            ctx.spsr.SS = 1
                            iface.writemem(info,ExcInfo.build(ctx))
                            ret = EXC_RET.HANDLED
                    elif reg in (CNTVOFF_EL2,apple_cntvoff,VM_TMR_FIQ_ENA_EL2) and (read or value == 0):
                        if read and rt != 31:
                            ctx.regs[rt] = 0
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    elif reg in (APCTL_EL1,KERNKEYLO_EL1,KERNKEYHI_EL1):
                        # Public hv_exc.c maps this guest control to its EL12 bank.
                        if read and rt != 31:
                            ctx.regs[rt] = u.mrs(HV.MSR_REDIRECTS[reg])
                        elif not read:
                            u.msr(HV.MSR_REDIRECTS[reg],value)
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    elif reg == SPRR_CONFIG_EL1 and (read or a.observe_sprr or a.real_guarded or (not shadow_sctlr & 1 and value in (0,1))):
                        # Public hv-sprr also defers permission mirrors until SCTLR.M.
                        # Both SCTLR aliases are intercepted; translated SPRR activation stops
                        # unless observation-only staging was requested: nothing is enforced.
                        if a.real_guarded:
                            # R2: really apply SPRR config to the guest, and snapshot the enable point
                            # for offline leaf validation. Nothing is faked. Whether an EL2 msr reaches
                            # the guest's SPRR (vs the HV's own) is the first thing the pre-idle dry run
                            # must confirm before this path is trusted.
                            if read:
                                if rt != 31:
                                    ctx.regs[rt] = u.mrs(SPRR_CONFIG_EL1) if real_sprr_on else shadow_sprr_config
                                event['kind'] = 'real-sprr-config'
                            elif not shadow_sctlr & 1:
                                # SPRR governs stage-1 leaf permissions; before the guest MMU is on it is
                                # inert. The monitor writes SPRR_CONFIG early (pre-MMU); stage those and
                                # apply for real only from the post-MMU enable point.
                                shadow_sprr_config = value
                                event['kind'] = 'staged-sprr-config'
                            else:
                                controls = dict(tcr=u.mrs(TCR_EL12), ttbr0=u.mrs(TTBR0_EL12),
                                                ttbr1=u.mrs(TTBR1_EL12), mair=u.mrs(MAIR_EL12))
                                u.msr(SPRR_CONFIG_EL1, value)
                                shadow_sprr_config = value
                                real_sprr_on = bool(value & 1) or real_sprr_on
                                enable = report.setdefault('sprr_real_enable', dict(enforced=True, events=[]))
                                enable['events'].append(dict(index=trace_count(report), value=value, controls=controls,
                                    enable=bool(value & 1), lock_config=bool(value & 2), lock_perm=bool(value & 0x10),
                                    lock_kernel_perm=bool(value & 0x20), unknown_bits=value & ~0x33,
                                    permissions={sysreg_rev.get(r, 'S3_%d_C%d_C%d_%d' % r[1:]): v for r, v in permission_shadow.items()}))
                                event['kind'] = 'real-sprr-config'
                        else:
                            if read and rt != 31:
                                ctx.regs[rt] = shadow_sprr_config
                            elif not read:
                                shadow_sprr_config = value
                            event['kind'] = 'staged-sprr-config'
                            if not read and shadow_sctlr & 1:
                                event['kind'] = 'observed-sprr-config'
                                observation = report.setdefault('sprr_observation', dict(enforced=False, events=[]))
                                # Bit names from the pinned runtime's cpu_regs.h; other bits are recorded as unknown.
                                observation['events'].append(dict(index=trace_count(report), value=value,
                                    enable=bool(value & 1), lock_config=bool(value & 2), lock_perm=bool(value & 0x10),
                                    lock_kernel_perm=bool(value & 0x20), unknown_bits=value & ~0x33,
                                    permissions={sysreg_rev[r]: v for r, v in permission_shadow.items()}))
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    elif reg in permission_shadow:
                        if read and rt != 31:
                            ctx.regs[rt] = permission_shadow[reg]
                        elif not read:
                            permission_shadow[reg] = value
                        # Redirectable perms (PPERM/UPERM) are applied via their EL12 alias in the
                        # real-guarded branch above; the rest (PMPRR, SH variants) have no alias and
                        # stage until a mechanism for them is established.
                        event['kind'] = 'staged-sprr-permission'
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    elif reg == GXF_CONFIG_EL1 and a.real_guarded and (read or value in (0, 1)):
                        # R2: really enable GXF so native genter/gexit transitions are defined.
                        # Apply only once the guest MMU is on (GXF setup is post-MMU); stage earlier.
                        if read:
                            if rt != 31:
                                ctx.regs[rt] = u.mrs(GXF_CONFIG_EL1) if shadow_sctlr & 1 else 0
                        elif shadow_sctlr & 1:
                            u.msr(GXF_CONFIG_EL1, value)
                        event['kind'] = 'real-gxf-config'
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    elif reg == GXF_CONFIG_EL1 and a.virtual_gxf and (read or value in (0, 1)):
                        if read and rt != 31:
                            ctx.regs[rt] = gxf_state['config']
                        elif not read:
                            gxf_state['config'] = value
                            gxf_report()['config_events'].append(dict(index=trace_count(report), value=value))
                        event['kind'] = 'virtual-gxf-config'
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    elif reg in apple_shadow or (reg == GXF_STATUS_EL1 and read):
                        if reg == GXF_STATUS_EL1:
                            if rt != 31:
                                ctx.regs[rt] = int(gxf_state['guarded'])
                            event['kind'] = 'staged-apple-register'
                        elif gxf_state['guarded'] and reg in gxf_banks:
                            # While guarded the GL1 bank is the live EL1 exception bank.
                            if read and rt != 31:
                                ctx.regs[rt] = u.mrs(gxf_banks[reg])
                            elif not read:
                                u.msr(gxf_banks[reg], value)
                            event['kind'] = 'guarded-bank-register'
                        else:
                            if read and rt != 31:
                                ctx.regs[rt] = apple_shadow.get(reg, 0)
                            elif not read:
                                apple_shadow[reg] = value
                                report['staged_apple_registers'] = {sysreg_rev.get(r, 'S3_%d_C%d_C%d_%d' % r[1:]): v for r, v in apple_shadow.items()}
                            event['kind'] = 'staged-apple-register'
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    elif a.stage_el2_config:
                        if read and rt != 31:
                            ctx.regs[rt] = el2_shadow.get(reg, 0)
                        elif not read:
                            el2_shadow[reg] = value
                            report['staged_el2_registers'] = {sysreg_rev.get(r, 'S3_%d_C%d_C%d_%d' % r[1:]): v for r, v in el2_shadow.items()}
                        event['kind'] = 'staged-el2-register'
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    else:
                        report['stop_reason'] = 'unsupported-el2-register'
                elif entered and reason == START.EXCEPTION_LOWER and esr >> 26 == 0x18:
                    access = ESR_ISS_MSR(esr & 0x1ffffff)
                    reg = (access.Op0,access.Op1,access.CRn,access.CRm,access.Op2)
                    value = 0 if access.Rt == 31 else ctx.regs[access.Rt]
                    event['sysreg'] = dict(encoding=list(reg), name=sysreg_rev.get(reg),
                                           read=bool(access.DIR), rt=access.Rt, value=value)
                    debug_effect = guest_debug.access(reg, bool(access.DIR), value)
                    if debug_effect is not None:
                        if access.DIR and access.Rt != 31:
                            ctx.regs[access.Rt] = debug_effect['value']
                        event['kind'] = debug_effect['kind']
                        event['sysreg']['value'] = debug_effect['value']
                        report['guest_debug'] = guest_debug.snapshot()
                        if guest_debug.oslock is not None:
                            report['guest_oslock'] = guest_debug.oslock
                        ctx.elr += 4
                        ctx.spsr.SS = 1
                        iface.writemem(info,ExcInfo.build(ctx))
                        ret = EXC_RET.HANDLED
                    else:
                        report['stop_reason'] = 'unsupported-system-register'
                elif entered and reason == START.EXCEPTION_LOWER and (esr >> 26) == 0x01 and a.free_run:
                    # WFE/WFI trapped (HCR.TWE) during free-run. The panic halt is a wfe
                    # self-loop at FC_IDLE_PC (0xf8b88); stop there. Any other wait is
                    # benign -- skip it (advance ELR past the wfe) and resume natively.
                    if ctx.elr == FC_IDLE_PC:
                        report['stop_reason'] = 'sptm-panic-halt'
                        report['sptm_panic_halt'] = dict(pc=hex(ctx.elr),
                            note='reached the panic wfe halt in free-run; panic args were consumed at 0xf8ca0 -- re-run single-stepped near here for the message',
                            prior_pcs=[hex(e['pc']) for e in report.get('trace', [])[-6:] if isinstance(e.get('pc'), int)])
                        event['kind'] = 'panic-halt'
                    else:
                        ctx.elr += 4
                        iface.writemem(info, ExcInfo.build(ctx))
                        event['kind'] = 'wfx-skip'
                        ret = EXC_RET.HANDLED
                elif (entered and reason == START.EXCEPTION_LOWER and (esr >> 26) in (0x24, 0x25)
                      and a.on_demand_stage2 and (esr & 0x3c) == 0x04):
                    # On-demand stage-2 backing. SPTM writes to a VA whose IPA is not
                    # mapped in the guest stage-2 (data-abort translation fault, DFSC
                    # 0b0001LL). Translate the faulting VA stage-1-only (AT S1E1x) to get
                    # the IPA -- valid even though stage-2 faults -- back that IPA page with
                    # a fresh zeroed host page, and retry the instruction (do not advance
                    # ELR). Bounded by --on-demand-stage2 MAXPAGES.
                    fault_write = bool((esr >> 6) & 1)
                    ipa = p.hv_translate(ctx.far, True, fault_write)
                    od = report.setdefault('on_demand_stage2',
                                           dict(count=0, samples=[], capped=False, stage1_faults=0))
                    if not ipa:
                        od['stage1_faults'] += 1
                        report['stop_reason'] = 'on-demand-stage1-fault'
                        event['kind'] = 'on-demand-stage1-fault'
                        event['fault_va'] = ctx.far
                    elif od['count'] >= a.on_demand_stage2:
                        od['capped'] = True
                        report['stop_reason'] = 'on-demand-stage2-exhausted'
                        event['kind'] = 'on-demand-stage2-exhausted'
                        event.update(fault_va=ctx.far, fault_ipa=ipa & ~(PAGE - 1))
                    else:
                        page = ipa & ~(PAGE - 1)
                        host = u.memalign(PAGE, PAGE)
                        p.memset64(host, 0, PAGE)
                        if p.hv_map(page, host | HV.PTE_ATTRIBUTES | HV.PTE_VALID, PAGE, 1) < 0:
                            report['stop_reason'] = 'on-demand-map-failed'
                            event['kind'] = 'on-demand-map-failed'
                            event.update(fault_va=ctx.far, fault_ipa=page)
                        else:
                            od['count'] += 1
                            if len(od['samples']) < 64:
                                od['samples'].append(dict(va=ctx.far, ipa=page, host=host, write=fault_write))
                            event['kind'] = 'on-demand-stage2-map'
                            event.update(fault_va=ctx.far, fault_ipa=page)
                            ctx.spsr.SS = 1
                            iface.writemem(info, ExcInfo.build(ctx))
                            ret = EXC_RET.HANDLED
                else:
                    report['stop_reason'] = 'unsupported-exception'
                    # For an instruction/data abort from the guest, capture HPFAR_EL2 so a
                    # stage-2 fault reports its IPA directly (no offline stage-1 table walk).
                    # HPFAR_EL2[43:4] = faulting IPA[51:12]; IPA page = (HPFAR & mask) << 8.
                    try:
                        ec = (esr >> 26) & 0x3f
                        if ec in (0x20, 0x21, 0x24, 0x25):
                            hpfar = u.mrs((3, 4, 6, 0, 4))
                            ipa = (hpfar & 0xfffffffff0) << 8
                            event['hpfar_el2'] = hpfar
                            event['fault_ipa'] = ipa
                            report['unsupported_exception_fault'] = dict(
                                ec=ec, esr=esr, far=event.get('far'), hpfar=hpfar,
                                ipa=ipa, dfsc=esr & 0x3f, write=bool((esr >> 6) & 1))
                    except Exception as hpfar_error:
                        event['hpfar_error'] = str(hpfar_error)
            else:
                report['stop_reason'] = 'hypervisor-event'
        except UnsupportedGuestDebug as error:
            event['unsupported_detail'] = str(error)
            report['stop_reason'] = 'unsupported-guest-debug-control'
            ret = EXC_RET.EXIT_GUEST
        except PpermWindowLimit:
            report['stop_reason'] = 'xnu-pperm-window-limit'
            ret = EXC_RET.EXIT_GUEST
        except Exception as error:
            report['error'] = str(error)
            report['stop_reason'] = 'probe-validation-error'
            ret = EXC_RET.EXIT_GUEST
        finally:
            append_event(report, event)
            if ret == EXC_RET.HANDLED and trace_count(report) > a.steps:
                ret = EXC_RET.EXIT_GUEST
                report['stop_reason'] = 'instruction-budget'
            if ret == EXC_RET.HANDLED and 'sptm_panic' not in report:
                # General SPTM panic capture: if any recorded PC is the panic entry
                # (0xf8ca0, noreturn -> 0xf8980 -> 0xf8b88 halt spin), halt within one
                # batch instead of spinning millions of steps to the budget, and record
                # the panic registers (x0 = format string VA, x1..x5 varargs, lr = call
                # site). Decode the strings/site offline from the Mach-O. This fires for
                # a plain boot too, unlike the guarded-call panic path above.
                for _pi, _ev in enumerate(report.get('trace', [])):
                    if _ev.get('pc') == FC_PANIC and isinstance(_ev.get('regs'), list) and len(_ev['regs']) >= 31:
                        _r = _ev['regs']
                        report['sptm_panic'] = dict(pc=FC_PANIC, args=list(_r[:6]), lr=_r[30],
                            prior_pcs=[e.get('pc') for e in report['trace'][max(0,_pi-16):_pi]])
                        report['stop_reason'] = 'sptm-panic'
                        ret = EXC_RET.EXIT_GUEST
                        break
            if ret == EXC_RET.HANDLED and vector_stop is not None:
                # Observe every drained batch record plus this event against the current VBAR before resuming.
                try:
                    hit = vector_stop.observe(report['trace'], start_index=report.get('trace_start_index', 0), vbar=u.mrs(VBAR_EL12))
                    if hit is not None:
                        ret = EXC_RET.EXIT_GUEST
                        report['stop_reason'] = 'guest-vector-range-entry'
                        report['guest_vector_stop'] = hit
                        try:
                            report['guest_vector_stop'] = vector_stop.snapshot_cause({name: u.mrs(reg) for name, reg in exception_registers.items()})
                        except Exception as error:
                            report['guest_vector_stop_error'] = str(error)
                except Exception as error:
                    ret = EXC_RET.EXIT_GUEST
                    report['error'] = str(error)
                    report['stop_reason'] = 'vector-stop-error'
            if ret == EXC_RET.HANDLED and guarded_vector_stop is not None:
                # Same incremental scan, but against the guarded vector base VBAR_GL1.
                # Cache VBAR_GL1 the first time the guest is in the guarded world
                # (SPSR guarded bit set); it is stable within a run and reading it
                # every stop would add a USB round-trip to each batch.
                try:
                    if not guarded_vbar:
                        last = report['trace'][-1] if report.get('trace') else None
                        if last and isinstance(last.get('spsr'), int) and (last['spsr'] & 0x400000):
                            reg = sysreg_fwd['VBAR_GL1']
                            if reg in HV.MSR_REDIRECTS:
                                guarded_vbar = int(u.mrs(HV.MSR_REDIRECTS[reg])) or 0
                    hit = guarded_vector_stop.observe(report['trace'], start_index=report.get('trace_start_index', 0), vbar=guarded_vbar)
                    if hit is not None:
                        ret = EXC_RET.EXIT_GUEST
                        report['stop_reason'] = 'guarded-vector-entry'
                        # Snapshot the guarded bank now: at the first divert (zero overshoot
                        # under a single-step window) ESR_GL1/ELR_GL1 hold the original
                        # trigger, before the vector slot's self-fault overwrites them.
                        bank = {}
                        for name in ('VBAR_GL1', 'ESR_GL1', 'ELR_GL1', 'SPSR_GL1', 'ASPSR_GL1', 'GXF_ENTRY_EL1', 'GXF_PABENTRY_EL1'):
                            try:
                                reg = sysreg_fwd[name]
                                bank[name] = u.mrs(HV.MSR_REDIRECTS[reg]) if reg in HV.MSR_REDIRECTS else None
                                if bank[name] is None:
                                    bank[name + '_error'] = 'no MSR_REDIRECTS alias'
                            except Exception as bank_error:
                                bank[name + '_error'] = str(bank_error)
                        hit['guarded_bank'] = bank
                        report['guarded_vector_stop'] = hit
                except Exception as error:
                    ret = EXC_RET.EXIT_GUEST
                    report['error'] = str(error)
                    report['stop_reason'] = 'guarded-vector-stop-error'
            if ret == EXC_RET.HANDLED and a.first_contact:
                # After the injected genter fires at idle, watch where it lands and halt
                # before any service mutation. FC_STOP = success (T0, about to call the
                # service, service NOT run); FC_INIT = genter hit the per-CPU init (stale
                # GXF_ENTER); FC_SERVICE = overshoot into the service (should not happen).
                last = report['trace'][-1] if report.get('trace') else None
                pc = last.get('pc') if last else None
                reason = {FC_STOP: 'first-contact-service-boundary',
                          FC_INIT: 'first-contact-wrong-entry-init',
                          FC_SERVICE: 'first-contact-service-entered'}.get(pc)
                if reason is not None:
                    ret = EXC_RET.EXIT_GUEST
                    report['stop_reason'] = reason
                    fc = dict(stop_pc=hex(pc), reason=reason,
                              reached_dispatcher=any(e.get('pc') == FC_DISPATCH for e in report.get('trace', [])))
                    try:
                        fc['gxf_enter'] = u.mrs(GXF_ENTER_ENC)
                    except Exception as e:
                        fc['gxf_enter_error'] = str(e)
                    report['first_contact'] = fc
            if ret == EXC_RET.HANDLED and a.real_guarded and 'sptm_panic' not in report:
                # SPTM boot panic capture: 0xf8ca0 is the generic panic entry. Capture the
                # caller LR (x30 -> which of ~900 panic sites fired) and args (x0 is often
                # a format-string VA -> the panic message, resolved offline from the image).
                last = report['trace'][-1] if report.get('trace') else None
                if last and last.get('pc') == FC_PANIC:
                    regs = last.get('regs') or []
                    def _h(i):
                        return hex(regs[i]) if len(regs) > i and isinstance(regs[i], int) else None
                    report['sptm_panic'] = dict(pc=hex(FC_PANIC), lr=_h(30),
                        args=[_h(i) for i in range(8)],
                        prior_pcs=[hex(e['pc']) for e in report.get('trace', [])[-6:] if isinstance(e.get('pc'), int)])
                    report['stop_reason'] = 'sptm-panic'
                    ret = EXC_RET.EXIT_GUEST
            try:
                # Full JSON snapshots grow with the trace. Keep early checkpoints
                # dense, then reduce write amplification on long experiments.
                interval = 128 if trace_count(report) <= 4096 else 4096
                if trace_count(report)-report.get('trace_checkpoint_events', 0) >= interval or ret == EXC_RET.EXIT_GUEST:
                    report['trace_checkpoint_events'] = trace_count(report)
                    save()
            except Exception as error:
                report['report_save_error'] = str(error)
                report['stop_reason'] = 'report-write-error'
                ret = EXC_RET.EXIT_GUEST
            finally:
                if (a.free_run and not handoff_state['active']
                        and not txm_context_step_state['active']
                        and not txm_validator_trace_state['active']
                        and ret == EXC_RET.HANDLED and entered):
                    # Free-run: resume natively. Clear the single-step bit any branch set
                    # so the guest runs to the next real trap instead of stepping.
                    try:
                        fc = iface.readstruct(info, ExcInfo)
                        if int(fc.spsr) & (1 << 21):
                            fc.spsr.SS = 0
                            iface.writemem(info, ExcInfo.build(fc))
                    except Exception as error:
                        report['free_run_resume_error'] = str(error)
                if batch is not None:
                    try:
                        if (not a.free_run and ret == EXC_RET.HANDLED and entered and shadow_sctlr & 1
                                and not (a.single_step_after and trace_count(report) >= a.single_step_after)
                                and not (ss_window and ss_window[0] <= trace_count(report) < ss_window[1])):
                            batch.arm(report, a.steps)
                        else:
                            batch.disable()
                    except Exception as error:
                        report['batch_error'] = str(error)
                        report['error'] = str(error)
                        report['stop_reason'] = 'native-batch-error'
                        report['trace_incomplete'] = True
                        ret = EXC_RET.EXIT_GUEST
                # A report filesystem failure must not strand a pending guest exit.
                p.exit(ret)
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
            if watchdog is not None:
                report['stop_reason'] = 'guest-unresponsive'
            try:
                save()
            finally:
                iface.dev.close()
        else:
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

if __name__ == '__main__':
    main()
