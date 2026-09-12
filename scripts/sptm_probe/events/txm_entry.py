# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Txm entry event handlers extracted from the original probe callback."""


def validate_context_entry(run, event_state):
    def owned_page(pa):
        if (pa & (run.PAGE - 1) or
                not run.base <= pa < pa + run.PAGE <= run.base + run.guest_size):
            raise ValueError('TXM context-entry table outside owned guest RAM')
        page = run.iface.readmem(pa, run.PAGE)
        if len(page) != run.PAGE:
            raise ValueError('Truncated TXM context-entry table')
        return page
    event_state.handler_boundary = run.a.xnu_txm_handler_boundary
    event_state.outbound = (run.a.xnu_txm_context_outbound_branch_one_step
        or event_state.handler_boundary is not None)
    event_state.gate_error = None
    try:
        event_state.target_mapping = run.translate(event_state.elr_gl1, event_state.roots['ttbr0'],
                                   event_state.roots['ttbr1'], owned_page)
        event_state.stack_mapping = run.translate(int(event_state.ctx.regs[0]), event_state.roots['ttbr0'],
                                  event_state.roots['ttbr1'], owned_page)
        event_state.outbound_mapping = (run.translate(
            run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET,
            event_state.roots['ttbr0'], event_state.roots['ttbr1'], owned_page)
            if event_state.outbound else None)
        event_state.helper_mapping = (run.translate(
            run.FC_XNU_TXM_HANDLER_HELPER,
            event_state.roots['ttbr0'], event_state.roots['ttbr1'], owned_page)
            if event_state.handler_boundary in (
                'local-setup', 'validator-entry', 'validator-trace',
                'response-trace', 'cmd1-completion-trace')
            else None)
        event_state.handler_global_mapping = (run.translate(
            run.FC_XNU_TXM_HANDLER_GLOBAL,
            event_state.roots['ttbr0'], event_state.roots['ttbr1'], owned_page)
            if event_state.handler_boundary in (
                'validator-entry', 'validator-trace', 'response-trace',
                'cmd1-completion-trace')
            else None)
        event_state.response_pointer_mapping = (run.translate(
            run.FC_XNU_TXM_HANDLER_RESPONSE_POINTER,
            event_state.roots['ttbr0'], event_state.roots['ttbr1'], owned_page)
            if event_state.handler_boundary in (
                'response-trace', 'cmd1-completion-trace') else None)
        event_state.pperm = int(run.u.mrs(run.HV.MSR_REDIRECTS[run.SPRR_PPERM_EL1]))
        event_state.uperm = int(run.u.mrs(run.HV.MSR_REDIRECTS[run.SPRR_UPERM_EL0]))
        event_state.mair = int(run.u.mrs(run.MAIR_EL12))
        event_state.target_permissions = run.leaf_permissions(
            event_state.target_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded')
        event_state.stack_permissions = run.leaf_permissions(
            event_state.stack_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded')
        event_state.outbound_permissions = (run.leaf_permissions(
            event_state.outbound_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded')
            if event_state.outbound_mapping is not None else None)
        event_state.helper_permissions = (run.leaf_permissions(
            event_state.helper_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded')
            if event_state.helper_mapping is not None else None)
        event_state.handler_global_permissions = (run.leaf_permissions(
            event_state.handler_global_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded')
            if event_state.handler_global_mapping is not None else None)
        event_state.response_pointer_permissions = (run.leaf_permissions(
            event_state.response_pointer_mapping['descriptor'], event_state.pperm, event_state.uperm,
            'guarded') if event_state.response_pointer_mapping is not None else None)
    except Exception as error:
        event_state.target_mapping = event_state.stack_mapping = None
        event_state.target_permissions = event_state.stack_permissions = None
        event_state.outbound_mapping = event_state.outbound_permissions = None
        event_state.helper_mapping = event_state.helper_permissions = None
        event_state.handler_global_mapping = event_state.handler_global_permissions = None
        event_state.response_pointer_mapping = event_state.response_pointer_permissions = None
        event_state.pperm = event_state.uperm = event_state.mair = None
        event_state.gate_error = str(error)
    event_state.prefix = (run.a.xnu_txm_context_entry_register_prefix
        or run.a.xnu_txm_context_stack_claim_one_step
        or run.a.xnu_txm_context_stack_metadata_init
        or run.a.xnu_txm_context_x18_branch_one_step
        or run.a.xnu_txm_context_outbound_branch_one_step
        or event_state.handler_boundary is not None)
    event_state.claim = (run.a.xnu_txm_context_stack_claim_one_step
        or run.a.xnu_txm_context_stack_metadata_init
        or run.a.xnu_txm_context_x18_branch_one_step
        or run.a.xnu_txm_context_outbound_branch_one_step
        or event_state.handler_boundary is not None)
    event_state.metadata = (run.a.xnu_txm_context_stack_metadata_init
        or run.a.xnu_txm_context_x18_branch_one_step
        or run.a.xnu_txm_context_outbound_branch_one_step
        or event_state.handler_boundary is not None)
    event_state.x18_branch = (run.a.xnu_txm_context_x18_branch_one_step
        or run.a.xnu_txm_context_outbound_branch_one_step
        or event_state.handler_boundary is not None)
    event_state.target_bytes = bytes.fromhex(event_state.handoff.get('bytes_hex', ''))
    event_state.sptm_segment = run.layout.get('images', {}).get('sptm', {}).get(
        'segments', {}).get('__TEXT_EXEC', {})
    event_state.sptm_source_offset = run.FC_XNU_TXM_CONTEXT_ERET_PC - 4 - run.FC_IMAGE_BASE
    event_state.sptm_source_in_segment = (event_state.sptm_segment.get('fileoff', 0)
        <= event_state.sptm_source_offset
        and event_state.sptm_source_offset + 4 <= event_state.sptm_segment.get('fileoff', 0)
            + event_state.sptm_segment.get('filesize', 0))
    event_state.source_eret = (run.sources.get('sptm', b'')[
        event_state.sptm_source_offset:event_state.sptm_source_offset + 4]
        if event_state.sptm_source_in_segment else b'')
    event_state.txm_segment = run.layout.get('images', {}).get('txm', {}).get(
        'segments', {}).get('__TEXT_EXEC', {})
    event_state.outbound_source_offset = (event_state.txm_segment.get('fileoff', 0)
        + run.FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED
        - event_state.txm_segment.get('va', 0))
    event_state.outbound_source_in_segment = (
        event_state.txm_segment.get('va', 0)
            <= run.FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED
        and run.FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED
            + len(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)
            <= event_state.txm_segment.get('va', 0)
                + event_state.txm_segment.get('filesize', 0))
    event_state.handler_source_size = ({
        'local-setup': run.FC_XNU_TXM_HANDLER_LOCAL_SETUP_SIZE,
        'validator-entry': run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE,
        'validator-trace': run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE,
        'response-trace': run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE,
        'cmd1-completion-trace':
            run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE,
    }.get(event_state.handler_boundary,
        len(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)))
    event_state.outbound_source = run.sources.get('txm', b'')[
        event_state.outbound_source_offset:event_state.outbound_source_offset
            + event_state.handler_source_size]
    event_state.helper_source_offset = (event_state.txm_segment.get('fileoff', 0)
        + run.FC_XNU_TXM_HANDLER_HELPER_LINKED
        - event_state.txm_segment.get('va', 0))
    event_state.helper_source = run.sources.get('txm', b'')[
        event_state.helper_source_offset:event_state.helper_source_offset
            + len(run.FC_XNU_TXM_HANDLER_HELPER_BYTES)]
    event_state.txm_prefix_source_offset = (event_state.txm_segment.get('fileoff', 0)
        + int(run.FC_XNU_TXM_CONTEXT_LINKED, 16) + 4
        - event_state.txm_segment.get('va', 0))
    event_state.prefix_source = run.sources.get('txm', b'')[event_state.txm_prefix_source_offset:
        event_state.txm_prefix_source_offset
            + len(run.FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES)]
    event_state.claim_source_offset = (event_state.txm_prefix_source_offset
        + len(run.FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES))
    event_state.claim_source = run.sources.get('txm', b'')[
        event_state.claim_source_offset:event_state.claim_source_offset + 4]
    event_state.post_claim_source_offset = event_state.claim_source_offset + 4
    event_state.post_claim_source = run.sources.get('txm', b'')[
        event_state.post_claim_source_offset:event_state.post_claim_source_offset
            + len(run.FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES)]
    event_state.x18_window_source_offset = (event_state.post_claim_source_offset
        + len(run.FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES) - 4)
    event_state.x18_window_source = run.sources.get('txm', b'')[
        event_state.x18_window_source_offset:event_state.x18_window_source_offset
            + len(run.FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES)]
    event_state.stack_owned_leaf = (event_state.stack_mapping is not None
        and event_state.stack_mapping['level'] == 3
        and event_state.stack_mapping['access_flag']
        and not event_state.stack_mapping['read_only']
        and event_state.stack_mapping['user_access']
        and event_state.stack_mapping['pa'] & (run.PAGE - 1) == 0
        and run.base <= event_state.stack_mapping['pa']
        and event_state.stack_mapping['pa'] + run.PAGE <= run.base + run.guest_size)
    event_state.outbound_owned_leaf = (event_state.outbound_mapping is not None
        and event_state.outbound_mapping['level'] == 3
        and event_state.outbound_mapping['access_flag']
        and event_state.outbound_mapping['read_only']
        and not event_state.outbound_mapping['pxn']
        and run.base <= event_state.outbound_mapping['pa']
        and (event_state.outbound_mapping['pa']
            + event_state.handler_source_size
            <= run.base + run.guest_size)
        and ((event_state.outbound_mapping['pa'] & (run.PAGE - 1))
            + event_state.handler_source_size <= run.PAGE))
    event_state.outbound_live_bytes = (run.iface.readmem(event_state.outbound_mapping['pa'],
            event_state.handler_source_size)
        if event_state.outbound and event_state.outbound_owned_leaf else None)
    event_state.helper_owned_leaf = (event_state.helper_mapping is not None
        and event_state.helper_mapping['level'] == 3
        and event_state.helper_mapping['access_flag']
        and event_state.helper_mapping['read_only']
        and not event_state.helper_mapping['pxn']
        and run.base <= event_state.helper_mapping['pa']
        and event_state.helper_mapping['pa'] + len(run.FC_XNU_TXM_HANDLER_HELPER_BYTES)
            <= run.base + run.guest_size
        and ((event_state.helper_mapping['pa'] & (run.PAGE - 1))
            + len(run.FC_XNU_TXM_HANDLER_HELPER_BYTES) <= run.PAGE))
    event_state.helper_live_bytes = (run.iface.readmem(event_state.helper_mapping['pa'],
            len(run.FC_XNU_TXM_HANDLER_HELPER_BYTES))
        if event_state.helper_owned_leaf else None)
    event_state.handler_global_owned_leaf = (event_state.handler_global_mapping is not None
        and event_state.handler_global_mapping['level'] == 3
        and event_state.handler_global_mapping['access_flag']
        and run.base <= event_state.handler_global_mapping['pa'] < run.base + run.guest_size)
    event_state.handler_global_before = (run.iface.readmem(
            event_state.handler_global_mapping['pa'], 1)
        if event_state.handler_global_owned_leaf else None)
    event_state.response_pointer_owned_leaf = (event_state.response_pointer_mapping is not None
        and event_state.response_pointer_mapping['level'] == 3
        and event_state.response_pointer_mapping['access_flag']
        and run.base <= event_state.response_pointer_mapping['pa']
            <= run.base + run.guest_size - 8)
    event_state.response_pointer_before = (run.iface.readmem(
            event_state.response_pointer_mapping['pa'], 8)
        if event_state.response_pointer_owned_leaf else None)
    event_state.first_touch_pa = (event_state.stack_mapping['pa'] + run.PAGE - 0x400 + 0x58
        if event_state.stack_owned_leaf else None)
    event_state.metadata_frame_pa = (event_state.stack_mapping['pa'] + run.PAGE - 0x400
        if event_state.stack_owned_leaf else None)
    event_state.claim_before = (run.iface.readmem(event_state.first_touch_pa, 1)
        if event_state.claim and event_state.first_touch_pa is not None else None)
    event_state.metadata_page_before = (run.iface.readmem(event_state.stack_mapping['pa'], run.PAGE)
        if event_state.metadata and event_state.stack_owned_leaf else None)
    event_state.metadata_offsets = dict(state=0, zero_word=4,
                            claim=0x58, zero_byte=0x79)
    event_state.metadata_before = ({name: event_state.metadata_page_before[
            run.PAGE - 0x400 + offset:
            run.PAGE - 0x400 + offset + (4 if name == 'zero_word' else 1)]
        for name, offset in event_state.metadata_offsets.items()}
        if event_state.metadata_page_before is not None else {})
    event_state.checks = {
        'verified_xnu_handoff': (run.handoff_state.get('native')
            and run.report.get('handoff', {}).get('image') == 'kernelcache'
            and run.report.get('handoff', {}).get('instructions_executed') is True),
        'trap_pc': event_state.ctx.elr == run.FC_XNU_TXM_CONTEXT_ERET_PC,
        'source_eret': event_state.source_eret == run.struct.pack(
            '<I', run.FC_XNU_TXM_CONTEXT_ERET_WORD),
        'caller_pstate': int(event_state.ctx.spsr) & ~0xf0000000 == 0x13c5,
        'caller_x3': int(event_state.ctx.regs[3]) == 0,
        'caller_selector_x16': int(event_state.ctx.regs[16]) == run.FC_XNU_TXM_CONTEXT_SELECTOR,
        'caller_x18': int(event_state.ctx.regs[18]) == run.FC_XNU_TXM_CONTEXT_X18,
        'target_pc': event_state.elr_gl1 == run.FC_XNU_TXM_CONTEXT_TARGET,
        'target_spsr': event_state.spsr_gl1 == 0x13c0,
        'target_image': event_state.handoff.get('image') == 'txm',
        'target_segment': event_state.handoff.get('segment') == '__TEXT_EXEC',
        'target_linked_pc': event_state.handoff.get('linked_pc') == run.FC_XNU_TXM_CONTEXT_LINKED,
        'target_source_match': event_state.handoff.get('bytes_match') is True,
        'target_bytes': event_state.target_bytes == run.FC_XNU_TXM_CONTEXT_BYTES,
        'target_sha256': run.hashlib.sha256(event_state.target_bytes).hexdigest()
            == run.FC_XNU_TXM_CONTEXT_SHA256,
        'stack_x0': int(event_state.ctx.regs[0]) == run.FC_XNU_TXM_CONTEXT_STACK,
        'stack_aligned': int(event_state.ctx.regs[0]) & (run.PAGE - 1) == 0,
        'target_mapping': (event_state.target_mapping is not None
            and event_state.target_mapping['level'] == 3
            and event_state.target_mapping['access_flag']
            and event_state.target_mapping['read_only']
            and not event_state.target_mapping['pxn']
            and run.base <= event_state.target_mapping['pa'] < run.base + run.guest_size),
        'target_normal_wb': (event_state.target_mapping is not None and event_state.mair is not None
            and (event_state.mair >> (((event_state.target_mapping['descriptor'] >> 2) & 7) * 8))
                & 0xff == 0xff),
        'target_no_hierarchical_restriction': (event_state.target_mapping is not None
            and event_state.target_permissions is not None
            and all(event_state.target_mapping[name] == event_state.target_permissions['native'][name]
                for name in ('read_only', 'user_access', 'pxn', 'uxn'))),
        'target_guarded_gl0_rx': (event_state.target_permissions is not None
            and event_state.target_permissions['user_read']
            and not event_state.target_permissions['user_write']
            and event_state.target_permissions['user_execute']),
        'stack_mapping': event_state.stack_owned_leaf,
        'stack_normal_wb': (event_state.stack_mapping is not None and event_state.mair is not None
            and (event_state.mair >> (((event_state.stack_mapping['descriptor'] >> 2) & 7) * 8))
                & 0xff == 0xff),
        'stack_no_hierarchical_restriction': (event_state.stack_mapping is not None
            and event_state.stack_permissions is not None
            and all(event_state.stack_mapping[name] == event_state.stack_permissions['native'][name]
                for name in ('read_only', 'user_access', 'pxn', 'uxn'))),
        'stack_guarded_gl0_rw': (event_state.stack_permissions is not None
            and event_state.stack_permissions['user_read']
            and event_state.stack_permissions['user_write']
            and not event_state.stack_permissions['user_execute']),
    }
    if event_state.prefix:
        event_state.checks['register_prefix_source'] = (
            event_state.prefix_source == run.FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES
            and run.hashlib.sha256(event_state.prefix_source).hexdigest()
                == run.FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_SHA256)
    if event_state.claim:
        event_state.checks['stack_claim_source'] = event_state.claim_source == run.struct.pack(
            '<I', run.FC_XNU_TXM_CONTEXT_CASB_WORD)
        event_state.checks['stack_claim_initial_zero'] = event_state.claim_before == b'\x00'
    if event_state.metadata:
        event_state.checks['post_claim_source'] = (
            event_state.post_claim_source == run.FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES
            and run.hashlib.sha256(event_state.post_claim_source).hexdigest()
                == run.FC_XNU_TXM_CONTEXT_POST_CLAIM_SHA256)
        event_state.checks['metadata_frame_in_stack_page'] = (
            event_state.metadata_frame_pa is not None
            and event_state.stack_mapping['pa'] <= event_state.metadata_frame_pa
            and event_state.metadata_frame_pa + 0x7a
                <= event_state.stack_mapping['pa'] + run.PAGE)
        event_state.checks['metadata_initial_zero'] = (
            event_state.metadata_before.get('state') == b'\x00'
            and event_state.metadata_before.get('zero_word') == b'\x00' * 4
            and event_state.metadata_before.get('claim') == b'\x00'
            and event_state.metadata_before.get('zero_byte') == b'\x00')
    if event_state.x18_branch:
        event_state.checks['x18_branch_source'] = (
            event_state.x18_window_source == run.FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES
            and run.hashlib.sha256(event_state.x18_window_source).hexdigest()
                == run.FC_XNU_TXM_CONTEXT_X18_WINDOW_SHA256
            and event_state.x18_window_source[:4] == run.struct.pack(
                '<I', run.FC_XNU_TXM_CONTEXT_X18_CBNZ_WORD)
            and event_state.x18_window_source[-4:] == run.struct.pack(
                '<I', run.FC_XNU_TXM_CONTEXT_OUTBOUND_BRANCH_WORD))
    if event_state.outbound:
        event_state.checks['outbound_target_source'] = (
            event_state.outbound_source_in_segment
            and event_state.outbound_source[:len(
                run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)]
                == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES
            and run.hashlib.sha256(event_state.outbound_source[:len(
                run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)]).hexdigest()
                == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_SHA256)
        event_state.branch_imm26 = run.FC_XNU_TXM_CONTEXT_OUTBOUND_BRANCH_WORD & 0x3ffffff
        event_state.branch_delta = ((event_state.branch_imm26 ^ 0x2000000) - 0x2000000) << 2
        event_state.checks['outbound_branch_target'] = (
            run.FC_XNU_TXM_CONTEXT_TARGET + 0x7c + event_state.branch_delta
                == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET)
        event_state.checks['outbound_target_mapping'] = event_state.outbound_owned_leaf
        event_state.checks['outbound_target_normal_wb'] = (
            event_state.outbound_mapping is not None and event_state.mair is not None
            and (event_state.mair >> (((event_state.outbound_mapping['descriptor'] >> 2) & 7) * 8))
                & 0xff == 0xff)
        event_state.checks['outbound_target_no_hierarchical_restriction'] = (
            event_state.outbound_mapping is not None
            and event_state.outbound_permissions is not None
            and all(event_state.outbound_mapping[name]
                == event_state.outbound_permissions['native'][name]
                for name in ('read_only', 'user_access', 'pxn', 'uxn')))
        event_state.checks['outbound_target_guarded_gl0_rx'] = (
            event_state.outbound_permissions is not None
            and event_state.outbound_permissions['user_read']
            and not event_state.outbound_permissions['user_write']
            and event_state.outbound_permissions['user_execute'])
        event_state.checks['outbound_target_live_bytes'] = (
            event_state.outbound_live_bytes is not None
            and event_state.outbound_live_bytes[:len(
                run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)]
                == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES
            and event_state.outbound_live_bytes == event_state.outbound_source
            and run.hashlib.sha256(event_state.outbound_live_bytes[:len(
                run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)]).hexdigest()
                == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_SHA256)
    if event_state.handler_boundary is not None:
        event_state.checks['handler_prologue_source'] = (
            event_state.outbound_source[:12] == run.FC_XNU_TXM_HANDLER_PROLOGUE_BYTES
            and event_state.outbound_live_bytes is not None
            and event_state.outbound_live_bytes[:12]
                == run.FC_XNU_TXM_HANDLER_PROLOGUE_BYTES
            and run.hashlib.sha256(event_state.outbound_live_bytes[:12]).hexdigest()
                == run.FC_XNU_TXM_HANDLER_PROLOGUE_SHA256)
    if event_state.handler_boundary in (
            'local-setup', 'validator-entry', 'validator-trace',
            'response-trace', 'cmd1-completion-trace'):
        event_state.checks['handler_local_setup_source'] = (
            len(event_state.outbound_source) >= run.FC_XNU_TXM_HANDLER_LOCAL_SETUP_SIZE
            and event_state.outbound_live_bytes == event_state.outbound_source
            and run.hashlib.sha256(event_state.outbound_source[:
                run.FC_XNU_TXM_HANDLER_LOCAL_SETUP_SIZE]).hexdigest()
                == run.FC_XNU_TXM_HANDLER_LOCAL_SETUP_SHA256)
        event_state.checks['handler_helper_source'] = (
            event_state.helper_source == run.FC_XNU_TXM_HANDLER_HELPER_BYTES
            and run.hashlib.sha256(event_state.helper_source).hexdigest()
                == run.FC_XNU_TXM_HANDLER_HELPER_SHA256)
        event_state.checks['handler_helper_mapping'] = event_state.helper_owned_leaf
        event_state.checks['handler_helper_guarded_gl0_rx'] = (
            event_state.helper_permissions is not None
            and event_state.helper_permissions['user_read']
            and not event_state.helper_permissions['user_write']
            and event_state.helper_permissions['user_execute'])
        event_state.checks['handler_helper_live_bytes'] = (
            event_state.helper_live_bytes == run.FC_XNU_TXM_HANDLER_HELPER_BYTES
            and event_state.helper_live_bytes == event_state.helper_source)
    if event_state.handler_boundary in (
            'validator-entry', 'validator-trace', 'response-trace',
            'cmd1-completion-trace'):
        event_state.checks['handler_validator_entry_source'] = (
            len(event_state.outbound_source)
                == run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE
            and run.hashlib.sha256(event_state.outbound_source).hexdigest()
                == run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SHA256)
        event_state.checks['handler_global_mapping'] = event_state.handler_global_owned_leaf
        event_state.checks['handler_global_guarded_gl0_read'] = (
            event_state.handler_global_permissions is not None
            and event_state.handler_global_permissions['user_read'])
        event_state.checks['handler_global_initial_zero'] = (
            event_state.handler_global_before == b'\x00')
    if event_state.handler_boundary in (
            'response-trace', 'cmd1-completion-trace'):
        event_state.checks['handler_response_pointer_mapping'] = (
            event_state.response_pointer_owned_leaf)
        event_state.checks['handler_response_pointer_guarded_gl0_read'] = (
            event_state.response_pointer_permissions is not None
            and event_state.response_pointer_permissions['user_read'])
        event_state.checks['handler_response_pointer_read'] = (
            event_state.response_pointer_before is not None
            and len(event_state.response_pointer_before) == 8)
    event_state.classification['checks'] = event_state.checks
    if event_state.gate_error is not None:
        event_state.classification['gate_error'] = event_state.gate_error
    event_state.gate = dict(enabled=True, checks=event_state.checks,
        trap_pc=hex(event_state.ctx.elr), target_pc=hex(event_state.elr_gl1),
        target_spsr=hex(event_state.spsr_gl1), x0=hex(int(event_state.ctx.regs[0])),
        x3=hex(int(event_state.ctx.regs[3])), x16=hex(int(event_state.ctx.regs[16])),
        target_mapping=event_state.target_mapping, stack_mapping=event_state.stack_mapping,
        target_guarded_permissions=event_state.target_permissions,
        stack_guarded_permissions=event_state.stack_permissions,
        pperm_el1=event_state.pperm, uperm_el0=event_state.uperm, mair_el12=event_state.mair,
        expected_next_pc=hex(run.FC_XNU_TXM_CONTEXT_TARGET + 4),
        expected_sp_el0=hex(run.FC_XNU_TXM_CONTEXT_STACK))
    if event_state.claim:
        event_state.gate.update(claim_va=hex(run.FC_XNU_TXM_CONTEXT_STACK
            + run.PAGE - 0x400 + 0x58),
            claim_pa=(hex(event_state.first_touch_pa)
                if event_state.first_touch_pa is not None else None),
            claim_before_hex=(event_state.claim_before.hex()
                if event_state.claim_before is not None else None))
    if event_state.metadata:
        event_state.gate.update(metadata_frame_va=hex(
                run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 0x400),
            metadata_frame_pa=(hex(event_state.metadata_frame_pa)
                if event_state.metadata_frame_pa is not None else None),
            metadata_before_hex={name: value.hex()
                for name, value in event_state.metadata_before.items()},
            metadata_page_before_sha256=(run.hashlib.sha256(
                event_state.metadata_page_before).hexdigest()
                if event_state.metadata_page_before is not None else None),
            metadata_writes=[
                dict(va=hex(run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE
                        - 0x400 + 4),
                     pa=(hex(event_state.metadata_frame_pa + 4)
                         if event_state.metadata_frame_pa is not None else None),
                     width=4, value_hex='00000000'),
                dict(va=hex(run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE
                        - 0x400 + 0x79),
                     pa=(hex(event_state.metadata_frame_pa + 0x79)
                         if event_state.metadata_frame_pa is not None else None),
                     width=1, value_hex='00'),
                dict(va=hex(run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 0x400),
                     pa=(hex(event_state.metadata_frame_pa)
                         if event_state.metadata_frame_pa is not None else None),
                     width=1, value_hex='01')])
    if event_state.x18_branch:
        event_state.gate.update(
            x18_branch_pc=hex(run.FC_XNU_TXM_CONTEXT_TARGET + 0x6c),
            x18_branch_linked=hex(
                int(run.FC_XNU_TXM_CONTEXT_LINKED, 16) + 0x6c),
            x18_branch_word=hex(run.FC_XNU_TXM_CONTEXT_X18_CBNZ_WORD),
            x18_taken_target_pc=hex(
                run.FC_XNU_TXM_CONTEXT_TARGET + 0x7c),
            x18_taken_target_linked=hex(
                int(run.FC_XNU_TXM_CONTEXT_LINKED, 16) + 0x7c),
            x18_taken_target_word=hex(
                run.FC_XNU_TXM_CONTEXT_OUTBOUND_BRANCH_WORD),
            expected_fallthrough_skipped=True,
            expected_stop_before_outbound_branch=True)
    if event_state.outbound:
        event_state.gate.update(
            outbound_target_pc=hex(
                run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET),
            outbound_target_linked=hex(
                run.FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED),
            outbound_target_mapping=event_state.outbound_mapping,
            outbound_target_guarded_permissions=event_state.outbound_permissions,
            outbound_target_sha256=
                run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_SHA256,
            outbound_target_live_bytes_hex=(
                event_state.outbound_live_bytes.hex()
                if event_state.outbound_live_bytes is not None else None),
            outbound_target_live_sha256=(run.hashlib.sha256(
                event_state.outbound_live_bytes).hexdigest()
                if event_state.outbound_live_bytes is not None else None),
            expected_stop_before_pacibsp=True)
    if event_state.handler_boundary is not None:
        event_state.terminal_offset = {'prologue': 8, 'register-saves': 0x20,
                           'local-setup': 0x44,
                           'validator-entry': 0xa0,
                           'validator-trace': 0xa4,
                           'response-trace': 0x4b4,
                           'cmd1-completion-trace': 0x4b4}[event_state.handler_boundary]
        event_state.gate.update(
            boundary=event_state.handler_boundary,
            handler_entry_pc=hex(
                run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET),
            handler_prologue_sha256=
                run.FC_XNU_TXM_HANDLER_PROLOGUE_SHA256,
            expected_terminal_pc=hex(
                run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET
                    + event_state.terminal_offset),
            expected_terminal_sp=hex(
                run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 0x400 - 0x70))
        if event_state.handler_boundary == 'prologue':
            event_state.gate['expected_stop_before_first_stp'] = True
        elif event_state.handler_boundary == 'register-saves':
            event_state.gate.update(expected_saved_register_pairs=5,
                        expected_stop_before_argument_moves=True)
        elif event_state.handler_boundary == 'local-setup':
            event_state.gate.update(
                handler_local_setup_sha256=
                    run.FC_XNU_TXM_HANDLER_LOCAL_SETUP_SHA256,
                handler_helper_pc=hex(run.FC_XNU_TXM_HANDLER_HELPER),
                handler_helper_sha256=
                    run.FC_XNU_TXM_HANDLER_HELPER_SHA256,
                expected_local_marker_va=hex(
                    run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 0x400
                        - 0x70 + 0x18),
                expected_stop_before_global_adrp=True)
        else:
            event_state.gate.update(
                handler_validator_entry_sha256=
                    run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SHA256,
                handler_global_va=hex(run.FC_XNU_TXM_HANDLER_GLOBAL),
                handler_global_mapping=event_state.handler_global_mapping,
                handler_global_guarded_permissions=
                    event_state.handler_global_permissions,
                handler_global_before_hex=(
                    event_state.handler_global_before.hex()
                    if event_state.handler_global_before is not None else None),
                expected_validator_selector=0x2d,
                expected_stop_before_validator_call=True)
            if event_state.handler_boundary in (
                    'response-trace', 'cmd1-completion-trace'):
                event_state.gate.update(
                    response_pointer_va=hex(
                        run.FC_XNU_TXM_HANDLER_RESPONSE_POINTER),
                    response_pointer_mapping=event_state.response_pointer_mapping,
                    response_pointer_before_hex=(
                        event_state.response_pointer_before.hex()
                        if event_state.response_pointer_before is not None else None),
                    expected_response_stop=hex(
                        run.FC_XNU_TXM_HANDLER_RESPONSE_STOP),
                    expected_stop_before_completion_call=True)
    event_state.report_key = ('xnu_txm_handler_boundary'
        if event_state.handler_boundary is not None
        else ('xnu_txm_context_outbound_branch_one_step' if event_state.outbound
        else ('xnu_txm_context_x18_branch_one_step' if event_state.x18_branch
        else ('xnu_txm_context_stack_metadata_init' if event_state.metadata
        else ('xnu_txm_context_stack_claim_one_step' if event_state.claim
        else ('xnu_txm_context_entry_register_prefix' if event_state.prefix
              else 'xnu_txm_context_entry_one_step'))))))
    run.report[event_state.report_key] = event_state.gate
    if all(event_state.checks.values()):
        event_state.txm_context_step = True
        event_state.classification['decision'] = ('txm-handler-' + event_state.handler_boundary
            if event_state.handler_boundary is not None
            else ('txm-context-outbound-branch-one-step'
            if event_state.outbound else ('txm-context-x18-branch-one-step'
            if event_state.x18_branch else ('txm-context-stack-metadata-init'
            if event_state.metadata else ('txm-context-stack-claim'
            if event_state.claim else ('txm-context-register-prefix'
                           if event_state.prefix else 'txm-context-one-step'))))))
    else:
        run.report['stop_reason'] = 'txm-context-entry-gate-rejected'
