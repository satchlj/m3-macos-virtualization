# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Txm step event handlers extracted from the original probe callback."""


def handle_context_step(run, event_state):
    event_state.ctx = event_state.native_ctx if run.handoff_state.get('native') else run.iface.readstruct(event_state.info, run.ExcInfo)
    event_state.expected = run.txm_context_step_state['expected_states'][
        run.txm_context_step_state['index']]
    event_state.observed_sp = int(event_state.ctx.sp[0])
    event_state.step_record_error = None
    event_state.first_touch = None
    event_state.claim_after = None
    event_state.observed_memory = {}
    event_state.metadata_page_after = None
    event_state.page_diff_offsets = None
    event_state.checks = {
        'lower_sync': event_state.reason == run.START.EXCEPTION_LOWER and event_state.code == run.EXC.SYNC,
        'software_step': int(event_state.ctx.esr) == 0xcb000022,
        'expected_pc': event_state.ctx.elr == event_state.expected['pc'],
        'expected_spsr': int(event_state.ctx.spsr) == event_state.expected['spsr'],
        'expected_sp_el0': event_state.observed_sp == event_state.expected['sp'],
        'x16_unchanged': int(event_state.ctx.regs[16]) == run.FC_XNU_TXM_CONTEXT_SELECTOR,
        'x18_unchanged': int(event_state.ctx.regs[18]) == run.FC_XNU_TXM_CONTEXT_X18,
    }
    event_state.checks.update({'x%d' % register: int(event_state.ctx.regs[register]) == value
        for register, value in event_state.expected['regs'].items()})
    event_state.captured_snapshot = {}
    for event_state.register in event_state.expected.get('capture_regs', ()):
        event_state.capture_ok = all(event_state.checks.values())
        event_state.checks['capture_x%d' % event_state.register] = event_state.capture_ok
        if event_state.capture_ok:
            event_state.value = int(event_state.ctx.regs[event_state.register])
            run.txm_context_step_state['captured_regs'][event_state.register] = event_state.value
            event_state.captured_snapshot['x%d' % event_state.register] = hex(event_state.value)
    for event_state.register in event_state.expected.get('same_captured_regs', ()):
        event_state.value = run.txm_context_step_state['captured_regs'].get(event_state.register)
        event_state.checks['captured_x%d_unchanged' % event_state.register] = (
            event_state.value is not None and int(event_state.ctx.regs[event_state.register]) == event_state.value)
    for event_state.register, event_state.source_register in event_state.expected.get(
            'captured_reg_values', {}).items():
        event_state.value = run.txm_context_step_state['captured_regs'].get(event_state.source_register)
        event_state.checks['x%d_from_captured_x%d' % (event_state.register, event_state.source_register)] = (
            event_state.value is not None and int(event_state.ctx.regs[event_state.register]) == event_state.value)
    event_state.save_register_pairs = ((26, 25), (24, 23), (22, 21),
                           (20, 19), (29, 30))
    for event_state.pair_index, event_state.registers in enumerate(
            event_state.save_register_pairs[:event_state.expected.get('saved_pairs', 0)]):
        try:
            event_state.values = [run.txm_context_step_state['captured_regs'][register]
                      for register in event_state.registers]
            event_state.observed = run.iface.readmem(
                run.txm_context_step_state['metadata_frame_pa'] - 0x70
                    + 0x20 + event_state.pair_index * 0x10, 0x10)
            event_state.name = 'save_pair_%d' % event_state.pair_index
            event_state.observed_memory[event_state.name] = event_state.observed.hex()
            event_state.checks['memory_' + event_state.name] = event_state.observed == run.struct.pack('<QQ', *event_state.values)
        except Exception as error:
            event_state.checks['memory_save_pair_%d' % event_state.pair_index] = False
            event_state.step_record_error = str(error)
    for event_state.name, event_state.expected_hex in event_state.expected.get('memory', {}).items():
        try:
            event_state.offset, event_state.width = run.txm_context_step_state['metadata_offsets'][event_state.name]
            event_state.observed = run.iface.readmem(
                run.txm_context_step_state['metadata_frame_pa'] + event_state.offset, event_state.width)
            event_state.observed_memory[event_state.name] = event_state.observed.hex()
            event_state.checks['memory_' + event_state.name] = event_state.observed == bytes.fromhex(event_state.expected_hex)
        except Exception as error:
            event_state.checks['memory_' + event_state.name] = False
            event_state.step_record_error = str(error)
    if (run.txm_context_step_state['report_key'] in
            ('xnu_txm_context_entry_register_prefix',
             'xnu_txm_context_stack_claim_one_step',
             'xnu_txm_context_stack_metadata_init',
             'xnu_txm_context_x18_branch_one_step',
             'xnu_txm_context_outbound_branch_one_step',
             'xnu_txm_handler_boundary')
            and run.txm_context_step_state['index'] + 1
                == len(run.txm_context_step_state['expected_states'])):
        try:
            def final_owned_page(pa):
                if (pa & (run.PAGE - 1) or
                        not run.base <= pa < pa + run.PAGE <= run.base + run.guest_size):
                    raise ValueError('Final TXM prefix table outside owned RAM')
                page = run.iface.readmem(pa, run.PAGE)
                if len(page) != run.PAGE:
                    raise ValueError('Truncated final TXM prefix table')
                return page
            event_state.first_touch = run.translate(run.txm_context_step_state['first_touch_va'],
                run.txm_context_step_state['roots']['ttbr0'],
                run.txm_context_step_state['roots']['ttbr1'], final_owned_page)
            event_state.checks['first_touch_mapping'] = (
                event_state.first_touch['level'] == 3 and event_state.first_touch['access_flag']
                and event_state.first_touch['pa'] == run.txm_context_step_state['first_touch_pa'])
            if (run.txm_context_step_state['report_key']
                    == 'xnu_txm_context_stack_claim_one_step'):
                event_state.claim_after = run.iface.readmem(event_state.first_touch['pa'], 1)
                event_state.checks['stack_claimed_zero_to_one'] = event_state.claim_after == b'\x01'
            elif (run.txm_context_step_state['report_key'] in
                    ('xnu_txm_context_stack_metadata_init',
                     'xnu_txm_context_x18_branch_one_step',
                     'xnu_txm_context_outbound_branch_one_step',
                     'xnu_txm_handler_boundary')):
                event_state.claim_after = run.iface.readmem(event_state.first_touch['pa'], 1)
                event_state.checks['stack_claimed_zero_to_one'] = event_state.claim_after == b'\x01'
                event_state.metadata_page_after = run.iface.readmem(
                    run.txm_context_step_state['stack_page_pa'], run.PAGE)
                event_state.expected_page = bytearray(
                    run.txm_context_step_state['metadata_page_before'])
                event_state.frame_offset = (run.txm_context_step_state['metadata_frame_pa']
                    - run.txm_context_step_state['stack_page_pa'])
                event_state.expected_page[event_state.frame_offset] = 1
                event_state.expected_page[event_state.frame_offset + 4:event_state.frame_offset + 8] = b'\x00' * 4
                event_state.expected_page[event_state.frame_offset + 0x58] = 1
                event_state.expected_page[event_state.frame_offset + 0x79] = 0
                if run.txm_context_step_state['handler_boundary'] in (
                        'register-saves', 'local-setup', 'validator-entry',
                        'validator-trace', 'response-trace',
                        'cmd1-completion-trace'):
                    for event_state.pair_index, event_state.registers in enumerate(event_state.save_register_pairs):
                        event_state.values = [run.txm_context_step_state['captured_regs'][register]
                                  for register in event_state.registers]
                        event_state.offset = event_state.frame_offset - 0x70 + 0x20 + event_state.pair_index * 0x10
                        event_state.expected_page[event_state.offset:event_state.offset + 0x10] = run.struct.pack(
                            '<QQ', *event_state.values)
                if run.txm_context_step_state['handler_boundary'] in (
                        'local-setup', 'validator-entry', 'validator-trace',
                        'response-trace', 'cmd1-completion-trace'):
                    event_state.expected_page[event_state.frame_offset - 0x70 + 0x18:
                                  event_state.frame_offset - 0x70 + 0x20] = run.struct.pack('<Q', 1)
                if run.txm_context_step_state['handler_boundary'] in (
                        'validator-entry', 'validator-trace', 'response-trace',
                        'cmd1-completion-trace'):
                    event_state.expected_page[event_state.frame_offset - 0x70:
                                  event_state.frame_offset - 0x68] = run.struct.pack(
                                      '<Q', run.FC_XNU_TXM_CONTEXT_STACK)
                    event_state.expected_page[event_state.frame_offset - 0x68:
                                  event_state.frame_offset - 0x58] = run.struct.pack(
                                      '<QQ', run.PAGE, run.PAGE)
                event_state.page_diff_offsets = [index for index, (before, after) in enumerate(
                    zip(run.txm_context_step_state['metadata_page_before'],
                        event_state.metadata_page_after)) if before != after]
                event_state.checks['metadata_final_values'] = (
                    event_state.metadata_page_after[event_state.frame_offset] == 1
                    and event_state.metadata_page_after[event_state.frame_offset + 4:event_state.frame_offset + 8]
                        == b'\x00' * 4
                    and event_state.metadata_page_after[event_state.frame_offset + 0x58] == 1
                    and event_state.metadata_page_after[event_state.frame_offset + 0x79] == 0)
                event_state.checks['metadata_no_unexpected_page_writes'] = (
                    event_state.metadata_page_after == bytes(event_state.expected_page))
        except Exception as error:
            event_state.first_touch = None
            event_state.checks['first_touch_mapping'] = False
            event_state.step_record_error = str(error)
    event_state.step_record = dict(
        index=run.txm_context_step_state['index'], expected_pc=hex(event_state.expected['pc']),
        observed_pc=hex(event_state.ctx.elr), expected_sp=hex(event_state.expected['sp']),
        observed_sp_el0=hex(event_state.observed_sp), esr=hex(int(event_state.ctx.esr)),
        spsr=hex(int(event_state.ctx.spsr)), checks=event_state.checks,
        verified=all(event_state.checks.values()))
    if event_state.step_record_error is not None:
        event_state.step_record['mapping_error'] = event_state.step_record_error
    if event_state.first_touch is not None:
        event_state.step_record['first_touch_mapping'] = event_state.first_touch
    if event_state.claim_after is not None:
        event_state.step_record['claim_after_hex'] = event_state.claim_after.hex()
    if event_state.observed_memory:
        event_state.step_record['observed_memory_hex'] = event_state.observed_memory
    if event_state.captured_snapshot:
        event_state.step_record['captured_regs'] = event_state.captured_snapshot
    if (run.txm_context_step_state['report_key'] in
            ('xnu_txm_context_stack_metadata_init',
             'xnu_txm_context_x18_branch_one_step',
             'xnu_txm_context_outbound_branch_one_step',
             'xnu_txm_handler_boundary')
            and run.txm_context_step_state['index'] + 1
                == len(run.txm_context_step_state['expected_states'])
            and event_state.metadata_page_after is not None):
        event_state.step_record.update(
            metadata_page_after_sha256=run.hashlib.sha256(
                event_state.metadata_page_after).hexdigest(),
            metadata_page_diff_offsets=[hex(offset)
                for offset in event_state.page_diff_offsets])
    event_state.probe = run.report[run.txm_context_step_state['report_key']]
    event_state.probe.setdefault('steps', []).append(event_state.step_record)
    event_state.event.update(kind=run.txm_context_step_state['event_kind'], pc=event_state.ctx.elr,
                 esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs),
                 far=event_state.ctx.far, sp=list(event_state.ctx.sp), checks=event_state.checks)
    if all(event_state.checks.values()) and event_state.expected.get('begin_validator_trace'):
        run.txm_context_step_state['active'] = False
        event_state.protected_pa = run.txm_context_step_state['metadata_frame_pa'] - 0x70
        event_state.protected_size = 0x70 + 0x7a
        run.txm_validator_trace_state.update(
            active=True, phase='validator', steps=0, limit=2048,
            boundary=run.txm_context_step_state['handler_boundary'],
            return_pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 0xa4,
            response_stop=run.FC_XNU_TXM_HANDLER_RESPONSE_STOP,
            expected_sp=event_state.expected['sp'], expected_result=0x2d,
            metadata_frame_pa=run.txm_context_step_state['metadata_frame_pa'],
            response_pointer=(int.from_bytes(
                run.txm_context_step_state['response_pointer_before'], 'little')
                if run.txm_context_step_state.get('response_pointer_before')
                is not None else None),
            protected_pa=event_state.protected_pa,
            protected_before=run.iface.readmem(event_state.protected_pa, event_state.protected_size),
            protected_size=event_state.protected_size,
            roots=dict(run.txm_context_step_state['roots']),
            report_key=run.txm_context_step_state['report_key'])
        event_state.step_record.update(boundary=run.txm_context_step_state['handler_boundary'],
                           validator_call_entered=True)
        event_state.probe['validator_entry'] = event_state.step_record
        event_state.ctx.spsr.SS = 1
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED
    elif (all(event_state.checks.values()) and run.txm_context_step_state['index'] + 1
            < len(run.txm_context_step_state['expected_states'])):
        run.txm_context_step_state['index'] += 1
        event_state.ctx.spsr.SS = 1
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED
    else:
        run.txm_context_step_state['active'] = False
        run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) & ~1)
        event_state.step_record['exactly_one_instruction'] = (
            run.txm_context_step_state['report_key']
                == 'xnu_txm_context_entry_one_step' and all(event_state.checks.values()))
        if (run.txm_context_step_state['report_key']
                == 'xnu_txm_context_x18_branch_one_step'):
            event_state.branch_verified = (all(event_state.checks.values()) and event_state.ctx.elr
                == run.FC_XNU_TXM_CONTEXT_TARGET + 0x7c)
            event_state.step_record.update(
                extension_instructions=(1 if event_state.branch_verified else None),
                branch_taken=event_state.branch_verified,
                fallthrough_svc_not_executed=event_state.branch_verified,
                outbound_branch_executed=(False if event_state.branch_verified else None))
        elif (run.txm_context_step_state['report_key']
                == 'xnu_txm_context_outbound_branch_one_step'):
            event_state.outbound_verified = (all(event_state.checks.values()) and event_state.ctx.elr
                == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET)
            event_state.step_record.update(
                extension_instructions=(1 if event_state.outbound_verified else None),
                outbound_branch_taken=event_state.outbound_verified,
                pacibsp_executed=(False if event_state.outbound_verified else None))
        elif (run.txm_context_step_state['report_key']
                == 'xnu_txm_handler_boundary'):
            event_state.boundary = run.txm_context_step_state['handler_boundary']
            event_state.terminal_offsets = {'prologue': 8, 'register-saves': 0x20,
                                'local-setup': 0x44,
                                'validator-entry': 0xa0}
            event_state.boundary_verified = (all(event_state.checks.values())
                and event_state.ctx.elr == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET
                    + event_state.terminal_offsets[event_state.boundary])
            event_state.extension_counts = {'prologue': 2, 'register-saves': 8,
                                'local-setup': 23,
                                'validator-entry': 39}
            event_state.step_record.update(
                boundary=event_state.boundary,
                extension_instructions=(event_state.extension_counts[event_state.boundary]
                    if event_state.boundary_verified else None),
                pacibsp_executed=event_state.boundary_verified,
                stack_allocation_bytes=(0x70 if event_state.boundary_verified else None),
                saved_register_pairs=(5 if event_state.boundary_verified
                    and event_state.boundary != 'prologue' else
                    (0 if event_state.boundary_verified else None)),
                helper_roundtrip_executed=(event_state.boundary_verified
                    if event_state.boundary in ('local-setup', 'validator-entry') else False),
                local_marker_stored=(event_state.boundary_verified
                    if event_state.boundary in ('local-setup', 'validator-entry') else False),
                global_guard_zero=(event_state.boundary_verified
                    if event_state.boundary == 'validator-entry' else None),
                validator_tuple_stored=(event_state.boundary_verified
                    if event_state.boundary == 'validator-entry' else None),
                first_stp_executed=(event_state.boundary_verified
                    if event_state.boundary != 'prologue' else
                    (False if event_state.boundary_verified else None)))
        event_state.probe['result'] = event_state.step_record
        event_state.probe['complete'] = all(event_state.checks.values())
        run.report['stop_reason'] = (run.txm_context_step_state['complete_reason']
            if all(event_state.checks.values()) else run.txm_context_step_state['mismatch_reason'])
