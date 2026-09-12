# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Retype event handlers extracted from the original probe callback."""

def handle_unrelated_return(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.state = run.phase53_retype_survey_state
    event_state.checks = {'exact_spsr': int(event_state.ctx.spsr) == run.FC_XNU_PHASE53_GENTER_RETURN_SPSR, 'returned_pc_in_xnu': run.FC_XNU_RUNTIME_TEXT[0] <= event_state.ctx.elr < run.FC_XNU_RUNTIME_TEXT[1]}
    event_state.transition = dict(kind='survey-unrelated-gexit-return', pc=hex(event_state.ctx.elr), spsr=hex(int(event_state.ctx.spsr)), completed_calls=event_state.state['completed_calls'])
    try:
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.roots = event_state.state['roots']

        def read_survey_unrelated_return_page(table):
            if table & run.PAGE - 1 or not run.base <= table < table + run.PAGE <= run.base + run.guest_size:
                raise ValueError('Phase53 survey table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)
        event_state.kernel_segment = run.layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        event_state.sptm_segment = run.layout['images']['sptm']['segments']['__TEXT_EXEC']
        event_state.return_leaf = run.translate(event_state.ctx.elr, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_survey_unrelated_return_page)
        event_state.gexit_leaf = run.translate(run.FC_XNU_PHASE53_GEXIT, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_survey_unrelated_return_page)
        event_state.return_live = run.iface.readmem(event_state.return_leaf['pa'], 4)
        event_state.gexit_live = run.iface.readmem(event_state.gexit_leaf['pa'], 4)
        event_state.return_linked = run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED + event_state.ctx.elr - run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY
        event_state.return_offset = event_state.kernel_segment['fileoff'] + event_state.return_linked - event_state.kernel_segment['va']
        event_state.return_source = run.sources['kernelcache'][event_state.return_offset:event_state.return_offset + 4]
        event_state.gexit_offset = event_state.sptm_segment['fileoff'] + run.FC_XNU_PHASE53_GEXIT_LINKED - event_state.sptm_segment['va']
        event_state.gexit_source = run.sources['sptm'][event_state.gexit_offset:event_state.gexit_offset + 4]
        event_state.expected_gexit = run.struct.pack('<I', run.FC_XNU_PHASE53_GEXIT_WORD)
        event_state.aggregate_steps = event_state.state['aggregate_steps'] + event_state.fast_status['steps']
        event_state.checks.update(return_source_complete=len(event_state.return_source) == 4, return_live_source=len(event_state.return_source) == 4 and event_state.return_live == event_state.return_source, return_level_three=event_state.return_leaf['level'] == 3, return_access_flag=event_state.return_leaf['access_flag'], gexit_source=event_state.gexit_source == event_state.expected_gexit, gexit_live=event_state.gexit_live == event_state.expected_gexit and event_state.gexit_live == event_state.gexit_source, gexit_level_three=event_state.gexit_leaf['level'] == 3, gexit_access_flag=event_state.gexit_leaf['access_flag'], filter_outside=not event_state.fast_status['active'] and event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_OUTSIDE, filter_bounded=0 < event_state.fast_status['steps'] <= event_state.state['max_steps'], filter_last_pc=event_state.fast_status['last_pc'] == event_state.ctx.elr, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_GEXIT, filter_segment=event_state.fast_status['first_pc'] == event_state.state['segment_start'] and event_state.fast_status['expected_first_pc'] == event_state.state['segment_start'] and (event_state.fast_status['range0_hits'] + event_state.fast_status['range1_hits'] == event_state.fast_status['steps']), filter_contract=event_state.fast_status['range0_start'] == run.FC_TXM_RUNTIME_TEXT[0] and event_state.fast_status['range0_end'] == run.FC_TXM_RUNTIME_TEXT[1] and (event_state.fast_status['range1_start'] == run.FC_SPTM_RUNTIME_TEXT[0]) and (event_state.fast_status['range1_end'] == run.FC_SPTM_RUNTIME_TEXT[1]) and (event_state.fast_status['terminal_pc'] == event_state.state['terminal_pc']) and (event_state.fast_status['max_steps'] == event_state.state['max_steps']), aggregate_budget=event_state.aggregate_steps <= run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS)
        event_state.transition.update(return_linked=hex(event_state.return_linked), return_pa=hex(event_state.return_leaf['pa']), return_source_hex=event_state.return_source.hex(), return_live_hex=event_state.return_live.hex(), gexit_pa=hex(event_state.gexit_leaf['pa']), gexit_source_hex=event_state.gexit_source.hex(), gexit_live_hex=event_state.gexit_live.hex(), prior_status=event_state.fast_status, aggregate_steps=event_state.aggregate_steps)
        if all(event_state.checks.values()):
            event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, event_state.state['terminal_pc'], event_state.state['max_steps'], event_state.ctx.elr)
            event_state.state.update(range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.ctx.elr, aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'] + 1)
            event_state.transition.update(checks=event_state.checks, complete=True, enable_status=event_state.enabled_status)
            event_state.state['world_transitions'].append(event_state.transition)
            run.report['xnu_phase53_retype_survey'].update(world_transitions=list(event_state.state['world_transitions']), aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'])
            event_state.event.update(kind='phase53-survey-unrelated-gexit-return', pc=event_state.ctx.elr, esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs), far=event_state.ctx.far, sp=list(event_state.ctx.sp), checks=event_state.checks)
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            run.report.pop('stop_reason', None)
            event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.state['active'] = False
            event_state.transition.update(checks=event_state.checks, complete=False)
            run.report['xnu_phase53_retype_survey']['unrelated_return_rejection'] = event_state.transition
            run.report['stop_reason'] = 'phase53-retype-survey-unrelated-return-gate-rejected'
    except Exception as unrelated_return_error:
        event_state.checks['gate_readback'] = False
        event_state.state['active'] = False
        event_state.transition.update(checks=event_state.checks, complete=False, error=str(unrelated_return_error))
        run.report['xnu_phase53_retype_survey']['unrelated_return_rejection'] = event_state.transition
        run.report['stop_reason'] = 'phase53-retype-survey-unrelated-return-gate-rejected'

def handle_guarded_return(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.state = run.phase53_retype_survey_state
    event_state.checks = {'exact_spsr': int(event_state.ctx.spsr) == run.FC_XNU_PHASE53_GENTER_RETURN_SPSR, 'wrapper_link': int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_GENTER_PREVIOUS & (1 << 40) - 1}
    event_state.record = dict(stage='seek-genter-return', pc=hex(event_state.ctx.elr), x30=hex(int(event_state.ctx.regs[30])))
    try:
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.roots = event_state.state['roots']

        def read_survey_return_page(table):
            if table & run.PAGE - 1 or not run.base <= table < table + run.PAGE <= run.base + run.guest_size:
                raise ValueError('Phase53 survey table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)
        event_state.kernel_segment = run.layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        event_state.sptm_segment = run.layout['images']['sptm']['segments']['__TEXT_EXEC']
        event_state.code_specs = (('selector', run.FC_XNU_PHASE53_GENTER_PREVIOUS, run.FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED, run.FC_XNU_PHASE53_GENTER_PREVIOUS_WORD, event_state.kernel_segment, run.sources['kernelcache']), ('genter', run.FC_XNU_PHASE53_GENTER, run.FC_XNU_PHASE53_GENTER_LINKED, run.FC_XNU_PHASE53_GENTER_WORD, event_state.kernel_segment, run.sources['kernelcache']), ('gexit', run.FC_XNU_PHASE53_GEXIT, run.FC_XNU_PHASE53_GEXIT_LINKED, run.FC_XNU_PHASE53_GEXIT_WORD, event_state.sptm_segment, run.sources['sptm']), ('return', run.FC_XNU_PHASE53_GENTER_RETURN, run.FC_XNU_PHASE53_GENTER_RETURN_LINKED, run.FC_XNU_PHASE53_GENTER_RETURN_WORD, event_state.kernel_segment, run.sources['kernelcache']))
        event_state.code_evidence = {}
        for event_state.name, event_state.pc, event_state.linked, event_state.word, event_state.segment, event_state.source in event_state.code_specs:
            event_state.leaf = run.translate(event_state.pc, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_survey_return_page)
            event_state.live = run.iface.readmem(event_state.leaf['pa'], 4)
            event_state.offset = event_state.segment['fileoff'] + event_state.linked - event_state.segment['va']
            event_state.source_bytes = event_state.source[event_state.offset:event_state.offset + 4]
            event_state.expected = run.struct.pack('<I', event_state.word)
            event_state.checks[event_state.name + '_source'] = event_state.source_bytes == event_state.expected
            event_state.checks[event_state.name + '_live'] = event_state.live == event_state.expected and event_state.live == event_state.source_bytes
            event_state.checks[event_state.name + '_level_three'] = event_state.leaf['level'] == 3
            event_state.checks[event_state.name + '_access_flag'] = event_state.leaf['access_flag']
            event_state.code_evidence[event_state.name] = dict(pa=hex(event_state.leaf['pa']), source_hex=event_state.source_bytes.hex(), live_hex=event_state.live.hex())
        event_state.aggregate_steps = event_state.state['aggregate_steps'] + event_state.fast_status['steps']
        event_state.checks.update(filter_stopped=not event_state.fast_status['active'] and event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_TERMINAL, filter_last_pc=event_state.fast_status['last_pc'] == event_state.ctx.elr, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_GEXIT, filter_segment=event_state.fast_status['first_pc'] == event_state.state['segment_start'] and event_state.fast_status['expected_first_pc'] == event_state.state['segment_start'] and (event_state.fast_status['range0_hits'] + event_state.fast_status['range1_hits'] == event_state.fast_status['steps']), filter_contract=event_state.fast_status['range0_start'] == event_state.state['range0'][0] and event_state.fast_status['range0_end'] == event_state.state['range0'][1] and (event_state.fast_status['range1_start'] == run.FC_SPTM_RUNTIME_TEXT[0]) and (event_state.fast_status['range1_end'] == run.FC_SPTM_RUNTIME_TEXT[1]) and (event_state.fast_status['terminal_pc'] == run.FC_XNU_PHASE53_GENTER_RETURN) and (event_state.fast_status['max_steps'] == event_state.state['max_steps']), aggregate_budget=event_state.aggregate_steps <= run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS)
        event_state.record.update(filter_status=event_state.fast_status, code=event_state.code_evidence, aggregate_steps=event_state.aggregate_steps)
        if all(event_state.checks.values()):
            event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB, event_state.state['max_steps'], event_state.ctx.elr)
            event_state.state.update(stage='seek-wrapper-retab', range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.ctx.elr, terminal_pc=run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB, aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'] + 1)
            event_state.record.update(checks=event_state.checks, complete=True, enable_status=event_state.enabled_status)
            event_state.state['current_call']['genter_return'] = event_state.record
            run.report['xnu_phase53_retype_survey'].update(current_stage='seek-wrapper-retab', terminal_pc=hex(run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB), aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'])
            event_state.event.update(kind='phase53-survey-genter-return', pc=event_state.ctx.elr, checks=event_state.checks)
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.state['active'] = False
            event_state.record.update(checks=event_state.checks, complete=False)
            event_state.state.get('current_call', {}).update(genter_return=event_state.record)
            run.report['xnu_phase53_retype_survey']['rejection'] = event_state.record
            run.report['stop_reason'] = 'phase53-retype-survey-genter-return-gate-rejected'
    except Exception as survey_return_error:
        event_state.checks['gate_readback'] = False
        event_state.state['active'] = False
        event_state.record.update(checks=event_state.checks, complete=False, error=str(survey_return_error))
        event_state.state.get('current_call', {}).update(genter_return=event_state.record)
        run.report['xnu_phase53_retype_survey']['rejection'] = event_state.record
        run.report['stop_reason'] = 'phase53-retype-survey-genter-return-gate-rejected'

def handle_survey_step(run, event_state):
    event_state.ctx = event_state.native_ctx if run.handoff_state.get('native') else run.iface.readstruct(event_state.info, run.ExcInfo)
    event_state.state = run.phase53_retype_survey_state
    event_state.stage_name = event_state.state['stage']
    event_state.specs = {'seek-entry': (run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY, run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED, run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_WORD), 'seek-genter': (run.FC_XNU_PHASE53_GENTER, run.FC_XNU_PHASE53_GENTER_LINKED, run.FC_XNU_PHASE53_GENTER_WORD), 'seek-wrapper-retab': (run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB, run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED, run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_WORD)}
    event_state.expected_pc, event_state.linked_pc, event_state.expected_word = event_state.specs[event_state.stage_name]
    event_state.checks = {'expected_pc': event_state.ctx.elr == event_state.expected_pc}
    event_state.stage_record = dict(stage=event_state.stage_name, pc=hex(event_state.ctx.elr))
    try:
        event_state.roots = event_state.state['roots']

        def read_survey_page(table):
            if table & run.PAGE - 1 or not run.base <= table < table + run.PAGE <= run.base + run.guest_size:
                raise ValueError('Phase53 survey table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)

        def capture_fte_neighborhood(physical_address):
            pointer_leaf = run.translate(run.FC_SPTM_PHASE53_FTE_BASE_POINTER, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_survey_page)
            pointer_raw = run.iface.readmem(pointer_leaf['pa'], 8)
            fte_base = run.struct.unpack('<Q', pointer_raw)[0]
            center_va = fte_base + (physical_address - run.base >> 10 & 18014398509481968)
            records = []
            for delta in (-16, 0, 16):
                va = center_va + delta
                leaf = run.translate(va, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_survey_page)
                raw = run.iface.readmem(leaf['pa'], 16)
                records.append(dict(delta=delta, va=hex(va), pa=hex(leaf['pa']), hex=raw.hex(), sha256=run.hashlib.sha256(raw).hexdigest(), in_flight_ops=run.struct.unpack('<H', raw[:2])[0] if len(raw) == 16 else None, type=raw[2] if len(raw) == 16 else None, complete=len(raw) == 16, level_three=leaf['level'] == 3, access_flag=leaf['access_flag']))
            return dict(base_pointer_va=hex(run.FC_SPTM_PHASE53_FTE_BASE_POINTER), base_pointer_pa=hex(pointer_leaf['pa']), base_pointer_hex=pointer_raw.hex(), pointer_level_three=pointer_leaf['level'] == 3, pointer_access_flag=pointer_leaf['access_flag'], fte_base=hex(fte_base), center_va=hex(center_va), records=records)
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.code_leaf = run.translate(event_state.ctx.elr, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_survey_page)
        event_state.code_live = run.iface.readmem(event_state.code_leaf['pa'], 4)
        event_state.kernel_segment = run.layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        event_state.source_offset = event_state.kernel_segment['fileoff'] + event_state.linked_pc - event_state.kernel_segment['va']
        event_state.source_word = run.sources['kernelcache'][event_state.source_offset:event_state.source_offset + 4]
        event_state.expected_code = run.struct.pack('<I', event_state.expected_word)
        event_state.aggregate_steps = event_state.state['aggregate_steps'] + event_state.fast_status['steps']
        event_state.checks.update(source_word=event_state.source_word == event_state.expected_code, live_word=event_state.code_live == event_state.expected_code and event_state.code_live == event_state.source_word, level_three=event_state.code_leaf['level'] == 3, access_flag=event_state.code_leaf['access_flag'], filter_terminal=not event_state.fast_status['active'] and event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_TERMINAL and (event_state.fast_status['last_pc'] == event_state.expected_pc), filter_bounded=0 < event_state.fast_status['steps'] <= event_state.state['max_steps'], filter_contract=event_state.fast_status['first_pc'] == event_state.state['segment_start'] and event_state.fast_status['expected_first_pc'] == event_state.state['segment_start'] and (event_state.fast_status['range0_hits'] + event_state.fast_status['range1_hits'] == event_state.fast_status['steps']) and (event_state.fast_status['range0_start'] == event_state.state['range0'][0]) and (event_state.fast_status['range0_end'] == event_state.state['range0'][1]) and (event_state.fast_status['range1_start'] == run.FC_SPTM_RUNTIME_TEXT[0]) and (event_state.fast_status['range1_end'] == run.FC_SPTM_RUNTIME_TEXT[1]) and (event_state.fast_status['terminal_pc'] == event_state.expected_pc) and (event_state.fast_status['max_steps'] == event_state.state['max_steps']), aggregate_budget=event_state.aggregate_steps <= run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS)
        event_state.stage_record.update(source_hex=event_state.source_word.hex(), live_hex=event_state.code_live.hex(), pa=hex(event_state.code_leaf['pa']), filter_status=event_state.fast_status, aggregate_steps=event_state.aggregate_steps)
        event_state.next_stage = event_state.next_pc = None
        if event_state.stage_name == 'seek-entry':
            event_state.args = tuple((int(event_state.ctx.regs[index]) for index in range(4)))
            event_state.pac_mask = (1 << 40) - 1
            event_state.caller_return = run.FC_XNU_RUNTIME_TEXT[0] & ~event_state.pac_mask | int(event_state.ctx.regs[30]) & event_state.pac_mask
            event_state.caller_callsite = event_state.caller_return - 4
            event_state.caller_linked = run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED + event_state.caller_callsite - run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY
            event_state.caller_leaf = run.translate(event_state.caller_callsite, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_survey_page)
            event_state.caller_live = run.iface.readmem(event_state.caller_leaf['pa'], 4)
            event_state.caller_offset = event_state.kernel_segment['fileoff'] + event_state.caller_linked - event_state.kernel_segment['va']
            event_state.caller_source = run.sources['kernelcache'][event_state.caller_offset:event_state.caller_offset + 4]
            event_state.caller_word = run.struct.unpack('<I', event_state.caller_source)[0] if len(event_state.caller_source) == 4 else 0
            event_state.immediate = event_state.caller_word & 67108863
            if event_state.immediate & 1 << 25:
                event_state.immediate -= 1 << 26
            event_state.caller_target = event_state.caller_callsite + (event_state.immediate << 2)
            if event_state.args[0] == 0 or event_state.args[0] & run.PAGE - 1 or (not run.base <= event_state.args[0] < run.base + run.guest_size):
                raise ValueError('Phase53 survey physical address is not an owned page')
            if event_state.args[1] > 255 or event_state.args[2] > 255:
                raise ValueError('Phase53 survey frame type is not u8')
            event_state.fte_before = capture_fte_neighborhood(event_state.args[0])
            event_state.center = event_state.fte_before['records'][1]
            event_state.checks.update(pa_aligned=event_state.args[0] != 0 and event_state.args[0] & run.PAGE - 1 == 0, pa_owned=run.base <= event_state.args[0] < run.base + run.guest_size, type_from_u8=event_state.args[1] <= 255, type_to_u8=event_state.args[2] <= 255, caller_in_xnu=run.FC_XNU_RUNTIME_TEXT[0] <= event_state.caller_callsite < run.FC_XNU_RUNTIME_TEXT[1], caller_source_bl=event_state.caller_word & 4227858432 == 2483027968, caller_live=event_state.caller_live == event_state.caller_source, caller_targets_wrapper=event_state.caller_target == run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY, caller_level_three=event_state.caller_leaf['level'] == 3, caller_access_flag=event_state.caller_leaf['access_flag'], fte_pointer_level_three=event_state.fte_before['pointer_level_three'], fte_pointer_access_flag=event_state.fte_before['pointer_access_flag'], fte_records_complete=all((item['complete'] for item in event_state.fte_before['records'])), fte_records_level_three=all((item['level_three'] for item in event_state.fte_before['records'])), fte_records_access_flag=all((item['access_flag'] for item in event_state.fte_before['records'])), fte_center_unlocked=event_state.center['in_flight_ops'] == 0, fte_center_type=event_state.center['type'] == event_state.args[1] & 255, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS)
            event_state.current_call = dict(index=event_state.state['completed_calls'], args=[hex(value) for value in event_state.args], pa=hex(event_state.args[0]), type_from=hex(event_state.args[1] & 4294967295), type_to=hex(event_state.args[2] & 4294967295), flags=hex(event_state.args[3]), x30=hex(int(event_state.ctx.regs[30])), caller_return=hex(event_state.caller_return), caller_callsite=hex(event_state.caller_callsite), caller_linked=hex(event_state.caller_linked), caller_source_hex=event_state.caller_source.hex(), caller_live_hex=event_state.caller_live.hex(), frame_table_before=event_state.fte_before)
            event_state.state['current_call'] = event_state.current_call
            event_state.next_stage = 'seek-genter'
            event_state.next_pc = run.FC_XNU_PHASE53_GENTER
        elif event_state.stage_name == 'seek-genter':
            event_state.current_call = event_state.state['current_call']
            event_state.expected_args = tuple((int(value, 0) for value in event_state.current_call['args']))
            event_state.selector_leaf = run.translate(run.FC_XNU_PHASE53_GENTER_PREVIOUS, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_survey_page)
            event_state.selector_live = run.iface.readmem(event_state.selector_leaf['pa'], 4)
            event_state.selector_offset = event_state.kernel_segment['fileoff'] + run.FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED - event_state.kernel_segment['va']
            event_state.selector_source = run.sources['kernelcache'][event_state.selector_offset:event_state.selector_offset + 4]
            event_state.expected_selector = run.struct.pack('<I', run.FC_XNU_PHASE53_GENTER_PREVIOUS_WORD)
            event_state.checks.update(selector_source=event_state.selector_source == event_state.expected_selector, selector_live=event_state.selector_live == event_state.expected_selector and event_state.selector_live == event_state.selector_source, selector_level_three=event_state.selector_leaf['level'] == 3, selector_access_flag=event_state.selector_leaf['access_flag'], genter_selector=int(event_state.ctx.regs[16]) == 1, args_unchanged=tuple((int(event_state.ctx.regs[index]) for index in range(4))) == event_state.expected_args, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_GENTER_PREVIOUS, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS)
            event_state.current_call['genter'] = dict(selector_source_hex=event_state.selector_source.hex(), selector_live_hex=event_state.selector_live.hex())
            event_state.next_stage = 'seek-genter-return'
            event_state.next_pc = run.FC_XNU_PHASE53_GENTER_RETURN
        elif event_state.stage_name == 'seek-wrapper-retab':
            event_state.current_call = event_state.state['current_call']
            event_state.args = tuple((int(value, 0) for value in event_state.current_call['args']))
            event_state.fte_after = capture_fte_neighborhood(event_state.args[0])
            event_state.center = event_state.fte_after['records'][1]
            event_state.before = event_state.current_call['frame_table_before']
            event_state.checks.update(filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_PREVIOUS, restored_caller=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == int(event_state.current_call['x30'], 0) & (1 << 40) - 1, fte_base_stable=event_state.fte_after['fte_base'] == event_state.before['fte_base'], fte_center_stable=event_state.fte_after['center_va'] == event_state.before['center_va'], fte_pointer_level_three=event_state.fte_after['pointer_level_three'], fte_pointer_access_flag=event_state.fte_after['pointer_access_flag'], fte_records_complete=all((item['complete'] for item in event_state.fte_after['records'])), fte_records_level_three=all((item['level_three'] for item in event_state.fte_after['records'])), fte_records_access_flag=all((item['access_flag'] for item in event_state.fte_after['records'])), fte_center_unlocked=event_state.center['in_flight_ops'] == 0, fte_center_type=event_state.center['type'] == event_state.args[2] & 255)
            event_state.current_call['frame_table_after'] = event_state.fte_after
        event_state.stage_record['checks'] = event_state.checks
        event_state.stage_record['complete'] = all(event_state.checks.values())
        if event_state.stage_name == 'seek-entry':
            event_state.state['calls'].append(event_state.state['current_call'])
        event_state.state['current_call'][event_state.stage_name] = event_state.stage_record
        run.report['xnu_phase53_retype_survey']['calls'] = list(event_state.state['calls'])
        if event_state.stage_record['complete'] and event_state.next_stage is not None:
            event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, event_state.next_pc, event_state.state['max_steps'], event_state.ctx.elr)
            event_state.state.update(stage=event_state.next_stage, range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.ctx.elr, terminal_pc=event_state.next_pc, aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'] + 1)
            event_state.stage_record['next_enable_status'] = event_state.enabled_status
            run.report['xnu_phase53_retype_survey'].update(current_stage=event_state.next_stage, terminal_pc=hex(event_state.next_pc), aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'])
            event_state.event.update(kind='phase53-survey-' + event_state.stage_name, pc=event_state.ctx.elr, checks=event_state.checks)
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.stage_record['complete']:
            event_state.state['aggregate_steps'] = event_state.aggregate_steps
            event_state.state['completed_calls'] += 1
            event_state.target_type = int(event_state.state['current_call']['type_to'], 0)
            event_state.target_found = event_state.target_type in run.FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES
            event_state.primary_target = int(event_state.state['current_call']['type_from'], 0) == 11 and event_state.target_type == 20
            event_state.state['current_call'].update(complete=True, target_found=event_state.target_found, primary_target=event_state.primary_target)
            run.report['xnu_phase53_retype_survey'].update(completed_calls=event_state.state['completed_calls'], aggregate_steps=event_state.aggregate_steps, target_found=event_state.target_found, primary_target_found=event_state.primary_target, calls=list(event_state.state['calls']))
            event_state.state['active'] = False
            if event_state.target_found and event_state.primary_target and (int(event_state.state['current_call']['flags'], 0) == 3) and (int(event_state.state['current_call']['caller_callsite'], 0) == run.FC_XNU_PHASE53_PRIMARY_RETYPE_CALL) and (int(event_state.state['current_call']['caller_return'], 0) == run.FC_XNU_PHASE53_PRIMARY_RETYPE_RETURN) and run.a.xnu_phase53_descriptor_bind:
                run.report['xnu_phase53_retype_survey']['complete'] = True
                event_state.caller_mode = int(event_state.ctx.spsr) & 15
                if event_state.caller_mode != 4:
                    raise ValueError('Phase53 descriptor-bind caller is not EL1t')
                event_state.caller_sp = int(event_state.ctx.sp[0])
                event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, run.FC_XNU_PHASE53_TWIG_BRANCH, run.FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS, event_state.ctx.elr)
                run.phase53_descriptor_bind_state.update(active=True, roots=event_state.roots, range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.ctx.elr, terminal_pc=run.FC_XNU_PHASE53_TWIG_BRANCH, stage='twig-branch', aggregate_steps=0, rearms=1, world_transitions=[], stages=[], target_pa=int(event_state.state['current_call']['pa'], 0), target_fte=event_state.state['current_call']['frame_table_after'], caller_sp=event_state.caller_sp, report_key='xnu_phase53_descriptor_bind', aggregate_limit=run.FC_XNU_PHASE53_DESCRIPTOR_BIND_TOTAL_STEPS, rearm_limit=run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS, max_steps=run.FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS)
                run.report.setdefault('xnu_phase53_descriptor_bind', {}).update(activated=True, current_stage='twig-branch', terminal_pc=hex(run.FC_XNU_PHASE53_TWIG_BRANCH), expected_first_pc=hex(event_state.ctx.elr), target_pa=event_state.state['current_call']['pa'], survey_call_index=event_state.state['current_call']['index'], caller_sp=hex(event_state.caller_sp), aggregate_steps=0, rearms=1, stages=[], world_transitions=[], activation_enable_status=event_state.enabled_status)
                event_state.stage_record['next_enable_status'] = event_state.enabled_status
                event_state.event.update(kind='phase53-descriptor-bind-start', pc=event_state.ctx.elr, checks=event_state.checks)
                event_state.ctx.spsr.SS = 1
                run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                run.report.pop('stop_reason', None)
                event_state.ret = run.EXC_RET.HANDLED
            elif event_state.target_found:
                run.report['xnu_phase53_retype_survey']['complete'] = True
                run.report['stop_reason'] = 'phase53-retype-survey-target-reached'
            elif event_state.state['completed_calls'] >= event_state.state['limit']:
                run.report['xnu_phase53_retype_survey']['limit_reached'] = True
                run.report['stop_reason'] = 'phase53-retype-survey-call-limit-reached'
            elif event_state.state['rearms'] >= run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS:
                run.report['stop_reason'] = 'phase53-retype-survey-rearm-limit-reached'
            else:
                event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY, event_state.state['max_steps'], event_state.ctx.elr)
                event_state.state.update(active=True, stage='seek-entry', range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.ctx.elr, terminal_pc=run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY, rearms=event_state.state['rearms'] + 1)
                event_state.stage_record['next_enable_status'] = event_state.enabled_status
                run.report['xnu_phase53_retype_survey'].update(current_stage='seek-entry', terminal_pc=hex(run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY), rearms=event_state.state['rearms'])
                event_state.event.update(kind='phase53-survey-next-call', pc=event_state.ctx.elr, checks=event_state.checks)
                event_state.ctx.spsr.SS = 1
                run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                run.report.pop('stop_reason', None)
                event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.state['active'] = False
            run.report['xnu_phase53_retype_survey']['rejection'] = event_state.stage_record
            run.report['stop_reason'] = 'phase53-retype-survey-' + event_state.stage_name + '-gate-rejected'
    except Exception as survey_gate_error:
        event_state.checks['gate_readback'] = False
        event_state.stage_record.update(checks=event_state.checks, complete=False, error=str(survey_gate_error))
        event_state.state['active'] = False
        run.report['xnu_phase53_retype_survey']['rejection'] = event_state.stage_record
        run.report['stop_reason'] = 'phase53-retype-survey-' + event_state.stage_name + '-gate-rejected'

def handle_bounded_step_limit(run, event_state):
    event_state.ctx = event_state.native_ctx if run.handoff_state.get('native') else run.iface.readstruct(event_state.info, run.ExcInfo)
    event_state.state = run.phase53_retype_survey_state
    event_state.fast_status = run.txm_sstep_fast_path.status()
    event_state.aggregate_steps = event_state.state['aggregate_steps'] + event_state.fast_status['steps']
    event_state.checks = {'filter_limit': not event_state.fast_status['active'] and event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_LIMIT, 'filter_exact_budget': event_state.fast_status['steps'] == event_state.state['max_steps'], 'filter_last_pc': event_state.fast_status['last_pc'] == event_state.ctx.elr, 'filter_segment': event_state.fast_status['first_pc'] == event_state.state['segment_start'] and event_state.fast_status['expected_first_pc'] == event_state.state['segment_start'] and (event_state.fast_status['range0_hits'] + event_state.fast_status['range1_hits'] == event_state.fast_status['steps']), 'filter_contract': event_state.fast_status['range0_start'] == event_state.state['range0'][0] and event_state.fast_status['range0_end'] == event_state.state['range0'][1] and (event_state.fast_status['range1_start'] == run.FC_SPTM_RUNTIME_TEXT[0]) and (event_state.fast_status['range1_end'] == run.FC_SPTM_RUNTIME_TEXT[1]) and (event_state.fast_status['terminal_pc'] == run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY) and (event_state.fast_status['max_steps'] == event_state.state['max_steps']), 'aggregate_budget': event_state.aggregate_steps <= run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS}
    event_state.record = dict(stage='seek-entry', pc=hex(event_state.ctx.elr), completed_calls=event_state.state['completed_calls'], filter_status=event_state.fast_status, aggregate_steps=event_state.aggregate_steps, checks=event_state.checks, complete=all(event_state.checks.values()))
    event_state.state['active'] = False
    if event_state.record['complete']:
        run.report['xnu_phase53_retype_survey'].update(complete=True, bounded_no_target=True, target_found=False, completed_calls=event_state.state['completed_calls'], aggregate_steps=event_state.aggregate_steps, bounded_exhaustion=event_state.record)
        run.report['stop_reason'] = 'phase53-retype-survey-step-limit-reached'
        event_state.event.update(kind='phase53-survey-step-limit', pc=event_state.ctx.elr, checks=event_state.checks)
    else:
        run.report['xnu_phase53_retype_survey']['rejection'] = event_state.record
        run.report['stop_reason'] = 'phase53-retype-survey-seek-entry-gate-rejected'


def handle_hvc_site(run, event_state):
    native_ctx = event_state.native_ctx
    native_phase53_retype_hvc_site = event_state.native_phase53_retype_hvc_site
    phase53_retype_hvc_state = run.phase53_retype_hvc_state
    phase53_kernel_runtime = run.phase53_kernel_runtime
    phase53_kernel_source = run.phase53_kernel_source
    phase53_read_live = run.phase53_read_live
    phase53_wrapper_snapshot = run.phase53_wrapper_snapshot
    phase53_capture_fte = run.phase53_capture_fte
    phase53_fte_checks = run.phase53_fte_checks
    phase53_restore_retype_hvcs = run.phase53_restore_retype_hvcs
    txm_sstep_fast_path = run.txm_sstep_fast_path
    gl1_fast_redirect = run.gl1_fast_redirect
    Gl1FastRedirect = run.Gl1FastRedirect
    struct = run.struct
    base, guest_size, PAGE = run.base, run.guest_size, run.PAGE
    report, a = run.report, run.a
    iface, info, event = run.iface, event_state.info, event_state.event
    u, MDSCR_EL1, EXC_RET, ExcInfo = run.u, run.MDSCR_EL1, run.EXC_RET, run.ExcInfo
    TTBR0_EL12, TTBR1_EL12 = run.TTBR0_EL12, run.TTBR1_EL12
    FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED = run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED
    FC_XNU_RUNTIME_TEXT = run.FC_XNU_RUNTIME_TEXT
    FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES = run.FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES
    FC_XNU_PHASE53_PRIMARY_RETYPE_CALL = run.FC_XNU_PHASE53_PRIMARY_RETYPE_CALL
    FC_XNU_PHASE53_PRIMARY_RETYPE_RETURN = run.FC_XNU_PHASE53_PRIMARY_RETYPE_RETURN
    FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB = run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB
    FC_XNU_PHASE53_TWIG_BRANCH = run.FC_XNU_PHASE53_TWIG_BRANCH
    FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS = run.FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS
    FC_SPTM_RUNTIME_TEXT = run.FC_SPTM_RUNTIME_TEXT
    ctx = native_ctx
    state = phase53_retype_hvc_state
    site = native_phase53_retype_hvc_site
    roots = state['roots']
    phase = site.phase
    runtime_pc = phase53_kernel_runtime(site.linked_pc)
    checks = {
        'state_active': state.get('active') is True,
        'mode': state.get('mode') == 'three-site-hvc',
        'expected_stage': state.get('stage') == {
            'PRE': 'hvc-pre', 'GENTER': 'hvc-genter',
            'POST': 'hvc-post'}[phase],
        'exact_esr': int(ctx.esr) ==
            (0x5a000000 | site.hvc_immediate),
        'exact_post_pc': int(ctx.elr) == runtime_pc + 4,
        'el1t': (int(ctx.spsr) & 15) == 4,
        'saved_ss_clear': not bool(int(ctx.spsr) & (1 << 21)),
        'physical_ss_clear': not bool(int(u.mrs(MDSCR_EL1)) & 1),
        'translation_roots_stable': (
            int(u.mrs(TTBR0_EL12)) == roots['ttbr0'] and
            int(u.mrs(TTBR1_EL12)) == roots['ttbr1']),
    }
    record = dict(
        phase=phase, pc=hex(int(ctx.elr)),
        source_pc=hex(runtime_pc), esr=hex(int(ctx.esr)),
        spsr=hex(int(ctx.spsr)))
    try:
        source = phase53_kernel_source(site.linked_pc, 4)
        code_leaf, live = phase53_read_live(
            roots, runtime_pc, 4)
        wrapper = phase53_wrapper_snapshot(roots)
        checks.update(
            source_word=source == struct.pack('<I', site.source_word),
            live_hvc=live == struct.pack('<I', site.hvc_word),
            code_level_three=code_leaf['level'] == 3,
            code_access_flag=code_leaf['access_flag'],
            wrapper_source_exact=wrapper['source_exact'],
            wrapper_live_exact=wrapper['live_exact'],
            wrapper_level_three=wrapper['level_three'],
            wrapper_access_flag=wrapper['access_flag'])
        record.update(
            source_hex=source.hex(), live_hex=live.hex(),
            code_pa=hex(code_leaf['pa']), wrapper=wrapper)

        if phase == 'PRE':
            frame_sp = int(ctx.sp[0])
            frame_leaf, frame = phase53_read_live(
                roots, frame_sp, 16)
            saved_fp, saved_lr = struct.unpack('<QQ', frame)
            args = tuple(int(ctx.regs[index]) for index in range(4))
            pac_mask = (1 << 40) - 1
            wrapper_runtime = phase53_kernel_runtime(
                FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED)
            caller_return = ((FC_XNU_RUNTIME_TEXT[0] & ~pac_mask) |
                             (int(ctx.regs[30]) & pac_mask))
            caller_callsite = caller_return - 4
            caller_linked = (
                FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED +
                caller_callsite - wrapper_runtime)
            caller_source = phase53_kernel_source(caller_linked, 4)
            caller_leaf, caller_live = phase53_read_live(
                roots, caller_callsite, 4)
            caller_word = struct.unpack('<I', caller_source)[0]
            immediate = caller_word & 0x3ffffff
            if immediate & (1 << 25):
                immediate -= 1 << 26
            caller_target = caller_callsite + (immediate << 2)
            if (args[0] == 0 or args[0] & (PAGE - 1) or
                    not base <= args[0] < base + guest_size):
                raise ValueError(
                    'Phase53 HVC physical address is not an owned page')
            if args[1] > 0xff or args[2] > 0xff:
                raise ValueError(
                    'Phase53 HVC frame type is not u8')
            fte_before = phase53_capture_fte(roots, args[0])
            checks.update(
                frame_sp_aligned=frame_sp & 15 == 0,
                frame_level_three=frame_leaf['level'] == 3,
                frame_access_flag=frame_leaf['access_flag'],
                saved_fp_exact=saved_fp == int(ctx.regs[29]),
                saved_lr_exact=saved_lr == int(ctx.regs[30]),
                pa_aligned=args[0] & (PAGE - 1) == 0,
                pa_owned=base <= args[0] < base + guest_size,
                type_from_u8=args[1] <= 0xff,
                type_to_u8=args[2] <= 0xff,
                caller_in_xnu=FC_XNU_RUNTIME_TEXT[0] <=
                    caller_callsite < FC_XNU_RUNTIME_TEXT[1],
                caller_source_bl=(caller_word & 0xfc000000) ==
                    0x94000000,
                caller_live=caller_live == caller_source,
                caller_targets_wrapper=caller_target ==
                    wrapper_runtime,
                caller_level_three=caller_leaf['level'] == 3,
                caller_access_flag=caller_leaf['access_flag'])
            checks.update(phase53_fte_checks(
                'fte_before', fte_before, args[1]))
            current_call = dict(
                index=state['completed_calls'],
                args=[hex(value) for value in args],
                pa=hex(args[0]),
                type_from=hex(args[1] & 0xffffffff),
                type_to=hex(args[2] & 0xffffffff),
                flags=hex(args[3]), x30=hex(int(ctx.regs[30])),
                frame_sp=hex(frame_sp),
                saved_fp=hex(saved_fp), saved_lr=hex(saved_lr),
                caller_return=hex(caller_return),
                caller_callsite=hex(caller_callsite),
                caller_linked=hex(caller_linked),
                caller_source_hex=caller_source.hex(),
                caller_live_hex=caller_live.hex(),
                frame_table_before=fte_before)
            record.update(
                call_index=state['completed_calls'],
                frame_sp=hex(frame_sp), frame_pa=hex(frame_leaf['pa']),
                frame_hex=frame.hex(), args=current_call['args'],
                caller_callsite=hex(caller_callsite),
                frame_table=fte_before)
            if not all(checks.values()):
                raise ValueError('Phase53 PRE HVC gate rejected')
            transition = state['machine'].observe(
                int(ctx.elr), struct.unpack('<I', live)[0])
            current_call['pre'] = dict(
                **record, checks=checks, complete=True,
                transition=transition)
            state['current_call'] = current_call
            state['calls'].append(current_call)
            state['stage'] = 'hvc-genter'
            ctx.regs[29] = frame_sp
            report['xnu_phase53_retype_survey'].update(
                current_stage='hvc-genter', calls=list(state['calls']))
            report['xnu_phase53_retype_hvc_fast_path'].update(
                current_stage='GENTER', expected_phase='GENTER',
                state_machine=state['machine'].snapshot(),
                calls=list(state['calls']))
            event.update(
                kind='phase53-retype-hvc-pre', pc=ctx.elr,
                esr=int(ctx.esr), spsr=int(ctx.spsr),
                regs=list(ctx.regs), sp=list(ctx.sp), checks=checks)
            iface.writemem(info, ExcInfo.build(ctx))
            report.pop('stop_reason', None)
            event_state.ret = EXC_RET.HANDLED
        elif phase == 'GENTER':
            current_call = state['current_call']
            frame_sp = int(current_call['frame_sp'], 0)
            frame_leaf, frame = phase53_read_live(
                roots, frame_sp, 16)
            saved_fp, saved_lr = struct.unpack('<QQ', frame)
            expected_args = tuple(int(value, 0) for value in
                                  current_call['args'])
            gl1_before = gl1_fast_redirect.status()
            checks.update(
                frame_pointer_exact=int(ctx.regs[29]) == frame_sp,
                frame_level_three=frame_leaf['level'] == 3,
                frame_access_flag=frame_leaf['access_flag'],
                saved_fp_unchanged=saved_fp ==
                    int(current_call['saved_fp'], 0),
                saved_lr_unchanged=saved_lr ==
                    int(current_call['saved_lr'], 0),
                helper1_return=int(ctx.regs[30]) == runtime_pc,
                args_unchanged=tuple(
                    int(ctx.regs[index]) for index in range(4)) ==
                    expected_args,
                gl1_fast_enabled=gl1_before['enabled'])
            record.update(
                call_index=current_call['index'],
                frame_sp=hex(frame_sp), frame_pa=hex(frame_leaf['pa']),
                frame_hex=frame.hex(),
                args=[hex(int(ctx.regs[index])) for index in range(4)],
                gl1_status=gl1_before)
            if not all(checks.values()):
                raise ValueError('Phase53 GENTER HVC gate rejected')
            transition = state['machine'].observe(
                int(ctx.elr), struct.unpack('<I', live)[0])
            ctx.regs[16] = 1
            current_call['gl1_before'] = gl1_before
            current_call['genter'] = dict(
                **record, checks=checks, complete=True,
                transition=transition)
            state['stage'] = 'hvc-post'
            report['xnu_phase53_retype_survey'].update(
                current_stage='hvc-post', calls=list(state['calls']))
            report['xnu_phase53_retype_hvc_fast_path'].update(
                current_stage='POST', expected_phase='POST',
                state_machine=state['machine'].snapshot(),
                calls=list(state['calls']))
            event.update(
                kind='phase53-retype-hvc-genter', pc=ctx.elr,
                esr=int(ctx.esr), spsr=int(ctx.spsr),
                regs=list(ctx.regs), sp=list(ctx.sp), checks=checks)
            iface.writemem(info, ExcInfo.build(ctx))
            report.pop('stop_reason', None)
            event_state.ret = EXC_RET.HANDLED
        else:
            current_call = state['current_call']
            frame_sp = int(current_call['frame_sp'], 0)
            frame_leaf, frame = phase53_read_live(
                roots, frame_sp, 16)
            saved_fp, saved_lr = struct.unpack('<QQ', frame)
            args = tuple(int(value, 0) for value in
                         current_call['args'])
            fte_after = phase53_capture_fte(roots, args[0])
            before = current_call['frame_table_before']
            gl1_before = current_call['gl1_before']
            gl1_after = gl1_fast_redirect.status()
            counter_names = Gl1FastRedirect.STATUS_FIELDS[8:]
            counter_deltas = {
                name: gl1_after[name] - gl1_before[name]
                for name in counter_names}
            aggregate_deltas = {
                name: gl1_after[name] - gl1_before[name]
                for name in ('handled', 'forwarded')}
            checks.update(
                frame_pointer_exact=int(ctx.regs[29]) == frame_sp,
                frame_level_three=frame_leaf['level'] == 3,
                frame_access_flag=frame_leaf['access_flag'],
                saved_fp_unchanged=saved_fp ==
                    int(current_call['saved_fp'], 0),
                saved_lr_unchanged=saved_lr ==
                    int(current_call['saved_lr'], 0),
                helper2_return=int(ctx.regs[30]) == runtime_pc,
                fte_base_stable=fte_after['fte_base'] ==
                    before['fte_base'],
                fte_center_stable=fte_after['center_va'] ==
                    before['center_va'],
                gl1_fast_still_enabled=gl1_after['enabled'],
                gl1_config_unchanged=all(
                    gl1_after[name] == gl1_before[name] for name in
                    Gl1FastRedirect.STATUS_FIELDS[:6]),
                gl1_handled_delta=(gl1_after['handled'] -
                                   gl1_before['handled']) == 7,
                gl1_forwarded_delta=(gl1_after['forwarded'] -
                                     gl1_before['forwarded']) == 0,
                gl1_each_site_once=all(
                    delta == 1 for delta in
                    counter_deltas.values()))
            checks.update(phase53_fte_checks(
                'fte_after', fte_after, args[2]))
            record.update(
                call_index=current_call['index'],
                frame_sp=hex(frame_sp), frame_pa=hex(frame_leaf['pa']),
                frame_hex=frame.hex(), result=hex(int(ctx.regs[0])),
                frame_table=fte_after, gl1_status=gl1_after,
                gl1_counter_deltas=counter_deltas,
                gl1_aggregate_deltas=aggregate_deltas)
            if not all(checks.values()):
                raise ValueError('Phase53 POST HVC gate rejected')
            transition = state['machine'].observe(
                int(ctx.elr), struct.unpack('<I', live)[0])
            ctx.sp[0] = frame_sp
            current_call.update(
                post=dict(**record, checks=checks, complete=True,
                          transition=transition),
                frame_table_after=fte_after,
                retype_result=hex(int(ctx.regs[0])), complete=True)
            state['completed_calls'] += 1
            if (state['machine'].completed_calls !=
                    state['completed_calls']):
                raise ValueError(
                    'Phase53 HVC completion counters diverged')
            target_type = args[2]
            target_found = target_type in \
                FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES
            primary_target = args[1] == 0xb and target_type == 0x14
            current_call.update(
                target_found=target_found,
                primary_target=primary_target)
            state['stage'] = 'hvc-pre'
            report['xnu_phase53_retype_survey'].update(
                completed_calls=state['completed_calls'],
                target_found=target_found,
                primary_target_found=primary_target,
                calls=list(state['calls']))
            report['xnu_phase53_retype_hvc_fast_path'].update(
                current_stage='PRE', expected_phase='PRE',
                completed_calls=state['completed_calls'],
                state_machine=state['machine'].snapshot(),
                calls=list(state['calls']))
            event.update(
                kind='phase53-retype-hvc-post', pc=ctx.elr,
                esr=int(ctx.esr), spsr=int(ctx.spsr),
                regs=list(ctx.regs), sp=list(ctx.sp), checks=checks,
                target_found=target_found,
                primary_target=primary_target)

            descriptor_target = (
                target_found and primary_target and args[3] == 3 and
                int(current_call['caller_callsite'], 0) ==
                    FC_XNU_PHASE53_PRIMARY_RETYPE_CALL and
                int(current_call['caller_return'], 0) ==
                    FC_XNU_PHASE53_PRIMARY_RETYPE_RETURN and
                a.xnu_phase53_descriptor_bind)
            terminal = (target_found or
                        state['completed_calls'] >= state['limit'])
            if terminal:
                restoration = phase53_restore_retype_hvcs(roots)
                state['patches_live'] = False
                report['xnu_phase53_retype_hvc_fast_path'].update(
                    enabled=False, patches_restored=True,
                    restoration=restoration)
                current_call['hvc_restoration'] = restoration
            if descriptor_target:
                report['xnu_phase53_retype_survey']['complete'] = True
                caller_sp = frame_sp + 16
                enabled_status = txm_sstep_fast_path.enable(
                    FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
                    FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB, 4,
                    ctx.elr)
                state.update(
                    active=True, stage='epilogue',
                    filter_disabled=False,
                    descriptor_pending=dict(
                        target_pa=args[0], target_fte=fte_after,
                        caller_sp=caller_sp,
                        call_index=current_call['index']))
                report['xnu_phase53_retype_hvc_fast_path'].update(
                    current_stage='EPILOGUE',
                    expected_phase='EPILOGUE')
                current_call['post']['epilogue_enable_status'] = (
                    enabled_status)
                event['kind'] = 'phase53-retype-hvc-epilogue-start'
                ctx.spsr.SS = 1
                u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
                iface.writemem(info, ExcInfo.build(ctx))
                report.pop('stop_reason', None)
                event_state.ret = EXC_RET.HANDLED
            elif target_found:
                state['active'] = False
                report['xnu_phase53_retype_survey']['complete'] = True
                report['stop_reason'] = (
                    'phase53-retype-survey-target-reached')
            elif state['completed_calls'] >= state['limit']:
                state['active'] = False
                report['xnu_phase53_retype_survey'].update(
                    complete=True, bounded_no_target=True,
                    limit_reached=True)
                report['stop_reason'] = (
                    'phase53-retype-survey-call-limit-reached')
            else:
                ctx.spsr.SS = 0
                u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) & ~1)
                iface.writemem(info, ExcInfo.build(ctx))
                report.pop('stop_reason', None)
                event_state.ret = EXC_RET.HANDLED
    except Exception as retype_hvc_error:
        checks['gate_readback'] = False
        record.update(checks=checks, complete=False,
                      error=str(retype_hvc_error))
        state['active'] = False
        state['failed'] = True
        state.get('current_call', {}).setdefault(
            phase.lower(), record)
        report['xnu_phase53_retype_hvc_fast_path'].update(
            failed=True, patches_live=state.get('patches_live'),
            rejection=record,
            state_machine=(state['machine'].snapshot()
                if state.get('machine') is not None else None))
        report['xnu_phase53_retype_survey']['rejection'] = record
        report['stop_reason'] = (
            'phase53-retype-hvc-' + phase.lower() +
            '-gate-rejected')


def handle_hvc_epilogue(run, event_state):
    native_ctx = event_state.native_ctx
    phase53_retype_hvc_state = run.phase53_retype_hvc_state
    phase53_descriptor_bind_state = run.phase53_descriptor_bind_state
    phase53_kernel_runtime = run.phase53_kernel_runtime
    phase53_kernel_source = run.phase53_kernel_source
    phase53_read_live = run.phase53_read_live
    phase53_wrapper_snapshot = run.phase53_wrapper_snapshot
    txm_sstep_fast_path = run.txm_sstep_fast_path
    struct, report = run.struct, run.report
    iface, info, event = run.iface, event_state.info, event_state.event
    u, MDSCR_EL1, EXC_RET, ExcInfo = run.u, run.MDSCR_EL1, run.EXC_RET, run.ExcInfo
    FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED = run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED
    FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_WORD = run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_WORD
    FC_XNU_PHASE53_RETYPE_WRAPPER_WORDS = run.FC_XNU_PHASE53_RETYPE_WRAPPER_WORDS
    FC_VEL2_STEP_FILTER_TERMINAL = run.FC_VEL2_STEP_FILTER_TERMINAL
    FC_XNU_RUNTIME_TEXT = run.FC_XNU_RUNTIME_TEXT
    FC_SPTM_RUNTIME_TEXT = run.FC_SPTM_RUNTIME_TEXT
    FC_XNU_PHASE53_TWIG_BRANCH = run.FC_XNU_PHASE53_TWIG_BRANCH
    FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS = run.FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS
    FC_XNU_PHASE53_DESCRIPTOR_BIND_TOTAL_STEPS = run.FC_XNU_PHASE53_DESCRIPTOR_BIND_TOTAL_STEPS
    FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS = run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS
    ctx = native_ctx
    state = phase53_retype_hvc_state
    roots = state['roots']
    pending = state['descriptor_pending']
    current_call = state['current_call']
    expected_pc = phase53_kernel_runtime(
        FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED)
    checks = {
        'exact_pc': int(ctx.elr) == expected_pc,
        'el1t': (int(ctx.spsr) & 15) == 4,
        'saved_ss_clear': not bool(int(ctx.spsr) & (1 << 21)),
        'restored_sp': int(ctx.sp[0]) == pending['caller_sp'],
        'restored_fp': int(ctx.regs[29]) ==
            int(current_call['saved_fp'], 0),
        'restored_lr': int(ctx.regs[30]) ==
            int(current_call['saved_lr'], 0),
    }
    record = dict(stage='epilogue', pc=hex(int(ctx.elr)),
                  esr=hex(int(ctx.esr)), spsr=hex(int(ctx.spsr)))
    try:
        filter_status = txm_sstep_fast_path.status()
        retab_source = phase53_kernel_source(
            FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED, 4)
        retab_leaf, retab_live = phase53_read_live(
            roots, expected_pc, 4)
        ldp_source = phase53_kernel_source(
            FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED - 4, 4)
        ldp_leaf, ldp_live = phase53_read_live(
            roots, expected_pc - 4, 4)
        wrapper = phase53_wrapper_snapshot(roots, patched=False)
        checks.update(
            retab_source=retab_source == struct.pack(
                '<I', FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_WORD),
            retab_live=retab_live == retab_source,
            retab_level_three=retab_leaf['level'] == 3,
            retab_access_flag=retab_leaf['access_flag'],
            ldp_source=ldp_source == struct.pack(
                '<I', FC_XNU_PHASE53_RETYPE_WRAPPER_WORDS[8]),
            ldp_live=ldp_live == ldp_source,
            ldp_level_three=ldp_leaf['level'] == 3,
            ldp_access_flag=ldp_leaf['access_flag'],
            wrapper_source_exact=wrapper['source_exact'],
            wrapper_restored_exact=wrapper['live_exact'],
            filter_terminal=(not filter_status['active'] and
                filter_status['status'] ==
                    FC_VEL2_STEP_FILTER_TERMINAL),
            filter_one_epilogue_step=
                filter_status['steps'] == 1,
            filter_first_pc=filter_status['first_pc'] ==
                expected_pc - 4,
            filter_last_pc=filter_status['last_pc'] == expected_pc,
            filter_previous_pc=filter_status['previous_pc'] ==
                expected_pc - 4,
            filter_contract=(
                filter_status['terminal_pc'] == expected_pc and
                filter_status['expected_first_pc'] ==
                    expected_pc - 4 and
                filter_status['max_steps'] == 4 and
                filter_status['range0_start'] ==
                    FC_XNU_RUNTIME_TEXT[0] and
                filter_status['range0_end'] ==
                    FC_XNU_RUNTIME_TEXT[1] and
                filter_status['range1_start'] ==
                    FC_SPTM_RUNTIME_TEXT[0] and
                filter_status['range1_end'] ==
                    FC_SPTM_RUNTIME_TEXT[1]))
        record.update(
            filter_status=filter_status,
            retab_source_hex=retab_source.hex(),
            retab_live_hex=retab_live.hex(),
            ldp_source_hex=ldp_source.hex(),
            ldp_live_hex=ldp_live.hex(), wrapper=wrapper)
        if not all(checks.values()):
            raise ValueError('Phase53 HVC epilogue gate rejected')
        enabled_status = txm_sstep_fast_path.enable(
            FC_XNU_RUNTIME_TEXT, FC_SPTM_RUNTIME_TEXT,
            FC_XNU_PHASE53_TWIG_BRANCH,
            FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS,
            ctx.elr)
        state['active'] = False
        phase53_descriptor_bind_state.update(
            active=True, roots=roots,
            range0=FC_XNU_RUNTIME_TEXT,
            segment_start=ctx.elr,
            terminal_pc=FC_XNU_PHASE53_TWIG_BRANCH,
            stage='twig-branch', aggregate_steps=0,
            rearms=1, world_transitions=[], stages=[],
            target_pa=pending['target_pa'],
            target_fte=pending['target_fte'],
            caller_sp=pending['caller_sp'],
            report_key='xnu_phase53_descriptor_bind',
            aggregate_limit=
                FC_XNU_PHASE53_DESCRIPTOR_BIND_TOTAL_STEPS,
            rearm_limit=
                FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS,
            max_steps=FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS)
        report['xnu_phase53_descriptor_bind'].update(
            activated=True, current_stage='twig-branch',
            terminal_pc=hex(FC_XNU_PHASE53_TWIG_BRANCH),
            expected_first_pc=hex(ctx.elr),
            target_pa=hex(pending['target_pa']),
            survey_call_index=pending['call_index'],
            caller_sp=hex(pending['caller_sp']),
            aggregate_steps=0, rearms=1, stages=[],
            world_transitions=[],
            activation_enable_status=enabled_status)
        record.update(checks=checks, complete=True,
                      next_enable_status=enabled_status)
        current_call['epilogue'] = record
        report['xnu_phase53_retype_hvc_fast_path'].update(
            current_stage='complete', expected_phase='complete',
            epilogue=record, calls=list(state['calls']))
        event.update(kind='phase53-descriptor-bind-start',
                     pc=ctx.elr, checks=checks)
        ctx.spsr.SS = 1
        u.msr(MDSCR_EL1, u.mrs(MDSCR_EL1) | 1)
        iface.writemem(info, ExcInfo.build(ctx))
        report.pop('stop_reason', None)
        event_state.ret = EXC_RET.HANDLED
    except Exception as epilogue_error:
        checks['gate_readback'] = False
        record.update(checks=checks, complete=False,
                      error=str(epilogue_error))
        state['active'] = False
        current_call['epilogue'] = record
        report['xnu_phase53_retype_hvc_fast_path'].update(
            failed=True, rejection=record,
            calls=list(state['calls']))
        report['xnu_phase53_retype_survey']['rejection'] = record
        report['stop_reason'] = (
            'phase53-retype-hvc-epilogue-gate-rejected')
