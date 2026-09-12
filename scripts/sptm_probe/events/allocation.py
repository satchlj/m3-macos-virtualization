# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Allocation event handlers extracted from the original probe callback."""

def handle_authenticated_return(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.phase53_filter_state = run.phase53_descriptor_bind_state if run.phase53_descriptor_bind_state.get('active') else run.phase53_retype_survey_state if run.phase53_retype_survey_state.get('active') else run.phase53_allocation_trace_state
    event_state.phase53_report_key = run.phase53_descriptor_bind_state.get('report_key', 'xnu_phase53_descriptor_bind') if run.phase53_descriptor_bind_state.get('active') else 'xnu_phase53_retype_survey' if run.phase53_retype_survey_state.get('active') else 'xnu_phase53_allocation_trace'
    event_state.pac_mask = (1 << 40) - 1
    event_state.return_pc = run.FC_XNU_RUNTIME_TEXT[0] & ~event_state.pac_mask | int(event_state.ctx.regs[30]) & event_state.pac_mask
    event_state.transition = dict(kind='authenticated-retab', trap_pc=hex(event_state.ctx.elr), return_pc=hex(event_state.return_pc), spsr=hex(int(event_state.ctx.spsr)), x30=hex(int(event_state.ctx.regs[30])))
    event_state.checks = {'exact_spsr': int(event_state.ctx.spsr) == run.FC_XNU_TXM_HANDLER_CMD1_RETAB_SPSR, 'return_pc_in_xnu': run.FC_XNU_RUNTIME_TEXT[0] <= event_state.return_pc < run.FC_XNU_RUNTIME_TEXT[1]}
    try:
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.current_range = event_state.phase53_filter_state['range0']
        event_state.segment_start = event_state.phase53_filter_state['segment_start']
        event_state.roots = event_state.phase53_filter_state['roots']

        def read_phase53_retab_page(table):
            if table & run.PAGE - 1 or not run.base <= table < table + run.PAGE <= run.base + run.guest_size:
                raise ValueError('Phase53 RETAB table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)
        event_state.retab_leaf = run.translate(event_state.ctx.elr, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_phase53_retab_page)
        event_state.retab_live = run.iface.readmem(event_state.retab_leaf['pa'], 4)
        event_state.kernel_segment = run.layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        event_state.retab_source_offset = event_state.kernel_segment['fileoff'] + run.FC_XNU_TXM_HANDLER_CMD1_RETAB_LINKED - event_state.kernel_segment['va']
        event_state.retab_source = run.sources['kernelcache'][event_state.retab_source_offset:event_state.retab_source_offset + 4]
        event_state.expected_retab = run.struct.pack('<I', run.FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD)
        event_state.phase53_max_steps = event_state.phase53_filter_state.get('max_steps', run.FC_XNU_PHASE53_FAST_STEPS)
        event_state.survey_aggregate = event_state.phase53_filter_state.get('aggregate_steps', 0) + event_state.fast_status['steps']
        event_state.checks.update(source_word=event_state.retab_source == event_state.expected_retab, live_word=event_state.retab_live == event_state.expected_retab and event_state.retab_live == event_state.retab_source, level_three=event_state.retab_leaf['level'] == 3, access_flag=event_state.retab_leaf['access_flag'], filter_outside=not event_state.fast_status['active'] and event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_OUTSIDE, filter_bounded=0 < event_state.fast_status['steps'] <= event_state.phase53_max_steps, filter_last_pc=event_state.fast_status['last_pc'] == event_state.ctx.elr, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS, filter_segment=event_state.fast_status['first_pc'] == event_state.segment_start and event_state.fast_status['expected_first_pc'] == event_state.segment_start and (event_state.fast_status['range0_hits'] + event_state.fast_status['range1_hits'] == event_state.fast_status['steps']), filter_contract=event_state.fast_status['range0_start'] == event_state.current_range[0] and event_state.fast_status['range0_end'] == event_state.current_range[1] and (event_state.current_range == run.FC_TXM_RUNTIME_TEXT) and (event_state.fast_status['range1_start'] == run.FC_SPTM_RUNTIME_TEXT[0]) and (event_state.fast_status['range1_end'] == run.FC_SPTM_RUNTIME_TEXT[1]) and (event_state.fast_status['terminal_pc'] == event_state.phase53_filter_state['terminal_pc']) and (event_state.fast_status['max_steps'] == event_state.phase53_max_steps))
        if run.phase53_retype_survey_state.get('active') or run.phase53_descriptor_bind_state.get('active'):
            event_state.aggregate_limit = event_state.phase53_filter_state.get('aggregate_limit', run.FC_XNU_PHASE53_DESCRIPTOR_BIND_TOTAL_STEPS if run.phase53_descriptor_bind_state.get('active') else run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS)
            event_state.rearm_limit = event_state.phase53_filter_state.get('rearm_limit', run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS if run.phase53_descriptor_bind_state.get('active') else run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS)
            event_state.checks.update(aggregate_budget=event_state.survey_aggregate <= event_state.aggregate_limit, rearm_budget=event_state.phase53_filter_state['rearms'] < event_state.rearm_limit)
        event_state.transition.update(pa=hex(event_state.retab_leaf['pa']), source_hex=event_state.retab_source.hex(), live_hex=event_state.retab_live.hex(), prior_status=event_state.fast_status)
        if all(event_state.checks.values()):
            event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, event_state.phase53_filter_state['terminal_pc'], event_state.phase53_max_steps, event_state.ctx.elr)
            event_state.phase53_filter_state['range0'] = run.FC_XNU_RUNTIME_TEXT
            event_state.phase53_filter_state['segment_start'] = event_state.ctx.elr
            if run.phase53_retype_survey_state.get('active') or run.phase53_descriptor_bind_state.get('active'):
                event_state.phase53_filter_state['aggregate_steps'] = event_state.survey_aggregate
                event_state.phase53_filter_state['rearms'] += 1
                run.report[event_state.phase53_report_key].update(aggregate_steps=event_state.survey_aggregate, rearms=event_state.phase53_filter_state['rearms'])
            event_state.transition.update(enable_status=event_state.enabled_status, checks=event_state.checks, complete=True)
            event_state.phase53_filter_state['world_transitions'].append(event_state.transition)
            run.report[event_state.phase53_report_key]['world_transitions'] = list(event_state.phase53_filter_state['world_transitions'])
            event_state.event.update(kind='phase53-authenticated-retab', pc=event_state.ctx.elr, esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs), far=event_state.ctx.far, sp=list(event_state.ctx.sp), checks=event_state.checks)
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.transition.update(checks=event_state.checks, complete=False)
            event_state.phase53_filter_state['active'] = False
            run.report[event_state.phase53_report_key]['world_transition_rejection'] = event_state.transition
            run.report['stop_reason'] = 'phase53-retab-transition-gate-rejected'
    except Exception as transition_error:
        event_state.checks['gate_readback'] = False
        event_state.transition.update(checks=event_state.checks, error=str(transition_error), complete=False)
        event_state.phase53_filter_state['active'] = False
        run.report[event_state.phase53_report_key]['world_transition_rejection'] = event_state.transition
        run.report['stop_reason'] = 'phase53-retab-transition-gate-rejected'

def handle_guarded_return(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.transition = dict(kind='guarded-service-return', pc=hex(event_state.ctx.elr), spsr=hex(int(event_state.ctx.spsr)), x30=hex(int(event_state.ctx.regs[30])))
    event_state.checks = {'exact_spsr': int(event_state.ctx.spsr) == run.FC_XNU_PHASE53_GENTER_RETURN_SPSR, 'wrapper_caller': int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_GENTER_PREVIOUS & (1 << 40) - 1}
    try:
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.roots = run.phase53_allocation_trace_state['roots']

        def read_phase53_guarded_return_page(table):
            if table & run.PAGE - 1 or not run.base <= table < table + run.PAGE <= run.base + run.guest_size:
                raise ValueError('Phase53 guarded-return table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)
        event_state.selector_leaf = run.translate(run.FC_XNU_PHASE53_GENTER_PREVIOUS, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_phase53_guarded_return_page)
        event_state.genter_leaf = run.translate(run.FC_XNU_PHASE53_GENTER, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_phase53_guarded_return_page)
        event_state.gexit_leaf = run.translate(run.FC_XNU_PHASE53_GEXIT, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_phase53_guarded_return_page)
        event_state.return_leaf = run.translate(run.FC_XNU_PHASE53_GENTER_RETURN, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_phase53_guarded_return_page)
        event_state.selector_live = run.iface.readmem(event_state.selector_leaf['pa'], 4)
        event_state.genter_live = run.iface.readmem(event_state.genter_leaf['pa'], 4)
        event_state.gexit_live = run.iface.readmem(event_state.gexit_leaf['pa'], 4)
        event_state.return_live = run.iface.readmem(event_state.return_leaf['pa'], 4)
        event_state.sptm_segment = run.layout['images']['sptm']['segments']['__TEXT_EXEC']
        event_state.kernel_segment = run.layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        event_state.selector_source_offset = event_state.kernel_segment['fileoff'] + run.FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED - event_state.kernel_segment['va']
        event_state.genter_source_offset = event_state.kernel_segment['fileoff'] + run.FC_XNU_PHASE53_GENTER_LINKED - event_state.kernel_segment['va']
        event_state.gexit_source_offset = event_state.sptm_segment['fileoff'] + run.FC_XNU_PHASE53_GEXIT_LINKED - event_state.sptm_segment['va']
        event_state.return_source_offset = event_state.kernel_segment['fileoff'] + run.FC_XNU_PHASE53_GENTER_RETURN_LINKED - event_state.kernel_segment['va']
        event_state.gexit_source = run.sources['sptm'][event_state.gexit_source_offset:event_state.gexit_source_offset + 4]
        event_state.selector_source = run.sources['kernelcache'][event_state.selector_source_offset:event_state.selector_source_offset + 4]
        event_state.genter_source = run.sources['kernelcache'][event_state.genter_source_offset:event_state.genter_source_offset + 4]
        event_state.return_source = run.sources['kernelcache'][event_state.return_source_offset:event_state.return_source_offset + 4]
        event_state.expected_gexit = run.struct.pack('<I', run.FC_XNU_PHASE53_GEXIT_WORD)
        event_state.expected_selector = run.struct.pack('<I', run.FC_XNU_PHASE53_GENTER_PREVIOUS_WORD)
        event_state.expected_genter = run.struct.pack('<I', run.FC_XNU_PHASE53_GENTER_WORD)
        event_state.expected_return = run.struct.pack('<I', run.FC_XNU_PHASE53_GENTER_RETURN_WORD)
        event_state.current_range = run.phase53_allocation_trace_state['range0']
        event_state.segment_start = run.phase53_allocation_trace_state['segment_start']
        event_state.checks.update(gexit_source=event_state.gexit_source == event_state.expected_gexit, gexit_live=event_state.gexit_live == event_state.expected_gexit and event_state.gexit_live == event_state.gexit_source, selector_source=event_state.selector_source == event_state.expected_selector, selector_live=event_state.selector_live == event_state.expected_selector and event_state.selector_live == event_state.selector_source, genter_source=event_state.genter_source == event_state.expected_genter, genter_live=event_state.genter_live == event_state.expected_genter and event_state.genter_live == event_state.genter_source, return_source=event_state.return_source == event_state.expected_return, return_live=event_state.return_live == event_state.expected_return and event_state.return_live == event_state.return_source, gexit_level_three=event_state.gexit_leaf['level'] == 3, gexit_access_flag=event_state.gexit_leaf['access_flag'], selector_level_three=event_state.selector_leaf['level'] == 3, selector_access_flag=event_state.selector_leaf['access_flag'], genter_level_three=event_state.genter_leaf['level'] == 3, genter_access_flag=event_state.genter_leaf['access_flag'], return_level_three=event_state.return_leaf['level'] == 3, return_access_flag=event_state.return_leaf['access_flag'], filter_outside=not event_state.fast_status['active'] and event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_OUTSIDE, filter_bounded=0 < event_state.fast_status['steps'] <= run.FC_XNU_PHASE53_FAST_STEPS, filter_last_pc=event_state.fast_status['last_pc'] == event_state.ctx.elr, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS, filter_segment=event_state.fast_status['first_pc'] == event_state.segment_start and event_state.fast_status['expected_first_pc'] == event_state.segment_start and (event_state.fast_status['range0_hits'] + event_state.fast_status['range1_hits'] == event_state.fast_status['steps']), filter_contract=event_state.current_range == run.FC_TXM_RUNTIME_TEXT and event_state.fast_status['range0_start'] == event_state.current_range[0] and (event_state.fast_status['range0_end'] == event_state.current_range[1]) and (event_state.fast_status['range1_start'] == run.FC_SPTM_RUNTIME_TEXT[0]) and (event_state.fast_status['range1_end'] == run.FC_SPTM_RUNTIME_TEXT[1]) and (event_state.fast_status['terminal_pc'] == run.phase53_allocation_trace_state['terminal_pc']) and (event_state.fast_status['max_steps'] == run.FC_XNU_PHASE53_FAST_STEPS))
        event_state.transition.update(gexit_pa=hex(event_state.gexit_leaf['pa']), gexit_source_hex=event_state.gexit_source.hex(), gexit_live_hex=event_state.gexit_live.hex(), selector_pa=hex(event_state.selector_leaf['pa']), selector_source_hex=event_state.selector_source.hex(), selector_live_hex=event_state.selector_live.hex(), genter_pa=hex(event_state.genter_leaf['pa']), genter_source_hex=event_state.genter_source.hex(), genter_live_hex=event_state.genter_live.hex(), return_pa=hex(event_state.return_leaf['pa']), return_source_hex=event_state.return_source.hex(), return_live_hex=event_state.return_live.hex(), prior_status=event_state.fast_status)
        if all(event_state.checks.values()):
            event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, run.phase53_allocation_trace_state['terminal_pc'], run.FC_XNU_PHASE53_FAST_STEPS, event_state.ctx.elr)
            run.phase53_allocation_trace_state.update(range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.ctx.elr)
            event_state.transition.update(enable_status=event_state.enabled_status, checks=event_state.checks, complete=True)
            run.phase53_allocation_trace_state['world_transitions'].append(event_state.transition)
            run.report['xnu_phase53_allocation_trace']['world_transitions'] = list(run.phase53_allocation_trace_state['world_transitions'])
            event_state.event.update(kind='phase53-guarded-service-return', pc=event_state.ctx.elr, esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs), far=event_state.ctx.far, sp=list(event_state.ctx.sp), checks=event_state.checks)
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.transition.update(checks=event_state.checks, complete=False)
            run.phase53_allocation_trace_state['active'] = False
            run.report['xnu_phase53_allocation_trace']['world_transition_rejection'] = event_state.transition
            run.report['stop_reason'] = 'phase53-guarded-service-return-gate-rejected'
    except Exception as transition_error:
        event_state.checks['gate_readback'] = False
        event_state.transition.update(checks=event_state.checks, error=str(transition_error), complete=False)
        run.phase53_allocation_trace_state['active'] = False
        run.report['xnu_phase53_allocation_trace']['world_transition_rejection'] = event_state.transition
        run.report['stop_reason'] = 'phase53-guarded-service-return-gate-rejected'

def handle_allocation_step(run, event_state):
    event_state.ctx = event_state.native_ctx if run.handoff_state.get('native') else run.iface.readstruct(event_state.info, run.ExcInfo)
    event_state.stage_name = run.phase53_allocation_trace_state.get('stage', 'allocation-call')
    event_state.stage_specs = {'allocation-call': (run.FC_XNU_PHASE53_ALLOC_CALL, run.FC_XNU_PHASE53_ALLOC_CALL_LINKED, run.FC_XNU_PHASE53_ALLOC_CALL_WORD, 'internal-allocation-call', run.FC_XNU_PHASE53_ALLOC_INTERNAL_CALL), 'internal-allocation-call': (run.FC_XNU_PHASE53_ALLOC_INTERNAL_CALL, run.FC_XNU_PHASE53_ALLOC_INTERNAL_CALL_LINKED, run.FC_XNU_PHASE53_ALLOC_INTERNAL_CALL_WORD, 'allocation-return', run.FC_XNU_PHASE53_ALLOC_RETURN), 'allocation-return': (run.FC_XNU_PHASE53_ALLOC_RETURN, run.FC_XNU_PHASE53_ALLOC_RETURN_LINKED, run.FC_XNU_PHASE53_ALLOC_RETURN_WORD, 'post-ubfiz', run.FC_XNU_PHASE53_POST_UBFIZ), 'post-ubfiz': (run.FC_XNU_PHASE53_POST_UBFIZ, run.FC_XNU_PHASE53_POST_UBFIZ_LINKED, run.FC_XNU_PHASE53_POST_UBFIZ_WORD, 'retype-call', run.FC_XNU_PHASE53_RETYPE_CALL), 'retype-call': (run.FC_XNU_PHASE53_RETYPE_CALL, run.FC_XNU_PHASE53_RETYPE_CALL_LINKED, run.FC_XNU_PHASE53_RETYPE_CALL_WORD, 'genter', run.FC_XNU_PHASE53_GENTER), 'genter': (run.FC_XNU_PHASE53_GENTER, run.FC_XNU_PHASE53_GENTER_LINKED, run.FC_XNU_PHASE53_GENTER_WORD, 'retype-return', run.FC_XNU_PHASE53_RETYPE_RETURN), 'retype-return': (run.FC_XNU_PHASE53_RETYPE_RETURN, run.FC_XNU_PHASE53_RETYPE_RETURN_LINKED, run.FC_XNU_PHASE53_RETYPE_RETURN_WORD, None, None)}
    event_state.expected_pc, event_state.linked_pc, event_state.expected_word, event_state.next_stage, event_state.next_pc = event_state.stage_specs[event_state.stage_name]
    event_state.stage_record = dict(stage=event_state.stage_name, pc=hex(event_state.ctx.elr), esr=hex(int(event_state.ctx.esr)), spsr=hex(int(event_state.ctx.spsr)), sp_el0=hex(int(event_state.ctx.sp[0])), x0=hex(int(event_state.ctx.regs[0])), x1=hex(int(event_state.ctx.regs[1])), x2=hex(int(event_state.ctx.regs[2])), x3=hex(int(event_state.ctx.regs[3])), x16=hex(int(event_state.ctx.regs[16])), x21=hex(int(event_state.ctx.regs[21])), x30=hex(int(event_state.ctx.regs[30])))
    event_state.checks = {'lower_sync': event_state.reason == run.START.EXCEPTION_LOWER and event_state.code == run.EXC.SYNC, 'software_step': int(event_state.ctx.esr) >> 26 == 50, 'exact_pc': event_state.ctx.elr == event_state.expected_pc}
    try:
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.roots = run.phase53_allocation_trace_state['roots']

        def read_phase53_page(table):
            if table & run.PAGE - 1 or not run.base <= table < table + run.PAGE <= run.base + run.guest_size:
                raise ValueError('Phase53 table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)
        event_state.code_leaf = run.translate(event_state.ctx.elr, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_phase53_page)
        event_state.code_live = run.iface.readmem(event_state.code_leaf['pa'], 4)
        event_state.kernel_segment = run.layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        event_state.code_source_offset = event_state.kernel_segment['fileoff'] + event_state.linked_pc - event_state.kernel_segment['va']
        event_state.code_source = run.sources['kernelcache'][event_state.code_source_offset:event_state.code_source_offset + 4]
        event_state.actual_linked_pc = event_state.linked_pc + event_state.ctx.elr - event_state.expected_pc
        event_state.actual_source_offset = event_state.kernel_segment['fileoff'] + event_state.actual_linked_pc - event_state.kernel_segment['va']
        event_state.actual_source = run.sources['kernelcache'][event_state.actual_source_offset:event_state.actual_source_offset + 4]
        event_state.expected_code = run.struct.pack('<I', event_state.expected_word)
        event_state.segment_start = run.phase53_allocation_trace_state['segment_start']
        event_state.current_range = run.phase53_allocation_trace_state['range0']
        event_state.checks.update(source_word=event_state.code_source == event_state.expected_code, live_word=event_state.code_live == event_state.expected_code and event_state.code_live == event_state.code_source, level_three=event_state.code_leaf['level'] == 3, access_flag=event_state.code_leaf['access_flag'], filter_terminal=not event_state.fast_status['active'] and event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_TERMINAL and (event_state.fast_status['last_pc'] == event_state.expected_pc), filter_bounded=0 < event_state.fast_status['steps'] <= run.FC_XNU_PHASE53_FAST_STEPS, filter_contract=event_state.fast_status['first_pc'] == event_state.segment_start and event_state.fast_status['expected_first_pc'] == event_state.segment_start and (event_state.fast_status['range0_hits'] + event_state.fast_status['range1_hits'] == event_state.fast_status['steps']) and (event_state.fast_status['range0_start'] == event_state.current_range[0]) and (event_state.fast_status['range0_end'] == event_state.current_range[1]) and (event_state.current_range == run.FC_XNU_RUNTIME_TEXT) and (event_state.fast_status['range1_start'] == run.FC_SPTM_RUNTIME_TEXT[0]) and (event_state.fast_status['range1_end'] == run.FC_SPTM_RUNTIME_TEXT[1]) and (event_state.fast_status['terminal_pc'] == event_state.expected_pc) and (event_state.fast_status['max_steps'] == run.FC_XNU_PHASE53_FAST_STEPS))
        if event_state.stage_name == 'post-ubfiz':
            event_state.allocated_pa = int(event_state.ctx.regs[21])
            event_state.checks.update(ubfiz_previous=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_UBFIZ_PC, allocated_pa_aligned=event_state.allocated_pa != 0 and event_state.allocated_pa & run.PAGE - 1 == 0, allocated_pa_owned=run.base <= event_state.allocated_pa < run.base + run.guest_size)
            run.phase53_allocation_trace_state.update(allocated_pa=event_state.allocated_pa, fte_capture_available=False)
            try:
                event_state.pointer_leaf = run.translate(run.FC_SPTM_PHASE53_FTE_BASE_POINTER, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_phase53_page)
                event_state.pointer_raw = run.iface.readmem(event_state.pointer_leaf['pa'], 8)
                event_state.fte_base = run.struct.unpack('<Q', event_state.pointer_raw)[0]
                event_state.fte_va = event_state.fte_base + (event_state.allocated_pa - run.base >> 10 & 18014398509481968)
                event_state.fte_leaf = run.translate(event_state.fte_va, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_phase53_page)
                event_state.fte_before = run.iface.readmem(event_state.fte_leaf['pa'], 16)
                event_state.capture_checks = dict(pointer_level_three=event_state.pointer_leaf['level'] == 3, pointer_access_flag=event_state.pointer_leaf['access_flag'], fte_level_three=event_state.fte_leaf['level'] == 3, fte_access_flag=event_state.fte_leaf['access_flag'], record_complete=len(event_state.fte_before) == 16, record_unlocked=len(event_state.fte_before) == 16 and event_state.fte_before[:2] == b'\x00\x00', record_type_from=len(event_state.fte_before) == 16 and event_state.fte_before[2] == 11)
                event_state.capture_complete = all(event_state.capture_checks.values())
                run.phase53_allocation_trace_state.update(fte_capture_available=event_state.capture_complete, fte_base=event_state.fte_base, fte_va=event_state.fte_va, fte_pa=event_state.fte_leaf['pa'], fte_before=event_state.fte_before)
                event_state.stage_record['frame_table_before'] = dict(captured=event_state.capture_complete, allocated_pa=hex(event_state.allocated_pa), base_pointer_va=hex(run.FC_SPTM_PHASE53_FTE_BASE_POINTER), base_pointer_pa=hex(event_state.pointer_leaf['pa']), base_pointer_hex=event_state.pointer_raw.hex(), fte_base=hex(event_state.fte_base), fte_va=hex(event_state.fte_va), fte_pa=hex(event_state.fte_leaf['pa']), hex=event_state.fte_before.hex(), sha256=run.hashlib.sha256(event_state.fte_before).hexdigest(), checks=event_state.capture_checks)
            except Exception as frame_table_capture_error:
                event_state.stage_record['frame_table_before'] = dict(captured=False, allocated_pa=hex(event_state.allocated_pa), base_pointer_va=hex(run.FC_SPTM_PHASE53_FTE_BASE_POINTER), error=str(frame_table_capture_error))
        elif event_state.stage_name == 'retype-call':
            event_state.checks.update(retype_pa=int(event_state.ctx.regs[0]) == run.phase53_allocation_trace_state['allocated_pa'], retype_from=int(event_state.ctx.regs[1]) & 4294967295 == 11, retype_to=int(event_state.ctx.regs[2]) & 4294967295 == 41, retype_flags=int(event_state.ctx.regs[3]) == 0)
        elif event_state.stage_name == 'genter':
            event_state.checks.update(genter_selector=int(event_state.ctx.regs[16]) == 1, genter_previous=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_GENTER_PREVIOUS)
        elif event_state.stage_name == 'allocation-return':
            run.phase53_allocation_trace_state['allocator_result'] = int(event_state.ctx.regs[0])
            event_state.stage_record['allocator_result'] = hex(int(event_state.ctx.regs[0]))
        elif event_state.stage_name == 'retype-return':
            event_state.allocated_pa = run.phase53_allocation_trace_state['allocated_pa']
            event_state.checks['allocated_pa_stable'] = int(event_state.ctx.regs[21]) == event_state.allocated_pa
            if run.phase53_allocation_trace_state.get('fte_capture_available'):
                event_state.checks['retype_record_pointer'] = int(event_state.ctx.regs[0]) == run.phase53_allocation_trace_state['fte_va']
                event_state.pointer_leaf = run.translate(run.FC_SPTM_PHASE53_FTE_BASE_POINTER, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_phase53_page)
                event_state.pointer_raw = run.iface.readmem(event_state.pointer_leaf['pa'], 8)
                event_state.fte_base = run.struct.unpack('<Q', event_state.pointer_raw)[0]
                event_state.fte_va = event_state.fte_base + (event_state.allocated_pa - run.base >> 10 & 18014398509481968)
                event_state.fte_leaf = run.translate(event_state.fte_va, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_phase53_page)
                event_state.fte_after = run.iface.readmem(event_state.fte_leaf['pa'], 16)
                event_state.fte_before = run.phase53_allocation_trace_state['fte_before']
                event_state.changed = [dict(offset=i, before=event_state.fte_before[i], after=event_state.fte_after[i], xor=event_state.fte_before[i] ^ event_state.fte_after[i]) for i in range(16) if event_state.fte_before[i] != event_state.fte_after[i]]
                event_state.checks.update(fte_base_stable=event_state.fte_base == run.phase53_allocation_trace_state['fte_base'], fte_va_stable=event_state.fte_va == run.phase53_allocation_trace_state['fte_va'], fte_pa_stable=event_state.fte_leaf['pa'] == run.phase53_allocation_trace_state['fte_pa'], fte_record_complete=len(event_state.fte_after) == 16, fte_record_unlocked=event_state.fte_after[:2] == b'\x00\x00', fte_type_from=event_state.fte_before[2] == 11, fte_type_to=event_state.fte_after[2] == 41)
                event_state.stage_record['frame_table_after'] = dict(captured=True, base_pointer_hex=event_state.pointer_raw.hex(), fte_base=hex(event_state.fte_base), fte_va=hex(event_state.fte_va), fte_pa=hex(event_state.fte_leaf['pa']), hex=event_state.fte_after.hex(), sha256=run.hashlib.sha256(event_state.fte_after).hexdigest(), changed=bool(event_state.changed), changed_bytes=event_state.changed, type_before=hex(event_state.fte_before[2]), type_after=hex(event_state.fte_after[2]), retype_result=hex(int(event_state.ctx.regs[0])), retype_status=hex(int(event_state.ctx.regs[0])))
            else:
                event_state.stage_record['frame_table_after'] = dict(captured=False, reason='pre-retype snapshot unavailable', retype_result=hex(int(event_state.ctx.regs[0])), retype_status=hex(int(event_state.ctx.regs[0])))
        event_state.stage_record.update(pa=hex(event_state.code_leaf['pa']), expected_pc=hex(event_state.expected_pc), source_pc=hex(event_state.expected_pc), source_hex=event_state.code_source.hex(), actual_source_pc=hex(event_state.ctx.elr), actual_source_hex=event_state.actual_source.hex(), live_hex=event_state.code_live.hex(), filter_status=event_state.fast_status)
        if event_state.stage_name == 'allocation-call':
            event_state.stage_record['target_pc'] = hex(run.FC_XNU_PHASE53_ALLOC_ENTRY)
    except Exception as allocation_gate_error:
        event_state.checks['gate_readback'] = False
        event_state.stage_record['error'] = str(allocation_gate_error)
    event_state.stage_record['checks'] = event_state.checks
    event_state.stage_record['complete'] = all(event_state.checks.values())
    run.report['xnu_phase53_allocation_trace'].setdefault('stages', []).append(event_state.stage_record)
    event_state.event.update(kind='phase53-' + event_state.stage_name, pc=event_state.ctx.elr, esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs), far=event_state.ctx.far, sp=list(event_state.ctx.sp), checks=event_state.checks)
    if event_state.stage_record['complete'] and event_state.next_stage is not None:
        try:
            event_state.next_first_pc = event_state.ctx.elr
            event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, event_state.next_pc, run.FC_XNU_PHASE53_FAST_STEPS, event_state.next_first_pc)
            run.phase53_allocation_trace_state.update(stage=event_state.next_stage, range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.next_first_pc, terminal_pc=event_state.next_pc)
            event_state.stage_record['next_enable_status'] = event_state.enabled_status
            run.report['xnu_phase53_allocation_trace'].update(current_stage=event_state.next_stage, terminal_pc=hex(event_state.next_pc))
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            run.report.pop('stop_reason', None)
            event_state.ret = run.EXC_RET.HANDLED
        except Exception as next_enable_error:
            run.phase53_allocation_trace_state['active'] = False
            event_state.stage_record['next_enable_error'] = str(next_enable_error)
            run.report['stop_reason'] = 'phase53-' + event_state.stage_name + '-enable-failed'
    else:
        run.phase53_allocation_trace_state['active'] = False
        if event_state.stage_record['complete']:
            event_state.frame_table_after = event_state.stage_record.get('frame_table_after', {})
            run.report['xnu_phase53_allocation_trace'].update(complete=True, sequence_complete=True, frame_table_evidence=bool(event_state.frame_table_after.get('captured')), frame_table_mutation_observed=event_state.frame_table_after.get('changed') if event_state.frame_table_after.get('captured') else None, retype_result=hex(int(event_state.ctx.regs[0])), retype_status=hex(int(event_state.ctx.regs[0])))
            if getattr(run.a, 'xnu_phase53_retype_survey', False):
                try:
                    event_state.roots = run.phase53_allocation_trace_state['roots']
                    if run.a.xnu_phase53_retype_hvc_fast_path:
                        event_state.gl1_status = run.gl1_fast_redirect.status()
                        event_state.expected_gl1 = dict(
                            pc_base=run.FC_IMAGE_BASE,
                            spsr_tag=run.gl1_fast_tags['SPSR_GL1'],
                            aspsr_tag=run.gl1_fast_tags['ASPSR_GL1'],
                            esr_tag=run.gl1_fast_tags['ESR_GL1'],
                            elr_tag=run.gl1_fast_tags['ELR_GL1'])
                        if (not event_state.gl1_status['enabled'] or any(
                                event_state.gl1_status[name] != value for
                                name, value in event_state.expected_gl1.items())):
                            raise ValueError('GL1 fast redirect activation contract changed')
                        if any(run.phase53_kernel_runtime(site.linked_pc) !=
                               site.runtime_pc for site in run.RETYPE_HVC_SITES):
                            raise ValueError('Phase53 HVC runtime slide changed')
                        event_state.wrapper_before = run.phase53_wrapper_snapshot(
                            event_state.roots, patched=False)
                        if not all(event_state.wrapper_before[name] for name in (
                                'source_exact', 'live_exact', 'level_three',
                                'access_flag')):
                            raise ValueError('Phase53 HVC wrapper activation gate rejected')
                        event_state.step_filter_disable = run.txm_sstep_fast_path.disable()
                        run.phase53_retype_hvc_state.update(
                            roots=event_state.roots, patches_live=True)
                        event_state.installs = run.phase53_install_retype_hvcs(event_state.roots)
                        event_state.wrapper = run.phase53_wrapper_snapshot(event_state.roots)
                        if not all(event_state.wrapper[name] for name in (
                                'source_exact', 'live_exact', 'level_three',
                                'access_flag')):
                            run.phase53_restore_retype_hvcs(event_state.roots)
                            run.phase53_retype_hvc_state['patches_live'] = False
                            raise ValueError('Phase53 patched wrapper readback rejected')
                        event_state.machine = run.RetypeHvcStateMachine(
                            run.a.xnu_phase53_retype_survey_limit)
                        run.phase53_retype_hvc_state.update(
                            active=True, mode='three-site-hvc',
                            roots=event_state.roots, stage='hvc-pre',
                            completed_calls=0, calls=[],
                            limit=run.a.xnu_phase53_retype_survey_limit,
                            machine=event_state.machine, patches_live=True,
                            gl1_config={name: event_state.gl1_status[name] for
                                name in run.Gl1FastRedirect.STATUS_FIELDS[:6]},
                            gl1_activation_verified=True, filter_disabled=True,
                            native_continuations=[], continuation_limit=128,
                            repeated_continuation_limit=64)
                        run.report['xnu_phase53_retype_survey'] = dict(
                            requested=True, activated=True, mode='three-site-hvc',
                            current_stage='hvc-pre',
                            call_limit=run.a.xnu_phase53_retype_survey_limit,
                            target_types=[hex(value) for value in
                                run.FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES],
                            primary_target='0xb->0x14', calls=[])
                        run.report['xnu_phase53_retype_hvc_fast_path'].update(
                            activated=True, enabled=True, current_stage='PRE',
                            expected_phase='PRE', completed_calls=0,
                            native_continuation_limit=128,
                            native_continuations=[],
                            wrapper_before=event_state.wrapper_before,
                            installations=event_state.installs,
                            wrapper_activation=event_state.wrapper,
                            step_filter_disable_status=event_state.step_filter_disable,
                            gl1_activation_status=event_state.gl1_status,
                            calls=[])
                        event_state.stage_record['survey_hvc_fast_path'] = True
                        event_state.ctx.spsr.SS = 0
                        run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) & ~1)
                    else:
                        event_state.survey_enable = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY, run.FC_XNU_PHASE53_RETYPE_SURVEY_FAST_STEPS, event_state.ctx.elr)
                        run.phase53_retype_survey_state.update(active=True, roots=event_state.roots, range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.ctx.elr, terminal_pc=run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY, stage='seek-entry', completed_calls=0, aggregate_steps=0, rearms=1, calls=[], max_steps=run.FC_XNU_PHASE53_RETYPE_SURVEY_FAST_STEPS, limit=run.a.xnu_phase53_retype_survey_limit, world_transitions=[])
                        run.report['xnu_phase53_retype_survey'] = dict(requested=True, activated=True, current_stage='seek-entry', terminal_pc=hex(run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY), expected_first_pc=hex(event_state.ctx.elr), call_limit=run.a.xnu_phase53_retype_survey_limit, per_leg_step_limit=run.FC_XNU_PHASE53_RETYPE_SURVEY_FAST_STEPS, aggregate_step_limit=run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS, rearm_limit=run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS, target_types=[hex(value) for value in run.FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES], primary_target='0xb->0x14', enable_status=event_state.survey_enable, calls=[])
                        event_state.stage_record['survey_enable_status'] = event_state.survey_enable
                    event_state.event['kind'] = 'phase53-retype-survey-start'
                    if not run.a.xnu_phase53_retype_hvc_fast_path:
                        event_state.ctx.spsr.SS = 1
                        run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                    run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                    run.report.pop('stop_reason', None)
                    event_state.ret = run.EXC_RET.HANDLED
                except Exception as survey_enable_error:
                    run.phase53_retype_survey_state['active'] = False
                    run.report['xnu_phase53_retype_survey'] = dict(requested=True, activated=False, error=str(survey_enable_error))
                    run.report['stop_reason'] = 'phase53-retype-survey-enable-failed'
            else:
                run.report['stop_reason'] = 'phase53-retype-return-reached'
        else:
            run.report['stop_reason'] = 'phase53-' + event_state.stage_name + '-gate-rejected'
