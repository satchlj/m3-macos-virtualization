# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Retype event handlers extracted from the original probe callback."""


def handle_unrelated_return(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.state = run.phase53_retype_survey_state
    event_state.checks = {
        'exact_spsr': int(event_state.ctx.spsr) ==
            run.FC_XNU_PHASE53_GENTER_RETURN_SPSR,
        'returned_pc_in_xnu': run.FC_XNU_RUNTIME_TEXT[0] <= event_state.ctx.elr <
            run.FC_XNU_RUNTIME_TEXT[1],
    }
    event_state.transition = dict(
        kind='survey-unrelated-gexit-return', pc=hex(event_state.ctx.elr),
        spsr=hex(int(event_state.ctx.spsr)), completed_calls=
            event_state.state['completed_calls'])
    try:
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.roots = event_state.state['roots']
        def read_survey_unrelated_return_page(table):
            if (table & (run.PAGE - 1) or
                    not run.base <= table < table + run.PAGE <=
                        run.base + run.guest_size):
                raise ValueError(
                    'Phase53 survey table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)
        event_state.kernel_segment = run.layout['images']['kernelcache'][
            'segments']['__TEXT_EXEC']
        event_state.sptm_segment = run.layout['images']['sptm'][
            'segments']['__TEXT_EXEC']
        event_state.return_leaf = run.translate(
            event_state.ctx.elr, event_state.roots['ttbr0'], event_state.roots['ttbr1'],
            read_survey_unrelated_return_page)
        event_state.gexit_leaf = run.translate(
            run.FC_XNU_PHASE53_GEXIT, event_state.roots['ttbr0'], event_state.roots['ttbr1'],
            read_survey_unrelated_return_page)
        event_state.return_live = run.iface.readmem(event_state.return_leaf['pa'], 4)
        event_state.gexit_live = run.iface.readmem(event_state.gexit_leaf['pa'], 4)
        event_state.return_linked = (
            run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED + event_state.ctx.elr -
            run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY)
        event_state.return_offset = (event_state.kernel_segment['fileoff'] +
                         event_state.return_linked - event_state.kernel_segment['va'])
        event_state.return_source = run.sources['kernelcache'][
            event_state.return_offset:event_state.return_offset + 4]
        event_state.gexit_offset = (event_state.sptm_segment['fileoff'] +
            run.FC_XNU_PHASE53_GEXIT_LINKED - event_state.sptm_segment['va'])
        event_state.gexit_source = run.sources['sptm'][
            event_state.gexit_offset:event_state.gexit_offset + 4]
        event_state.expected_gexit = run.struct.pack(
            '<I', run.FC_XNU_PHASE53_GEXIT_WORD)
        event_state.aggregate_steps = (event_state.state['aggregate_steps'] +
                           event_state.fast_status['steps'])
        event_state.checks.update(
            return_source_complete=len(event_state.return_source) == 4,
            return_live_source=(len(event_state.return_source) == 4 and
                                event_state.return_live == event_state.return_source),
            return_level_three=event_state.return_leaf['level'] == 3,
            return_access_flag=event_state.return_leaf['access_flag'],
            gexit_source=event_state.gexit_source == event_state.expected_gexit,
            gexit_live=(event_state.gexit_live == event_state.expected_gexit and
                        event_state.gexit_live == event_state.gexit_source),
            gexit_level_three=event_state.gexit_leaf['level'] == 3,
            gexit_access_flag=event_state.gexit_leaf['access_flag'],
            filter_outside=(not event_state.fast_status['active'] and
                event_state.fast_status['status'] ==
                    run.FC_VEL2_STEP_FILTER_OUTSIDE),
            filter_bounded=(0 < event_state.fast_status['steps'] <=
                run.FC_XNU_PHASE53_FAST_STEPS),
            filter_last_pc=event_state.fast_status['last_pc'] == event_state.ctx.elr,
            filter_previous_pc=event_state.fast_status['previous_pc'] ==
                run.FC_XNU_PHASE53_GEXIT,
            filter_segment=(
                event_state.fast_status['first_pc'] == event_state.state['segment_start'] and
                event_state.fast_status['expected_first_pc'] ==
                    event_state.state['segment_start'] and
                event_state.fast_status['range0_hits'] +
                    event_state.fast_status['range1_hits'] ==
                    event_state.fast_status['steps']),
            filter_contract=(
                event_state.fast_status['range0_start'] ==
                    run.FC_TXM_RUNTIME_TEXT[0] and
                event_state.fast_status['range0_end'] ==
                    run.FC_TXM_RUNTIME_TEXT[1] and
                event_state.fast_status['range1_start'] ==
                    run.FC_SPTM_RUNTIME_TEXT[0] and
                event_state.fast_status['range1_end'] ==
                    run.FC_SPTM_RUNTIME_TEXT[1] and
                event_state.fast_status['terminal_pc'] == event_state.state['terminal_pc'] and
                event_state.fast_status['max_steps'] ==
                    run.FC_XNU_PHASE53_FAST_STEPS),
            aggregate_budget=(event_state.aggregate_steps <=
                run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS),
            rearm_budget=(event_state.state['rearms'] <
                run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS))
        event_state.transition.update(
            return_linked=hex(event_state.return_linked),
            return_pa=hex(event_state.return_leaf['pa']),
            return_source_hex=event_state.return_source.hex(),
            return_live_hex=event_state.return_live.hex(),
            gexit_pa=hex(event_state.gexit_leaf['pa']),
            gexit_source_hex=event_state.gexit_source.hex(),
            gexit_live_hex=event_state.gexit_live.hex(),
            prior_status=event_state.fast_status,
            aggregate_steps=event_state.aggregate_steps)
        if all(event_state.checks.values()):
            event_state.enabled_status = run.txm_sstep_fast_path.enable(
                run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT,
                event_state.state['terminal_pc'], run.FC_XNU_PHASE53_FAST_STEPS,
                event_state.ctx.elr)
            event_state.state.update(
                range0=run.FC_XNU_RUNTIME_TEXT,
                segment_start=event_state.ctx.elr,
                aggregate_steps=event_state.aggregate_steps,
                rearms=event_state.state['rearms'] + 1)
            event_state.transition.update(
                checks=event_state.checks, complete=True,
                enable_status=event_state.enabled_status)
            event_state.state['world_transitions'].append(event_state.transition)
            run.report['xnu_phase53_retype_survey'].update(
                world_transitions=list(event_state.state['world_transitions']),
                aggregate_steps=event_state.aggregate_steps,
                rearms=event_state.state['rearms'])
            event_state.event.update(
                kind='phase53-survey-unrelated-gexit-return',
                pc=event_state.ctx.elr, esr=int(event_state.ctx.esr),
                spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs),
                far=event_state.ctx.far, sp=list(event_state.ctx.sp), checks=event_state.checks)
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            run.report.pop('stop_reason', None)
            event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.state['active'] = False
            event_state.transition.update(checks=event_state.checks, complete=False)
            run.report['xnu_phase53_retype_survey'][
                'unrelated_return_rejection'] = event_state.transition
            run.report['stop_reason'] = (
                'phase53-retype-survey-unrelated-return-gate-rejected')
    except Exception as unrelated_return_error:
        event_state.checks['gate_readback'] = False
        event_state.state['active'] = False
        event_state.transition.update(
            checks=event_state.checks, complete=False,
            error=str(unrelated_return_error))
        run.report['xnu_phase53_retype_survey'][
            'unrelated_return_rejection'] = event_state.transition
        run.report['stop_reason'] = (
            'phase53-retype-survey-unrelated-return-gate-rejected')


def handle_guarded_return(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.state = run.phase53_retype_survey_state
    event_state.checks = {
        'exact_spsr': int(event_state.ctx.spsr) ==
            run.FC_XNU_PHASE53_GENTER_RETURN_SPSR,
        'wrapper_link': (int(event_state.ctx.regs[30]) & ((1 << 40) - 1)) ==
            (run.FC_XNU_PHASE53_GENTER_PREVIOUS & ((1 << 40) - 1)),
    }
    event_state.record = dict(stage='seek-genter-return', pc=hex(event_state.ctx.elr),
                  x30=hex(int(event_state.ctx.regs[30])))
    try:
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.roots = event_state.state['roots']
        def read_survey_return_page(table):
            if (table & (run.PAGE - 1) or
                    not run.base <= table < table + run.PAGE <=
                        run.base + run.guest_size):
                raise ValueError(
                    'Phase53 survey table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)
        event_state.kernel_segment = run.layout['images']['kernelcache'][
            'segments']['__TEXT_EXEC']
        event_state.sptm_segment = run.layout['images']['sptm'][
            'segments']['__TEXT_EXEC']
        event_state.code_specs = (
            ('selector', run.FC_XNU_PHASE53_GENTER_PREVIOUS,
             run.FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED,
             run.FC_XNU_PHASE53_GENTER_PREVIOUS_WORD,
             event_state.kernel_segment, run.sources['kernelcache']),
            ('genter', run.FC_XNU_PHASE53_GENTER,
             run.FC_XNU_PHASE53_GENTER_LINKED,
             run.FC_XNU_PHASE53_GENTER_WORD,
             event_state.kernel_segment, run.sources['kernelcache']),
            ('gexit', run.FC_XNU_PHASE53_GEXIT,
             run.FC_XNU_PHASE53_GEXIT_LINKED,
             run.FC_XNU_PHASE53_GEXIT_WORD,
             event_state.sptm_segment, run.sources['sptm']),
            ('return', run.FC_XNU_PHASE53_GENTER_RETURN,
             run.FC_XNU_PHASE53_GENTER_RETURN_LINKED,
             run.FC_XNU_PHASE53_GENTER_RETURN_WORD,
             event_state.kernel_segment, run.sources['kernelcache']))
        event_state.code_evidence = {}
        for event_state.name, event_state.pc, event_state.linked, event_state.word, event_state.segment, event_state.source in event_state.code_specs:
            event_state.leaf = run.translate(event_state.pc, event_state.roots['ttbr0'], event_state.roots['ttbr1'],
                             read_survey_return_page)
            event_state.live = run.iface.readmem(event_state.leaf['pa'], 4)
            event_state.offset = event_state.segment['fileoff'] + event_state.linked - event_state.segment['va']
            event_state.source_bytes = event_state.source[event_state.offset:event_state.offset + 4]
            event_state.expected = run.struct.pack('<I', event_state.word)
            event_state.checks[event_state.name + '_source'] = event_state.source_bytes == event_state.expected
            event_state.checks[event_state.name + '_live'] = (event_state.live == event_state.expected and
                                      event_state.live == event_state.source_bytes)
            event_state.checks[event_state.name + '_level_three'] = event_state.leaf['level'] == 3
            event_state.checks[event_state.name + '_access_flag'] = event_state.leaf['access_flag']
            event_state.code_evidence[event_state.name] = dict(
                pa=hex(event_state.leaf['pa']), source_hex=event_state.source_bytes.hex(),
                live_hex=event_state.live.hex())
        event_state.aggregate_steps = event_state.state['aggregate_steps'] + \
            event_state.fast_status['steps']
        event_state.checks.update(
            filter_stopped=(not event_state.fast_status['active'] and
                ((event_state.state['range0'] == run.FC_TXM_RUNTIME_TEXT and
                  event_state.fast_status['status'] ==
                    run.FC_VEL2_STEP_FILTER_OUTSIDE) or
                 (event_state.state['range0'] == run.FC_XNU_RUNTIME_TEXT and
                  event_state.fast_status['status'] ==
                    run.FC_VEL2_STEP_FILTER_TERMINAL))),
            filter_last_pc=event_state.fast_status['last_pc'] == event_state.ctx.elr,
            filter_previous_pc=event_state.fast_status['previous_pc'] ==
                run.FC_XNU_PHASE53_GEXIT,
            filter_segment=(
                event_state.fast_status['first_pc'] == event_state.state['segment_start'] and
                event_state.fast_status['expected_first_pc'] ==
                    event_state.state['segment_start'] and
                event_state.fast_status['range0_hits'] +
                    event_state.fast_status['range1_hits'] ==
                    event_state.fast_status['steps']),
            filter_contract=(
                event_state.fast_status['range0_start'] == event_state.state['range0'][0] and
                event_state.fast_status['range0_end'] == event_state.state['range0'][1] and
                event_state.fast_status['range1_start'] ==
                    run.FC_SPTM_RUNTIME_TEXT[0] and
                event_state.fast_status['range1_end'] ==
                    run.FC_SPTM_RUNTIME_TEXT[1] and
                event_state.fast_status['terminal_pc'] ==
                    run.FC_XNU_PHASE53_GENTER_RETURN and
                event_state.fast_status['max_steps'] ==
                    run.FC_XNU_PHASE53_FAST_STEPS),
            aggregate_budget=(event_state.aggregate_steps <=
                run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS),
            rearm_budget=(event_state.state['rearms'] <
                run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS))
        event_state.record.update(filter_status=event_state.fast_status,
                      code=event_state.code_evidence,
                      aggregate_steps=event_state.aggregate_steps)
        if all(event_state.checks.values()):
            event_state.enabled_status = run.txm_sstep_fast_path.enable(
                run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT,
                run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB,
                run.FC_XNU_PHASE53_FAST_STEPS, event_state.ctx.elr)
            event_state.state.update(
                stage='seek-wrapper-retab',
                range0=run.FC_XNU_RUNTIME_TEXT,
                segment_start=event_state.ctx.elr,
                terminal_pc=run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB,
                aggregate_steps=event_state.aggregate_steps,
                rearms=event_state.state['rearms'] + 1)
            event_state.record.update(checks=event_state.checks, complete=True,
                          enable_status=event_state.enabled_status)
            event_state.state['current_call']['genter_return'] = event_state.record
            run.report['xnu_phase53_retype_survey'].update(
                current_stage='seek-wrapper-retab',
                terminal_pc=hex(
                    run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB),
                aggregate_steps=event_state.aggregate_steps,
                rearms=event_state.state['rearms'])
            event_state.event.update(kind='phase53-survey-genter-return',
                         pc=event_state.ctx.elr, checks=event_state.checks)
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.state['active'] = False
            event_state.record.update(checks=event_state.checks, complete=False)
            event_state.state.get('current_call', {}).update(
                genter_return=event_state.record)
            run.report['xnu_phase53_retype_survey'][
                'rejection'] = event_state.record
            run.report['stop_reason'] = (
                'phase53-retype-survey-genter-return-gate-rejected')
    except Exception as survey_return_error:
        event_state.checks['gate_readback'] = False
        event_state.state['active'] = False
        event_state.record.update(checks=event_state.checks, complete=False,
                      error=str(survey_return_error))
        event_state.state.get('current_call', {}).update(
            genter_return=event_state.record)
        run.report['xnu_phase53_retype_survey']['rejection'] = event_state.record
        run.report['stop_reason'] = (
            'phase53-retype-survey-genter-return-gate-rejected')


def handle_survey_step(run, event_state):
    event_state.ctx = (event_state.native_ctx if run.handoff_state.get('native') else
           run.iface.readstruct(event_state.info, run.ExcInfo))
    event_state.state = run.phase53_retype_survey_state
    event_state.stage_name = event_state.state['stage']
    event_state.specs = {
        'seek-entry': (
            run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY,
            run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED,
            run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_WORD),
        'seek-genter': (
            run.FC_XNU_PHASE53_GENTER,
            run.FC_XNU_PHASE53_GENTER_LINKED,
            run.FC_XNU_PHASE53_GENTER_WORD),
        'seek-wrapper-retab': (
            run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB,
            run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED,
            run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_WORD),
    }
    event_state.expected_pc, event_state.linked_pc, event_state.expected_word = event_state.specs[event_state.stage_name]
    event_state.checks = {'expected_pc': event_state.ctx.elr == event_state.expected_pc}
    event_state.stage_record = dict(stage=event_state.stage_name, pc=hex(event_state.ctx.elr))
    try:
        event_state.roots = event_state.state['roots']
        def read_survey_page(table):
            if (table & (run.PAGE - 1) or
                    not run.base <= table < table + run.PAGE <=
                        run.base + run.guest_size):
                raise ValueError(
                    'Phase53 survey table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)
        def capture_fte_neighborhood(physical_address):
            pointer_leaf = run.translate(
                run.FC_SPTM_PHASE53_FTE_BASE_POINTER,
                event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_survey_page)
            pointer_raw = run.iface.readmem(pointer_leaf['pa'], 8)
            fte_base = run.struct.unpack('<Q', pointer_raw)[0]
            center_va = fte_base + (
                ((physical_address - run.base) >> 10) &
                0x3ffffffffffff0)
            records = []
            for delta in (-16, 0, 16):
                va = center_va + delta
                leaf = run.translate(va, event_state.roots['ttbr0'], event_state.roots['ttbr1'],
                                 read_survey_page)
                raw = run.iface.readmem(leaf['pa'], 16)
                records.append(dict(
                    delta=delta, va=hex(va), pa=hex(leaf['pa']),
                    hex=raw.hex(), sha256=run.hashlib.sha256(raw).hexdigest(),
                    in_flight_ops=(run.struct.unpack('<H', raw[:2])[0]
                        if len(raw) == 16 else None),
                    type=(raw[2] if len(raw) == 16 else None),
                    complete=len(raw) == 16,
                    level_three=leaf['level'] == 3,
                    access_flag=leaf['access_flag']))
            return dict(
                base_pointer_va=hex(
                    run.FC_SPTM_PHASE53_FTE_BASE_POINTER),
                base_pointer_pa=hex(pointer_leaf['pa']),
                base_pointer_hex=pointer_raw.hex(),
                pointer_level_three=pointer_leaf['level'] == 3,
                pointer_access_flag=pointer_leaf['access_flag'],
                fte_base=hex(fte_base), center_va=hex(center_va),
                records=records)
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.code_leaf = run.translate(event_state.ctx.elr, event_state.roots['ttbr0'],
                              event_state.roots['ttbr1'], read_survey_page)
        event_state.code_live = run.iface.readmem(event_state.code_leaf['pa'], 4)
        event_state.kernel_segment = run.layout['images']['kernelcache'][
            'segments']['__TEXT_EXEC']
        event_state.source_offset = (event_state.kernel_segment['fileoff'] + event_state.linked_pc -
                         event_state.kernel_segment['va'])
        event_state.source_word = run.sources['kernelcache'][
            event_state.source_offset:event_state.source_offset + 4]
        event_state.expected_code = run.struct.pack('<I', event_state.expected_word)
        event_state.aggregate_steps = (event_state.state['aggregate_steps'] +
                           event_state.fast_status['steps'])
        event_state.checks.update(
            source_word=event_state.source_word == event_state.expected_code,
            live_word=(event_state.code_live == event_state.expected_code and
                       event_state.code_live == event_state.source_word),
            level_three=event_state.code_leaf['level'] == 3,
            access_flag=event_state.code_leaf['access_flag'],
            filter_terminal=(not event_state.fast_status['active'] and
                event_state.fast_status['status'] ==
                    run.FC_VEL2_STEP_FILTER_TERMINAL and
                event_state.fast_status['last_pc'] == event_state.expected_pc),
            filter_bounded=(0 < event_state.fast_status['steps'] <=
                run.FC_XNU_PHASE53_FAST_STEPS),
            filter_contract=(
                event_state.fast_status['first_pc'] == event_state.state['segment_start'] and
                event_state.fast_status['expected_first_pc'] ==
                    event_state.state['segment_start'] and
                event_state.fast_status['range0_hits'] +
                    event_state.fast_status['range1_hits'] ==
                    event_state.fast_status['steps'] and
                event_state.fast_status['range0_start'] == event_state.state['range0'][0] and
                event_state.fast_status['range0_end'] == event_state.state['range0'][1] and
                event_state.fast_status['range1_start'] ==
                    run.FC_SPTM_RUNTIME_TEXT[0] and
                event_state.fast_status['range1_end'] ==
                    run.FC_SPTM_RUNTIME_TEXT[1] and
                event_state.fast_status['terminal_pc'] == event_state.expected_pc and
                event_state.fast_status['max_steps'] ==
                    run.FC_XNU_PHASE53_FAST_STEPS),
            aggregate_budget=(event_state.aggregate_steps <=
                run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS))
        event_state.stage_record.update(
            source_hex=event_state.source_word.hex(), live_hex=event_state.code_live.hex(),
            pa=hex(event_state.code_leaf['pa']), filter_status=event_state.fast_status,
            aggregate_steps=event_state.aggregate_steps)
        event_state.next_stage = event_state.next_pc = None
        if event_state.stage_name == 'seek-entry':
            event_state.args = tuple(int(event_state.ctx.regs[index]) for index in range(4))
            event_state.pac_mask = (1 << 40) - 1
            event_state.caller_return = ((run.FC_XNU_RUNTIME_TEXT[0] & ~event_state.pac_mask) |
                             (int(event_state.ctx.regs[30]) & event_state.pac_mask))
            event_state.caller_callsite = event_state.caller_return - 4
            event_state.caller_linked = (
                run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED +
                event_state.caller_callsite -
                run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY)
            event_state.caller_leaf = run.translate(
                event_state.caller_callsite, event_state.roots['ttbr0'], event_state.roots['ttbr1'],
                read_survey_page)
            event_state.caller_live = run.iface.readmem(event_state.caller_leaf['pa'], 4)
            event_state.caller_offset = (event_state.kernel_segment['fileoff'] +
                             event_state.caller_linked - event_state.kernel_segment['va'])
            event_state.caller_source = run.sources['kernelcache'][
                event_state.caller_offset:event_state.caller_offset + 4]
            event_state.caller_word = (run.struct.unpack('<I', event_state.caller_source)[0]
                           if len(event_state.caller_source) == 4 else 0)
            event_state.immediate = event_state.caller_word & 0x3ffffff
            if event_state.immediate & (1 << 25):
                event_state.immediate -= 1 << 26
            event_state.caller_target = event_state.caller_callsite + (event_state.immediate << 2)
            if (event_state.args[0] == 0 or event_state.args[0] & (run.PAGE - 1) or
                    not run.base <= event_state.args[0] < run.base + run.guest_size):
                raise ValueError(
                    'Phase53 survey physical address is not an owned page')
            if event_state.args[1] > 0xff or event_state.args[2] > 0xff:
                raise ValueError(
                    'Phase53 survey frame type is not u8')
            event_state.fte_before = capture_fte_neighborhood(event_state.args[0])
            event_state.center = event_state.fte_before['records'][1]
            event_state.checks.update(
                pa_aligned=event_state.args[0] != 0 and
                    event_state.args[0] & (run.PAGE - 1) == 0,
                pa_owned=run.base <= event_state.args[0] < run.base + run.guest_size,
                type_from_u8=event_state.args[1] <= 0xff,
                type_to_u8=event_state.args[2] <= 0xff,
                caller_in_xnu=run.FC_XNU_RUNTIME_TEXT[0] <=
                    event_state.caller_callsite < run.FC_XNU_RUNTIME_TEXT[1],
                caller_source_bl=(event_state.caller_word & 0xfc000000) ==
                    0x94000000,
                caller_live=event_state.caller_live == event_state.caller_source,
                caller_targets_wrapper=event_state.caller_target ==
                    run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY,
                caller_level_three=event_state.caller_leaf['level'] == 3,
                caller_access_flag=event_state.caller_leaf['access_flag'],
                fte_pointer_level_three=
                    event_state.fte_before['pointer_level_three'],
                fte_pointer_access_flag=
                    event_state.fte_before['pointer_access_flag'],
                fte_records_complete=all(item['complete'] for item in
                    event_state.fte_before['records']),
                fte_records_level_three=all(
                    item['level_three'] for item in
                    event_state.fte_before['records']),
                fte_records_access_flag=all(
                    item['access_flag'] for item in
                    event_state.fte_before['records']),
                fte_center_unlocked=event_state.center['in_flight_ops'] == 0,
                fte_center_type=event_state.center['type'] == (event_state.args[1] & 0xff),
                rearm_budget=event_state.state['rearms'] <
                    run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS)
            event_state.current_call = dict(
                index=event_state.state['completed_calls'],
                args=[hex(value) for value in event_state.args],
                pa=hex(event_state.args[0]), type_from=hex(event_state.args[1] & 0xffffffff),
                type_to=hex(event_state.args[2] & 0xffffffff),
                flags=hex(event_state.args[3]), x30=hex(int(event_state.ctx.regs[30])),
                caller_return=hex(event_state.caller_return),
                caller_callsite=hex(event_state.caller_callsite),
                caller_linked=hex(event_state.caller_linked),
                caller_source_hex=event_state.caller_source.hex(),
                caller_live_hex=event_state.caller_live.hex(),
                frame_table_before=event_state.fte_before)
            event_state.state['current_call'] = event_state.current_call
            event_state.next_stage = 'seek-genter'
            event_state.next_pc = run.FC_XNU_PHASE53_GENTER
        elif event_state.stage_name == 'seek-genter':
            event_state.current_call = event_state.state['current_call']
            event_state.expected_args = tuple(int(value, 0) for value in
                                  event_state.current_call['args'])
            event_state.selector_leaf = run.translate(
                run.FC_XNU_PHASE53_GENTER_PREVIOUS, event_state.roots['ttbr0'],
                event_state.roots['ttbr1'], read_survey_page)
            event_state.selector_live = run.iface.readmem(event_state.selector_leaf['pa'], 4)
            event_state.selector_offset = (event_state.kernel_segment['fileoff'] +
                run.FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED -
                event_state.kernel_segment['va'])
            event_state.selector_source = run.sources['kernelcache'][
                event_state.selector_offset:event_state.selector_offset + 4]
            event_state.expected_selector = run.struct.pack(
                '<I', run.FC_XNU_PHASE53_GENTER_PREVIOUS_WORD)
            event_state.checks.update(
                selector_source=event_state.selector_source == event_state.expected_selector,
                selector_live=(event_state.selector_live == event_state.expected_selector and
                               event_state.selector_live == event_state.selector_source),
                selector_level_three=event_state.selector_leaf['level'] == 3,
                selector_access_flag=event_state.selector_leaf['access_flag'],
                genter_selector=int(event_state.ctx.regs[16]) == 1,
                args_unchanged=tuple(int(event_state.ctx.regs[index]) for index in
                    range(4)) == event_state.expected_args,
                filter_previous_pc=event_state.fast_status['previous_pc'] ==
                    run.FC_XNU_PHASE53_GENTER_PREVIOUS,
                rearm_budget=event_state.state['rearms'] <
                    run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS)
            event_state.current_call['genter'] = dict(
                selector_source_hex=event_state.selector_source.hex(),
                selector_live_hex=event_state.selector_live.hex())
            event_state.next_stage = 'seek-genter-return'
            event_state.next_pc = run.FC_XNU_PHASE53_GENTER_RETURN
        elif event_state.stage_name == 'seek-wrapper-retab':
            event_state.current_call = event_state.state['current_call']
            event_state.args = tuple(int(value, 0) for value in
                         event_state.current_call['args'])
            event_state.fte_after = capture_fte_neighborhood(event_state.args[0])
            event_state.center = event_state.fte_after['records'][1]
            event_state.before = event_state.current_call['frame_table_before']
            event_state.checks.update(
                filter_previous_pc=event_state.fast_status['previous_pc'] ==
                    run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_PREVIOUS,
                restored_caller=(int(event_state.ctx.regs[30]) &
                    ((1 << 40) - 1)) ==
                    (int(event_state.current_call['x30'], 0) &
                     ((1 << 40) - 1)),
                fte_base_stable=event_state.fte_after['fte_base'] ==
                    event_state.before['fte_base'],
                fte_center_stable=event_state.fte_after['center_va'] ==
                    event_state.before['center_va'],
                fte_pointer_level_three=
                    event_state.fte_after['pointer_level_three'],
                fte_pointer_access_flag=
                    event_state.fte_after['pointer_access_flag'],
                fte_records_complete=all(item['complete'] for item in
                    event_state.fte_after['records']),
                fte_records_level_three=all(
                    item['level_three'] for item in
                    event_state.fte_after['records']),
                fte_records_access_flag=all(
                    item['access_flag'] for item in
                    event_state.fte_after['records']),
                fte_center_unlocked=event_state.center['in_flight_ops'] == 0,
                fte_center_type=event_state.center['type'] == (event_state.args[2] & 0xff))
            event_state.current_call['frame_table_after'] = event_state.fte_after
        event_state.stage_record['checks'] = event_state.checks
        event_state.stage_record['complete'] = all(event_state.checks.values())
        if event_state.stage_name == 'seek-entry':
            event_state.state['calls'].append(event_state.state['current_call'])
        event_state.state['current_call'][event_state.stage_name] = event_state.stage_record
        run.report['xnu_phase53_retype_survey']['calls'] = list(
            event_state.state['calls'])
        if event_state.stage_record['complete'] and event_state.next_stage is not None:
            event_state.enabled_status = run.txm_sstep_fast_path.enable(
                run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, event_state.next_pc,
                run.FC_XNU_PHASE53_FAST_STEPS, event_state.ctx.elr)
            event_state.state.update(
                stage=event_state.next_stage, range0=run.FC_XNU_RUNTIME_TEXT,
                segment_start=event_state.ctx.elr, terminal_pc=event_state.next_pc,
                aggregate_steps=event_state.aggregate_steps,
                rearms=event_state.state['rearms'] + 1)
            event_state.stage_record['next_enable_status'] = event_state.enabled_status
            run.report['xnu_phase53_retype_survey'].update(
                current_stage=event_state.next_stage, terminal_pc=hex(event_state.next_pc),
                aggregate_steps=event_state.aggregate_steps,
                rearms=event_state.state['rearms'])
            event_state.event.update(kind='phase53-survey-' + event_state.stage_name,
                         pc=event_state.ctx.elr, checks=event_state.checks)
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.stage_record['complete']:
            event_state.state['aggregate_steps'] = event_state.aggregate_steps
            event_state.state['completed_calls'] += 1
            event_state.target_type = int(event_state.state['current_call']['type_to'], 0)
            event_state.target_found = event_state.target_type in \
                run.FC_XNU_PHASE53_RETYPE_SURVEY_TARGET_TYPES
            event_state.primary_target = (
                int(event_state.state['current_call']['type_from'], 0) == 0xb and
                event_state.target_type == 0x14)
            event_state.state['current_call'].update(
                complete=True, target_found=event_state.target_found,
                primary_target=event_state.primary_target)
            run.report['xnu_phase53_retype_survey'].update(
                completed_calls=event_state.state['completed_calls'],
                aggregate_steps=event_state.aggregate_steps,
                target_found=event_state.target_found,
                primary_target_found=event_state.primary_target,
                calls=list(event_state.state['calls']))
            event_state.state['active'] = False
            if event_state.target_found:
                run.report['xnu_phase53_retype_survey']['complete'] = True
                run.report['stop_reason'] = (
                    'phase53-retype-survey-target-reached')
            elif event_state.state['completed_calls'] >= event_state.state['limit']:
                run.report['xnu_phase53_retype_survey'][
                    'limit_reached'] = True
                run.report['stop_reason'] = (
                    'phase53-retype-survey-call-limit-reached')
            elif event_state.state['rearms'] >= \
                    run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS:
                run.report['stop_reason'] = (
                    'phase53-retype-survey-rearm-limit-reached')
            else:
                event_state.enabled_status = run.txm_sstep_fast_path.enable(
                    run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT,
                    run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY,
                    run.FC_XNU_PHASE53_FAST_STEPS, event_state.ctx.elr)
                event_state.state.update(
                    active=True, stage='seek-entry',
                    range0=run.FC_XNU_RUNTIME_TEXT,
                    segment_start=event_state.ctx.elr,
                    terminal_pc=
                        run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY,
                    rearms=event_state.state['rearms'] + 1)
                event_state.stage_record['next_enable_status'] = event_state.enabled_status
                run.report['xnu_phase53_retype_survey'].update(
                    current_stage='seek-entry',
                    terminal_pc=hex(
                        run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY),
                    rearms=event_state.state['rearms'])
                event_state.event.update(
                    kind='phase53-survey-next-call', pc=event_state.ctx.elr,
                    checks=event_state.checks)
                event_state.ctx.spsr.SS = 1
                run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                run.report.pop('stop_reason', None)
                event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.state['active'] = False
            run.report['xnu_phase53_retype_survey'][
                'rejection'] = event_state.stage_record
            run.report['stop_reason'] = (
                'phase53-retype-survey-' + event_state.stage_name +
                '-gate-rejected')
    except Exception as survey_gate_error:
        event_state.checks['gate_readback'] = False
        event_state.stage_record.update(checks=event_state.checks, complete=False,
                            error=str(survey_gate_error))
        event_state.state['active'] = False
        run.report['xnu_phase53_retype_survey'][
            'rejection'] = event_state.stage_record
        run.report['stop_reason'] = (
            'phase53-retype-survey-' + event_state.stage_name +
            '-gate-rejected')
