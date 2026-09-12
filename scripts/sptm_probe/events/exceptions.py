# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Exceptions event handlers extracted from the original probe callback."""
from . import handoff

def handle_exception(run, event_state):
    event_state.ctx = run.iface.readstruct(event_state.info, run.ExcInfo)
    event_state.esr = int(event_state.ctx.esr)
    event_state.event.update(pc=event_state.ctx.elr, esr=event_state.esr, far=event_state.ctx.far, spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs), sp=list(event_state.ctx.sp))
    if not run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.esr == 1509982206 and event_state.ctx.elr == run.entry + 4 or (event_state.esr >> 26 == 50 and event_state.ctx.elr == run.entry)):
        run.entered = True
        run.iface.writemem(run.entry, run.original)
        run.p.dc_cvau(run.entry, 4)
        run.p.ic_ivau(run.entry, 4)
        event_state.ctx.elr = run.entry
        event_state.ctx.spsr.D = event_state.ctx.spsr.A = event_state.ctx.spsr.I = event_state.ctx.spsr.F = 1
        event_state.ctx.spsr.SS = 1
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.event['kind'] = 'entry-guard'
        event_state.ret = run.EXC_RET.HANDLED
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.esr >> 26 == 50):
        event_state.event['kind'] = 'instruction-step'
        event_state.off = event_state.ctx.elr - run.base
        event_state.effect = run.recognize_zero_loop(bytes(run.blob[event_state.off:event_state.off + 12]), event_state.ctx.regs, event_state.ctx.elr, run.base, run.guest_size) if run.a.emulate_zero_loops and 0 <= event_state.off <= len(run.blob) - 12 else None
        if event_state.effect is not None:
            if run.iface.readmem(event_state.ctx.elr, 12) == bytes(run.blob[event_state.off:event_state.off + 12]):
                run.p.memset64(event_state.effect['address'], 0, event_state.effect['bytes'])
                run.p.dc_cvau(event_state.effect['address'], event_state.effect['bytes'])
                event_state.ctx.regs[1], event_state.ctx.regs[2] = (event_state.effect['x1'], event_state.effect['x2'])
                event_state.ctx.elr = event_state.effect['pc']
                event_state.ctx.spsr.N, event_state.ctx.spsr.Z, event_state.ctx.spsr.C, event_state.ctx.spsr.V = (0, 1, 1, 0)
                event_state.event.update(kind='emulated-zero-loop', effects=event_state.effect)
        event_state.gc_done = False
        if run.multi_call_selectors is not None:
            if event_state.ctx.elr == run.FC_IDLE_PC and (not run.gc_state['in_call']) and (run.gc_state['index'] < len(run.multi_call_selectors)):
                event_state.sel = run.multi_call_selectors[run.gc_state['index']]
                event_state.ctx.regs[16] = event_state.sel
                run.gc_state['in_call'] = True
                run.gc_state['started'] = run.trace_count(run.report)
                event_state.event.update(kind='guarded-call-genter', call_index=run.gc_state['index'], selector=hex(event_state.sel))
            elif event_state.ctx.elr == run.FC_IDLE_PC + 4 and run.gc_state['in_call']:
                run.report.setdefault('guarded_calls', []).append(dict(index=run.gc_state['index'], selector=hex(run.multi_call_selectors[run.gc_state['index']]), result=event_state.ctx.regs[0], steps=run.trace_count(run.report) - run.gc_state['started']))
                event_state.event.update(kind='guarded-call-return', call_index=run.gc_state['index'], result=event_state.ctx.regs[0])
                run.gc_state['in_call'] = False
                run.gc_state['index'] += 1
                if run.gc_state['index'] >= len(run.multi_call_selectors):
                    run.report['stop_reason'] = 'guarded-calls-complete'
                    event_state.gc_done = True
            elif event_state.ctx.elr == run.FC_PANIC and run.gc_state['in_call']:
                run.report.setdefault('guarded_calls', []).append(dict(index=run.gc_state['index'], selector=hex(run.multi_call_selectors[run.gc_state['index']]), result=None, panicked=True, steps=run.trace_count(run.report) - run.gc_state['started']))
                event_state.event.update(kind='guarded-call-panic', call_index=run.gc_state['index'])
                run.report['stop_reason'] = 'guarded-call-panic'
                event_state.gc_done = True
        if event_state.gc_done:
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        elif run.trace_count(run.report) < run.a.steps:
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            run.report['stop_reason'] = 'instruction-budget'
    elif run.entered and run.a.free_run and run.a.real_guarded and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.esr >> 26 == 22) and (event_state.esr & 65535 == 18432):
        run.report['eret_trap'] = dict(pc=hex(event_state.ctx.elr), spsr=hex(int(event_state.ctx.spsr)), x3=hex(event_state.ctx.regs[3]), phase='before-bank-read')
        run.save()
        event_state.elr_gl1 = event_state.spsr_gl1 = 0
        try:
            event_state.rg = run.sysreg_fwd['ELR_GL1']
            event_state.rs = run.sysreg_fwd['SPSR_GL1']
            if event_state.rg in run.HV.MSR_REDIRECTS:
                event_state.elr_gl1 = int(run.u.mrs(run.HV.MSR_REDIRECTS[event_state.rg]))
            if event_state.rs in run.HV.MSR_REDIRECTS:
                event_state.spsr_gl1 = int(run.u.mrs(run.HV.MSR_REDIRECTS[event_state.rs]))
        except Exception as bank_error:
            event_state.event['eret_bank_error'] = str(bank_error)
            event_state.elr_gl1 = event_state.spsr_gl1 = 0
        event_state.event.update(kind='eret-guarded', target=hex(event_state.elr_gl1), target_spsr=hex(event_state.spsr_gl1))
        run.report['eret_trap'].update(phase='banks-read', target=hex(event_state.elr_gl1), target_spsr=hex(event_state.spsr_gl1))
        run.report['stop_reason'] = 'eret-unclassified-target'
        if event_state.elr_gl1:
            event_state.roots = dict(ttbr0=run.u.mrs(run.TTBR0_EL12), ttbr1=run.u.mrs(run.TTBR1_EL12))
            event_state.classification = dict(status='classified', decision='rejected', trap_pc=hex(event_state.ctx.elr), target_pc=hex(event_state.elr_gl1), target_spsr=hex(event_state.spsr_gl1), translation_roots={name: hex(value) for name, value in event_state.roots.items()})
            try:
                event_state.handoff = run.classify_entry(event_state.elr_gl1, run.layout, run.base, run.guest_size, event_state.roots, run.iface.readmem, run.sources)
                event_state.classification.update(event_state.handoff)
                event_state.classification_ok = True
            except Exception as classification_error:
                event_state.classification.update(status='error', error=str(classification_error))
                run.report.setdefault('eret_classifications', []).append(event_state.classification)
                run.report['stop_reason'] = 'eret-classification-error'
                event_state.classification_ok = False
                event_state.handoff = dict(image=None, segment=None, entry_matches=False, bytes_match=False, linked_pc=None, bytes_hex='', target_pc=hex(event_state.elr_gl1), instructions_executed=False)
            if event_state.classification_ok:
                run.report.setdefault('eret_classifications', []).append(event_state.classification)
            event_state.eret_record = dict(event_state.handoff, spsr=hex(event_state.spsr_gl1), via='ERET_HVC guarded banks')
            event_state.completion_fast_status = None
            event_state.completion_guarded_esr = None
            event_state.completion_guarded_aspsr = None
            if event_state.classification_ok and run.txm_validator_trace_state.get('active') and (run.txm_validator_trace_state.get('phase') == 'completion') and run.txm_validator_trace_state.get('fast_path_armed') and getattr(run.a, 'xnu_txm_sstep_fast_path', False):
                try:
                    event_state.completion_fast_status = run.txm_sstep_fast_path.status()
                    event_state.completion_guarded_esr = int(run.u.mrs(run.HV.MSR_REDIRECTS[run.ESR_GL1]))
                    event_state.completion_guarded_aspsr = int(run.u.mrs(run.HV.MSR_REDIRECTS[run.ASPSR_GL1]))
                    event_state.classification.update(completion_fast_status=event_state.completion_fast_status, guarded_esr=hex(event_state.completion_guarded_esr), guarded_aspsr=hex(event_state.completion_guarded_aspsr))
                except Exception as completion_gate_error:
                    event_state.classification['completion_gate_error'] = str(completion_gate_error)
            event_state.completion_eret = event_state.classification_ok and event_state.completion_fast_status is not None and (event_state.ctx.elr == run.FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET) and (event_state.elr_gl1 == run.FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC + 4) and (event_state.spsr_gl1 == 2147488704) and (event_state.completion_guarded_esr == run.FC_XNU_TXM_HANDLER_CMD1_GUARDED_ESR) and (event_state.completion_guarded_aspsr == run.FC_XNU_TXM_HANDLER_CMD1_GUARDED_ASPSR) and (event_state.handoff['image'] == 'txm') and (event_state.handoff['segment'] == '__TEXT_EXEC') and (event_state.handoff['linked_pc'] == hex(run.FC_XNU_TXM_HANDLER_CMD1_RETURN_LINKED)) and event_state.handoff['bytes_match'] and bytes.fromhex(event_state.handoff['bytes_hex']).startswith(run.FC_XNU_TXM_HANDLER_CMD1_RETURN_BYTES) and event_state.completion_fast_status['active'] and (event_state.completion_fast_status['status'] == run.FC_VEL2_STEP_FILTER_RUNNING) and (0 < event_state.completion_fast_status['steps'] <= run.FC_TXM_COMPLETION_FAST_STEPS) and (event_state.completion_fast_status['first_pc'] == run.FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR) and (event_state.completion_fast_status['last_pc'] == event_state.ctx.elr - 8) and (event_state.completion_fast_status['range0_hits'] == 0) and (event_state.completion_fast_status['range1_hits'] == event_state.completion_fast_status['steps']) and (event_state.completion_fast_status['terminal_pc'] == run.FC_XNU_TXM_HANDLER_CMD1_RETAB) and (event_state.completion_fast_status['expected_first_pc'] == run.FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR)
            event_state.entry_launch = event_state.classification_ok and event_state.handoff['entry_matches'] and event_state.handoff['bytes_match'] and (event_state.spsr_gl1 == 5056) and (event_state.handoff['image'] in ('txm', 'kernelcache'))
            event_state.txm_return = event_state.classification_ok and run.a.native_handoff and (event_state.handoff['image'] == 'txm') and (event_state.entry_launch or (event_state.handoff['segment'] in ('__TEXT_EXEC', '__TEXT_BOOT_EXEC') and run.report.get('handoff', {}).get('image') == 'txm' and (event_state.ctx.elr == 18446741874804412124) and (event_state.handoff['linked_pc'] in run.TXM_WORLD_RETURN_LINKED) and (len(run.report.get('txm_world_returns', [])) < 128) and (sum((previous['linked_pc'] == event_state.handoff['linked_pc'] for previous in run.report.get('txm_world_returns', []))) < 64) and event_state.handoff['bytes_match'] and event_state.handoff['bytes_hex'].startswith('ff0f5fd6') and (0 <= event_state.spsr_gl1 < 1 << 32) and (event_state.spsr_gl1 & ~4026531840 == 5056)))
            event_state.phase53_eret_candidate = bool(run.phase53_allocation_trace_state.get('active') or run.phase53_descriptor_bind_state.get('active') or run.phase53_retype_survey_state.get('active'))
            event_state.phase53_eret = False
            if event_state.phase53_eret_candidate:
                event_state.phase53_filter_state = run.phase53_descriptor_bind_state if run.phase53_descriptor_bind_state.get('active') else run.phase53_retype_survey_state if run.phase53_retype_survey_state.get('active') else run.phase53_allocation_trace_state
                event_state.phase53_report_key = run.phase53_descriptor_bind_state.get('report_key', 'xnu_phase53_descriptor_bind') if run.phase53_descriptor_bind_state.get('active') else 'xnu_phase53_retype_survey' if run.phase53_retype_survey_state.get('active') else 'xnu_phase53_allocation_trace'
                event_state.transition = dict(trap_pc=hex(event_state.ctx.elr), target_pc=hex(event_state.elr_gl1), target_spsr=hex(event_state.spsr_gl1), target_image=event_state.handoff.get('image'), target_segment=event_state.handoff.get('segment'))
                event_state.target_range = {'txm': run.FC_TXM_RUNTIME_TEXT, 'kernelcache': run.FC_XNU_RUNTIME_TEXT}.get(event_state.handoff.get('image')) if event_state.classification_ok else None
                event_state.source_offset = event_state.ctx.elr - 4 - run.FC_IMAGE_BASE
                event_state.source_eret = run.sources.get('sptm', b'')[event_state.source_offset:event_state.source_offset + 4] if 0 <= event_state.source_offset <= len(run.sources.get('sptm', b'')) - 4 else b''
                event_state.transition_checks = {'classified': event_state.classification_ok, 'trap_in_sptm_text': run.FC_SPTM_RUNTIME_TEXT[0] <= event_state.ctx.elr < run.FC_SPTM_RUNTIME_TEXT[1], 'source_eret': event_state.source_eret == run.struct.pack('<I', run.FC_XNU_TXM_CONTEXT_ERET_WORD), 'target_world': event_state.target_range is not None, 'target_segment': event_state.handoff.get('segment') in ('__TEXT_EXEC', '__TEXT_BOOT_EXEC'), 'target_source_match': event_state.handoff.get('bytes_match') is True, 'target_pc_in_range': event_state.target_range is not None and event_state.target_range[0] <= event_state.elr_gl1 < event_state.target_range[1], 'target_mode': event_state.spsr_gl1 & 15 in (0, 4, 5)}
                try:
                    event_state.prior_status = run.txm_sstep_fast_path.status()
                    event_state.current_range = event_state.phase53_filter_state['range0']
                    event_state.segment_start = event_state.phase53_filter_state['segment_start']
                    event_state.survey_aggregate = event_state.phase53_filter_state.get('aggregate_steps', 0) + event_state.prior_status['steps']
                    event_state.phase53_max_steps = event_state.phase53_filter_state.get('max_steps', run.FC_XNU_PHASE53_FAST_STEPS)
                    event_state.transition_checks.update(filter_running=event_state.prior_status['active'] and event_state.prior_status['status'] == run.FC_VEL2_STEP_FILTER_RUNNING, filter_bounded=0 < event_state.prior_status['steps'] <= event_state.phase53_max_steps, filter_last_pc=event_state.prior_status['last_pc'] == event_state.ctx.elr - 4, filter_segment=event_state.prior_status['first_pc'] == event_state.segment_start and event_state.prior_status['expected_first_pc'] == event_state.segment_start and (event_state.prior_status['range0_hits'] + event_state.prior_status['range1_hits'] == event_state.prior_status['steps']), filter_contract=event_state.prior_status['range0_start'] == event_state.current_range[0] and event_state.prior_status['range0_end'] == event_state.current_range[1] and (event_state.prior_status['range1_start'] == run.FC_SPTM_RUNTIME_TEXT[0]) and (event_state.prior_status['range1_end'] == run.FC_SPTM_RUNTIME_TEXT[1]) and (event_state.prior_status['terminal_pc'] == event_state.phase53_filter_state['terminal_pc']) and (event_state.prior_status['max_steps'] == event_state.phase53_max_steps))
                    if run.phase53_retype_survey_state.get('active') or run.phase53_descriptor_bind_state.get('active'):
                        event_state.aggregate_limit = event_state.phase53_filter_state.get('aggregate_limit', run.FC_XNU_PHASE53_DESCRIPTOR_BIND_TOTAL_STEPS if run.phase53_descriptor_bind_state.get('active') else run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS)
                        event_state.rearm_limit = event_state.phase53_filter_state.get('rearm_limit', run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS if run.phase53_descriptor_bind_state.get('active') else run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS)
                        event_state.transition_checks.update(aggregate_budget=event_state.survey_aggregate <= event_state.aggregate_limit, rearm_budget=event_state.phase53_filter_state['rearms'] < event_state.rearm_limit)
                    if all(event_state.transition_checks.values()):
                        event_state.enabled_status = run.txm_sstep_fast_path.enable(event_state.target_range, run.FC_SPTM_RUNTIME_TEXT, event_state.phase53_filter_state['terminal_pc'], event_state.phase53_max_steps, event_state.elr_gl1)
                        event_state.phase53_filter_state['range0'] = event_state.target_range
                        event_state.phase53_filter_state['segment_start'] = event_state.elr_gl1
                        if run.phase53_retype_survey_state.get('active') or run.phase53_descriptor_bind_state.get('active'):
                            event_state.phase53_filter_state['aggregate_steps'] = event_state.survey_aggregate
                            event_state.phase53_filter_state['rearms'] += 1
                        event_state.transition.update(source_hex=event_state.source_eret.hex(), prior_status=event_state.prior_status, enable_status=event_state.enabled_status, checks=event_state.transition_checks, complete=True)
                        event_state.phase53_filter_state['world_transitions'].append(event_state.transition)
                        run.report[event_state.phase53_report_key]['world_transitions'] = list(event_state.phase53_filter_state['world_transitions'])
                        if run.phase53_retype_survey_state.get('active') or run.phase53_descriptor_bind_state.get('active'):
                            run.report[event_state.phase53_report_key].update(aggregate_steps=event_state.survey_aggregate, rearms=event_state.phase53_filter_state['rearms'])
                        event_state.phase53_eret = True
                    else:
                        event_state.transition.update(source_hex=event_state.source_eret.hex(), prior_status=event_state.prior_status, checks=event_state.transition_checks, complete=False)
                except Exception as transition_error:
                    event_state.transition_checks['filter_readback'] = False
                    event_state.transition.update(source_hex=event_state.source_eret.hex(), checks=event_state.transition_checks, error=str(transition_error), complete=False)
                if not event_state.phase53_eret:
                    event_state.phase53_filter_state['active'] = False
                    run.report[event_state.phase53_report_key]['world_transition_rejection'] = event_state.transition
                    run.report['stop_reason'] = 'phase53-world-transition-gate-rejected'
            event_state.txm_context_step = False
            if event_state.classification_ok and (run.a.xnu_txm_context_entry_one_step or run.a.xnu_txm_context_entry_register_prefix or run.a.xnu_txm_context_stack_claim_one_step or run.a.xnu_txm_context_stack_metadata_init or run.a.xnu_txm_context_x18_branch_one_step or run.a.xnu_txm_context_outbound_branch_one_step or (run.a.xnu_txm_handler_boundary is not None)) and (event_state.ctx.elr == run.FC_XNU_TXM_CONTEXT_ERET_PC) and (not event_state.entry_launch) and (not event_state.txm_return) and (not event_state.phase53_eret_candidate):

                def owned_page(pa):
                    if pa & run.PAGE - 1 or not run.base <= pa < pa + run.PAGE <= run.base + run.guest_size:
                        raise ValueError('TXM context-entry table outside owned guest RAM')
                    page = run.iface.readmem(pa, run.PAGE)
                    if len(page) != run.PAGE:
                        raise ValueError('Truncated TXM context-entry table')
                    return page
                event_state.handler_boundary = run.a.xnu_txm_handler_boundary
                event_state.outbound = run.a.xnu_txm_context_outbound_branch_one_step or event_state.handler_boundary is not None
                event_state.gate_error = None
                try:
                    event_state.target_mapping = run.translate(event_state.elr_gl1, event_state.roots['ttbr0'], event_state.roots['ttbr1'], owned_page)
                    event_state.stack_mapping = run.translate(int(event_state.ctx.regs[0]), event_state.roots['ttbr0'], event_state.roots['ttbr1'], owned_page)
                    event_state.outbound_mapping = run.translate(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET, event_state.roots['ttbr0'], event_state.roots['ttbr1'], owned_page) if event_state.outbound else None
                    event_state.helper_mapping = run.translate(run.FC_XNU_TXM_HANDLER_HELPER, event_state.roots['ttbr0'], event_state.roots['ttbr1'], owned_page) if event_state.handler_boundary in ('local-setup', 'validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace') else None
                    event_state.handler_global_mapping = run.translate(run.FC_XNU_TXM_HANDLER_GLOBAL, event_state.roots['ttbr0'], event_state.roots['ttbr1'], owned_page) if event_state.handler_boundary in ('validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace') else None
                    event_state.response_pointer_mapping = run.translate(run.FC_XNU_TXM_HANDLER_RESPONSE_POINTER, event_state.roots['ttbr0'], event_state.roots['ttbr1'], owned_page) if event_state.handler_boundary in ('response-trace', 'cmd1-completion-trace') else None
                    event_state.pperm = int(run.u.mrs(run.HV.MSR_REDIRECTS[run.SPRR_PPERM_EL1]))
                    event_state.uperm = int(run.u.mrs(run.HV.MSR_REDIRECTS[run.SPRR_UPERM_EL0]))
                    event_state.mair = int(run.u.mrs(run.MAIR_EL12))
                    event_state.target_permissions = run.leaf_permissions(event_state.target_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded')
                    event_state.stack_permissions = run.leaf_permissions(event_state.stack_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded')
                    event_state.outbound_permissions = run.leaf_permissions(event_state.outbound_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded') if event_state.outbound_mapping is not None else None
                    event_state.helper_permissions = run.leaf_permissions(event_state.helper_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded') if event_state.helper_mapping is not None else None
                    event_state.handler_global_permissions = run.leaf_permissions(event_state.handler_global_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded') if event_state.handler_global_mapping is not None else None
                    event_state.response_pointer_permissions = run.leaf_permissions(event_state.response_pointer_mapping['descriptor'], event_state.pperm, event_state.uperm, 'guarded') if event_state.response_pointer_mapping is not None else None
                except Exception as error:
                    event_state.target_mapping = event_state.stack_mapping = None
                    event_state.target_permissions = event_state.stack_permissions = None
                    event_state.outbound_mapping = event_state.outbound_permissions = None
                    event_state.helper_mapping = event_state.helper_permissions = None
                    event_state.handler_global_mapping = event_state.handler_global_permissions = None
                    event_state.response_pointer_mapping = event_state.response_pointer_permissions = None
                    event_state.pperm = event_state.uperm = event_state.mair = None
                    event_state.gate_error = str(error)
                event_state.prefix = run.a.xnu_txm_context_entry_register_prefix or run.a.xnu_txm_context_stack_claim_one_step or run.a.xnu_txm_context_stack_metadata_init or run.a.xnu_txm_context_x18_branch_one_step or run.a.xnu_txm_context_outbound_branch_one_step or (event_state.handler_boundary is not None)
                event_state.claim = run.a.xnu_txm_context_stack_claim_one_step or run.a.xnu_txm_context_stack_metadata_init or run.a.xnu_txm_context_x18_branch_one_step or run.a.xnu_txm_context_outbound_branch_one_step or (event_state.handler_boundary is not None)
                event_state.metadata = run.a.xnu_txm_context_stack_metadata_init or run.a.xnu_txm_context_x18_branch_one_step or run.a.xnu_txm_context_outbound_branch_one_step or (event_state.handler_boundary is not None)
                event_state.x18_branch = run.a.xnu_txm_context_x18_branch_one_step or run.a.xnu_txm_context_outbound_branch_one_step or event_state.handler_boundary is not None
                event_state.target_bytes = bytes.fromhex(event_state.handoff.get('bytes_hex', ''))
                event_state.sptm_segment = run.layout.get('images', {}).get('sptm', {}).get('segments', {}).get('__TEXT_EXEC', {})
                event_state.sptm_source_offset = run.FC_XNU_TXM_CONTEXT_ERET_PC - 4 - run.FC_IMAGE_BASE
                event_state.sptm_source_in_segment = event_state.sptm_segment.get('fileoff', 0) <= event_state.sptm_source_offset and event_state.sptm_source_offset + 4 <= event_state.sptm_segment.get('fileoff', 0) + event_state.sptm_segment.get('filesize', 0)
                event_state.source_eret = run.sources.get('sptm', b'')[event_state.sptm_source_offset:event_state.sptm_source_offset + 4] if event_state.sptm_source_in_segment else b''
                event_state.txm_segment = run.layout.get('images', {}).get('txm', {}).get('segments', {}).get('__TEXT_EXEC', {})
                event_state.outbound_source_offset = event_state.txm_segment.get('fileoff', 0) + run.FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED - event_state.txm_segment.get('va', 0)
                event_state.outbound_source_in_segment = event_state.txm_segment.get('va', 0) <= run.FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED and run.FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED + len(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES) <= event_state.txm_segment.get('va', 0) + event_state.txm_segment.get('filesize', 0)
                event_state.handler_source_size = {'local-setup': run.FC_XNU_TXM_HANDLER_LOCAL_SETUP_SIZE, 'validator-entry': run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE, 'validator-trace': run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE, 'response-trace': run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE, 'cmd1-completion-trace': run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE}.get(event_state.handler_boundary, len(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES))
                event_state.outbound_source = run.sources.get('txm', b'')[event_state.outbound_source_offset:event_state.outbound_source_offset + event_state.handler_source_size]
                event_state.helper_source_offset = event_state.txm_segment.get('fileoff', 0) + run.FC_XNU_TXM_HANDLER_HELPER_LINKED - event_state.txm_segment.get('va', 0)
                event_state.helper_source = run.sources.get('txm', b'')[event_state.helper_source_offset:event_state.helper_source_offset + len(run.FC_XNU_TXM_HANDLER_HELPER_BYTES)]
                event_state.txm_prefix_source_offset = event_state.txm_segment.get('fileoff', 0) + int(run.FC_XNU_TXM_CONTEXT_LINKED, 16) + 4 - event_state.txm_segment.get('va', 0)
                event_state.prefix_source = run.sources.get('txm', b'')[event_state.txm_prefix_source_offset:event_state.txm_prefix_source_offset + len(run.FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES)]
                event_state.claim_source_offset = event_state.txm_prefix_source_offset + len(run.FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES)
                event_state.claim_source = run.sources.get('txm', b'')[event_state.claim_source_offset:event_state.claim_source_offset + 4]
                event_state.post_claim_source_offset = event_state.claim_source_offset + 4
                event_state.post_claim_source = run.sources.get('txm', b'')[event_state.post_claim_source_offset:event_state.post_claim_source_offset + len(run.FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES)]
                event_state.x18_window_source_offset = event_state.post_claim_source_offset + len(run.FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES) - 4
                event_state.x18_window_source = run.sources.get('txm', b'')[event_state.x18_window_source_offset:event_state.x18_window_source_offset + len(run.FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES)]
                event_state.stack_owned_leaf = event_state.stack_mapping is not None and event_state.stack_mapping['level'] == 3 and event_state.stack_mapping['access_flag'] and (not event_state.stack_mapping['read_only']) and event_state.stack_mapping['user_access'] and (event_state.stack_mapping['pa'] & run.PAGE - 1 == 0) and (run.base <= event_state.stack_mapping['pa']) and (event_state.stack_mapping['pa'] + run.PAGE <= run.base + run.guest_size)
                event_state.outbound_owned_leaf = event_state.outbound_mapping is not None and event_state.outbound_mapping['level'] == 3 and event_state.outbound_mapping['access_flag'] and event_state.outbound_mapping['read_only'] and (not event_state.outbound_mapping['pxn']) and (run.base <= event_state.outbound_mapping['pa']) and (event_state.outbound_mapping['pa'] + event_state.handler_source_size <= run.base + run.guest_size) and ((event_state.outbound_mapping['pa'] & run.PAGE - 1) + event_state.handler_source_size <= run.PAGE)
                event_state.outbound_live_bytes = run.iface.readmem(event_state.outbound_mapping['pa'], event_state.handler_source_size) if event_state.outbound and event_state.outbound_owned_leaf else None
                event_state.helper_owned_leaf = event_state.helper_mapping is not None and event_state.helper_mapping['level'] == 3 and event_state.helper_mapping['access_flag'] and event_state.helper_mapping['read_only'] and (not event_state.helper_mapping['pxn']) and (run.base <= event_state.helper_mapping['pa']) and (event_state.helper_mapping['pa'] + len(run.FC_XNU_TXM_HANDLER_HELPER_BYTES) <= run.base + run.guest_size) and ((event_state.helper_mapping['pa'] & run.PAGE - 1) + len(run.FC_XNU_TXM_HANDLER_HELPER_BYTES) <= run.PAGE)
                event_state.helper_live_bytes = run.iface.readmem(event_state.helper_mapping['pa'], len(run.FC_XNU_TXM_HANDLER_HELPER_BYTES)) if event_state.helper_owned_leaf else None
                event_state.handler_global_owned_leaf = event_state.handler_global_mapping is not None and event_state.handler_global_mapping['level'] == 3 and event_state.handler_global_mapping['access_flag'] and (run.base <= event_state.handler_global_mapping['pa'] < run.base + run.guest_size)
                event_state.handler_global_before = run.iface.readmem(event_state.handler_global_mapping['pa'], 1) if event_state.handler_global_owned_leaf else None
                event_state.response_pointer_owned_leaf = event_state.response_pointer_mapping is not None and event_state.response_pointer_mapping['level'] == 3 and event_state.response_pointer_mapping['access_flag'] and (run.base <= event_state.response_pointer_mapping['pa'] <= run.base + run.guest_size - 8)
                event_state.response_pointer_before = run.iface.readmem(event_state.response_pointer_mapping['pa'], 8) if event_state.response_pointer_owned_leaf else None
                event_state.first_touch_pa = event_state.stack_mapping['pa'] + run.PAGE - 1024 + 88 if event_state.stack_owned_leaf else None
                event_state.metadata_frame_pa = event_state.stack_mapping['pa'] + run.PAGE - 1024 if event_state.stack_owned_leaf else None
                event_state.claim_before = run.iface.readmem(event_state.first_touch_pa, 1) if event_state.claim and event_state.first_touch_pa is not None else None
                event_state.metadata_page_before = run.iface.readmem(event_state.stack_mapping['pa'], run.PAGE) if event_state.metadata and event_state.stack_owned_leaf else None
                event_state.metadata_offsets = dict(state=0, zero_word=4, claim=88, zero_byte=121)
                event_state.metadata_before = {name: event_state.metadata_page_before[run.PAGE - 1024 + offset:run.PAGE - 1024 + offset + (4 if name == 'zero_word' else 1)] for name, offset in event_state.metadata_offsets.items()} if event_state.metadata_page_before is not None else {}
                event_state.checks = {'verified_xnu_handoff': run.handoff_state.get('native') and run.report.get('handoff', {}).get('image') == 'kernelcache' and (run.report.get('handoff', {}).get('instructions_executed') is True), 'trap_pc': event_state.ctx.elr == run.FC_XNU_TXM_CONTEXT_ERET_PC, 'source_eret': event_state.source_eret == run.struct.pack('<I', run.FC_XNU_TXM_CONTEXT_ERET_WORD), 'caller_pstate': int(event_state.ctx.spsr) & ~4026531840 == 5061, 'caller_x3': int(event_state.ctx.regs[3]) == 0, 'caller_selector_x16': int(event_state.ctx.regs[16]) == run.FC_XNU_TXM_CONTEXT_SELECTOR, 'caller_x18': int(event_state.ctx.regs[18]) == run.FC_XNU_TXM_CONTEXT_X18, 'target_pc': event_state.elr_gl1 == run.FC_XNU_TXM_CONTEXT_TARGET, 'target_spsr': event_state.spsr_gl1 == 5056, 'target_image': event_state.handoff.get('image') == 'txm', 'target_segment': event_state.handoff.get('segment') == '__TEXT_EXEC', 'target_linked_pc': event_state.handoff.get('linked_pc') == run.FC_XNU_TXM_CONTEXT_LINKED, 'target_source_match': event_state.handoff.get('bytes_match') is True, 'target_bytes': event_state.target_bytes == run.FC_XNU_TXM_CONTEXT_BYTES, 'target_sha256': run.hashlib.sha256(event_state.target_bytes).hexdigest() == run.FC_XNU_TXM_CONTEXT_SHA256, 'stack_x0': int(event_state.ctx.regs[0]) == run.FC_XNU_TXM_CONTEXT_STACK, 'stack_aligned': int(event_state.ctx.regs[0]) & run.PAGE - 1 == 0, 'target_mapping': event_state.target_mapping is not None and event_state.target_mapping['level'] == 3 and event_state.target_mapping['access_flag'] and event_state.target_mapping['read_only'] and (not event_state.target_mapping['pxn']) and (run.base <= event_state.target_mapping['pa'] < run.base + run.guest_size), 'target_normal_wb': event_state.target_mapping is not None and event_state.mair is not None and (event_state.mair >> (event_state.target_mapping['descriptor'] >> 2 & 7) * 8 & 255 == 255), 'target_no_hierarchical_restriction': event_state.target_mapping is not None and event_state.target_permissions is not None and all((event_state.target_mapping[name] == event_state.target_permissions['native'][name] for name in ('read_only', 'user_access', 'pxn', 'uxn'))), 'target_guarded_gl0_rx': event_state.target_permissions is not None and event_state.target_permissions['user_read'] and (not event_state.target_permissions['user_write']) and event_state.target_permissions['user_execute'], 'stack_mapping': event_state.stack_owned_leaf, 'stack_normal_wb': event_state.stack_mapping is not None and event_state.mair is not None and (event_state.mair >> (event_state.stack_mapping['descriptor'] >> 2 & 7) * 8 & 255 == 255), 'stack_no_hierarchical_restriction': event_state.stack_mapping is not None and event_state.stack_permissions is not None and all((event_state.stack_mapping[name] == event_state.stack_permissions['native'][name] for name in ('read_only', 'user_access', 'pxn', 'uxn'))), 'stack_guarded_gl0_rw': event_state.stack_permissions is not None and event_state.stack_permissions['user_read'] and event_state.stack_permissions['user_write'] and (not event_state.stack_permissions['user_execute'])}
                if event_state.prefix:
                    event_state.checks['register_prefix_source'] = event_state.prefix_source == run.FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES and run.hashlib.sha256(event_state.prefix_source).hexdigest() == run.FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_SHA256
                if event_state.claim:
                    event_state.checks['stack_claim_source'] = event_state.claim_source == run.struct.pack('<I', run.FC_XNU_TXM_CONTEXT_CASB_WORD)
                    event_state.checks['stack_claim_initial_zero'] = event_state.claim_before == b'\x00'
                if event_state.metadata:
                    event_state.checks['post_claim_source'] = event_state.post_claim_source == run.FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES and run.hashlib.sha256(event_state.post_claim_source).hexdigest() == run.FC_XNU_TXM_CONTEXT_POST_CLAIM_SHA256
                    event_state.checks['metadata_frame_in_stack_page'] = event_state.metadata_frame_pa is not None and event_state.stack_mapping['pa'] <= event_state.metadata_frame_pa and (event_state.metadata_frame_pa + 122 <= event_state.stack_mapping['pa'] + run.PAGE)
                    event_state.checks['metadata_initial_zero'] = event_state.metadata_before.get('state') == b'\x00' and event_state.metadata_before.get('zero_word') == b'\x00' * 4 and (event_state.metadata_before.get('claim') == b'\x00') and (event_state.metadata_before.get('zero_byte') == b'\x00')
                if event_state.x18_branch:
                    event_state.checks['x18_branch_source'] = event_state.x18_window_source == run.FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES and run.hashlib.sha256(event_state.x18_window_source).hexdigest() == run.FC_XNU_TXM_CONTEXT_X18_WINDOW_SHA256 and (event_state.x18_window_source[:4] == run.struct.pack('<I', run.FC_XNU_TXM_CONTEXT_X18_CBNZ_WORD)) and (event_state.x18_window_source[-4:] == run.struct.pack('<I', run.FC_XNU_TXM_CONTEXT_OUTBOUND_BRANCH_WORD))
                if event_state.outbound:
                    event_state.checks['outbound_target_source'] = event_state.outbound_source_in_segment and event_state.outbound_source[:len(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)] == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES and (run.hashlib.sha256(event_state.outbound_source[:len(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)]).hexdigest() == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_SHA256)
                    event_state.branch_imm26 = run.FC_XNU_TXM_CONTEXT_OUTBOUND_BRANCH_WORD & 67108863
                    event_state.branch_delta = (event_state.branch_imm26 ^ 33554432) - 33554432 << 2
                    event_state.checks['outbound_branch_target'] = run.FC_XNU_TXM_CONTEXT_TARGET + 124 + event_state.branch_delta == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET
                    event_state.checks['outbound_target_mapping'] = event_state.outbound_owned_leaf
                    event_state.checks['outbound_target_normal_wb'] = event_state.outbound_mapping is not None and event_state.mair is not None and (event_state.mair >> (event_state.outbound_mapping['descriptor'] >> 2 & 7) * 8 & 255 == 255)
                    event_state.checks['outbound_target_no_hierarchical_restriction'] = event_state.outbound_mapping is not None and event_state.outbound_permissions is not None and all((event_state.outbound_mapping[name] == event_state.outbound_permissions['native'][name] for name in ('read_only', 'user_access', 'pxn', 'uxn')))
                    event_state.checks['outbound_target_guarded_gl0_rx'] = event_state.outbound_permissions is not None and event_state.outbound_permissions['user_read'] and (not event_state.outbound_permissions['user_write']) and event_state.outbound_permissions['user_execute']
                    event_state.checks['outbound_target_live_bytes'] = event_state.outbound_live_bytes is not None and event_state.outbound_live_bytes[:len(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)] == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES and (event_state.outbound_live_bytes == event_state.outbound_source) and (run.hashlib.sha256(event_state.outbound_live_bytes[:len(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES)]).hexdigest() == run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_SHA256)
                if event_state.handler_boundary is not None:
                    event_state.checks['handler_prologue_source'] = event_state.outbound_source[:12] == run.FC_XNU_TXM_HANDLER_PROLOGUE_BYTES and event_state.outbound_live_bytes is not None and (event_state.outbound_live_bytes[:12] == run.FC_XNU_TXM_HANDLER_PROLOGUE_BYTES) and (run.hashlib.sha256(event_state.outbound_live_bytes[:12]).hexdigest() == run.FC_XNU_TXM_HANDLER_PROLOGUE_SHA256)
                if event_state.handler_boundary in ('local-setup', 'validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace'):
                    event_state.checks['handler_local_setup_source'] = len(event_state.outbound_source) >= run.FC_XNU_TXM_HANDLER_LOCAL_SETUP_SIZE and event_state.outbound_live_bytes == event_state.outbound_source and (run.hashlib.sha256(event_state.outbound_source[:run.FC_XNU_TXM_HANDLER_LOCAL_SETUP_SIZE]).hexdigest() == run.FC_XNU_TXM_HANDLER_LOCAL_SETUP_SHA256)
                    event_state.checks['handler_helper_source'] = event_state.helper_source == run.FC_XNU_TXM_HANDLER_HELPER_BYTES and run.hashlib.sha256(event_state.helper_source).hexdigest() == run.FC_XNU_TXM_HANDLER_HELPER_SHA256
                    event_state.checks['handler_helper_mapping'] = event_state.helper_owned_leaf
                    event_state.checks['handler_helper_guarded_gl0_rx'] = event_state.helper_permissions is not None and event_state.helper_permissions['user_read'] and (not event_state.helper_permissions['user_write']) and event_state.helper_permissions['user_execute']
                    event_state.checks['handler_helper_live_bytes'] = event_state.helper_live_bytes == run.FC_XNU_TXM_HANDLER_HELPER_BYTES and event_state.helper_live_bytes == event_state.helper_source
                if event_state.handler_boundary in ('validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace'):
                    event_state.checks['handler_validator_entry_source'] = len(event_state.outbound_source) == run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SIZE and run.hashlib.sha256(event_state.outbound_source).hexdigest() == run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SHA256
                    event_state.checks['handler_global_mapping'] = event_state.handler_global_owned_leaf
                    event_state.checks['handler_global_guarded_gl0_read'] = event_state.handler_global_permissions is not None and event_state.handler_global_permissions['user_read']
                    event_state.checks['handler_global_initial_zero'] = event_state.handler_global_before == b'\x00'
                if event_state.handler_boundary in ('response-trace', 'cmd1-completion-trace'):
                    event_state.checks['handler_response_pointer_mapping'] = event_state.response_pointer_owned_leaf
                    event_state.checks['handler_response_pointer_guarded_gl0_read'] = event_state.response_pointer_permissions is not None and event_state.response_pointer_permissions['user_read']
                    event_state.checks['handler_response_pointer_read'] = event_state.response_pointer_before is not None and len(event_state.response_pointer_before) == 8
                event_state.classification['checks'] = event_state.checks
                if event_state.gate_error is not None:
                    event_state.classification['gate_error'] = event_state.gate_error
                event_state.gate = dict(enabled=True, checks=event_state.checks, trap_pc=hex(event_state.ctx.elr), target_pc=hex(event_state.elr_gl1), target_spsr=hex(event_state.spsr_gl1), x0=hex(int(event_state.ctx.regs[0])), x3=hex(int(event_state.ctx.regs[3])), x16=hex(int(event_state.ctx.regs[16])), target_mapping=event_state.target_mapping, stack_mapping=event_state.stack_mapping, target_guarded_permissions=event_state.target_permissions, stack_guarded_permissions=event_state.stack_permissions, pperm_el1=event_state.pperm, uperm_el0=event_state.uperm, mair_el12=event_state.mair, expected_next_pc=hex(run.FC_XNU_TXM_CONTEXT_TARGET + 4), expected_sp_el0=hex(run.FC_XNU_TXM_CONTEXT_STACK))
                if event_state.claim:
                    event_state.gate.update(claim_va=hex(run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 1024 + 88), claim_pa=hex(event_state.first_touch_pa) if event_state.first_touch_pa is not None else None, claim_before_hex=event_state.claim_before.hex() if event_state.claim_before is not None else None)
                if event_state.metadata:
                    event_state.gate.update(metadata_frame_va=hex(run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 1024), metadata_frame_pa=hex(event_state.metadata_frame_pa) if event_state.metadata_frame_pa is not None else None, metadata_before_hex={name: value.hex() for name, value in event_state.metadata_before.items()}, metadata_page_before_sha256=run.hashlib.sha256(event_state.metadata_page_before).hexdigest() if event_state.metadata_page_before is not None else None, metadata_writes=[dict(va=hex(run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 1024 + 4), pa=hex(event_state.metadata_frame_pa + 4) if event_state.metadata_frame_pa is not None else None, width=4, value_hex='00000000'), dict(va=hex(run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 1024 + 121), pa=hex(event_state.metadata_frame_pa + 121) if event_state.metadata_frame_pa is not None else None, width=1, value_hex='00'), dict(va=hex(run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 1024), pa=hex(event_state.metadata_frame_pa) if event_state.metadata_frame_pa is not None else None, width=1, value_hex='01')])
                if event_state.x18_branch:
                    event_state.gate.update(x18_branch_pc=hex(run.FC_XNU_TXM_CONTEXT_TARGET + 108), x18_branch_linked=hex(int(run.FC_XNU_TXM_CONTEXT_LINKED, 16) + 108), x18_branch_word=hex(run.FC_XNU_TXM_CONTEXT_X18_CBNZ_WORD), x18_taken_target_pc=hex(run.FC_XNU_TXM_CONTEXT_TARGET + 124), x18_taken_target_linked=hex(int(run.FC_XNU_TXM_CONTEXT_LINKED, 16) + 124), x18_taken_target_word=hex(run.FC_XNU_TXM_CONTEXT_OUTBOUND_BRANCH_WORD), expected_fallthrough_skipped=True, expected_stop_before_outbound_branch=True)
                if event_state.outbound:
                    event_state.gate.update(outbound_target_pc=hex(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET), outbound_target_linked=hex(run.FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED), outbound_target_mapping=event_state.outbound_mapping, outbound_target_guarded_permissions=event_state.outbound_permissions, outbound_target_sha256=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_SHA256, outbound_target_live_bytes_hex=event_state.outbound_live_bytes.hex() if event_state.outbound_live_bytes is not None else None, outbound_target_live_sha256=run.hashlib.sha256(event_state.outbound_live_bytes).hexdigest() if event_state.outbound_live_bytes is not None else None, expected_stop_before_pacibsp=True)
                if event_state.handler_boundary is not None:
                    event_state.terminal_offset = {'prologue': 8, 'register-saves': 32, 'local-setup': 68, 'validator-entry': 160, 'validator-trace': 164, 'response-trace': 1204, 'cmd1-completion-trace': 1204}[event_state.handler_boundary]
                    event_state.gate.update(boundary=event_state.handler_boundary, handler_entry_pc=hex(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET), handler_prologue_sha256=run.FC_XNU_TXM_HANDLER_PROLOGUE_SHA256, expected_terminal_pc=hex(run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + event_state.terminal_offset), expected_terminal_sp=hex(run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 1024 - 112))
                    if event_state.handler_boundary == 'prologue':
                        event_state.gate['expected_stop_before_first_stp'] = True
                    elif event_state.handler_boundary == 'register-saves':
                        event_state.gate.update(expected_saved_register_pairs=5, expected_stop_before_argument_moves=True)
                    elif event_state.handler_boundary == 'local-setup':
                        event_state.gate.update(handler_local_setup_sha256=run.FC_XNU_TXM_HANDLER_LOCAL_SETUP_SHA256, handler_helper_pc=hex(run.FC_XNU_TXM_HANDLER_HELPER), handler_helper_sha256=run.FC_XNU_TXM_HANDLER_HELPER_SHA256, expected_local_marker_va=hex(run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 1024 - 112 + 24), expected_stop_before_global_adrp=True)
                    else:
                        event_state.gate.update(handler_validator_entry_sha256=run.FC_XNU_TXM_HANDLER_VALIDATOR_ENTRY_SHA256, handler_global_va=hex(run.FC_XNU_TXM_HANDLER_GLOBAL), handler_global_mapping=event_state.handler_global_mapping, handler_global_guarded_permissions=event_state.handler_global_permissions, handler_global_before_hex=event_state.handler_global_before.hex() if event_state.handler_global_before is not None else None, expected_validator_selector=45, expected_stop_before_validator_call=True)
                        if event_state.handler_boundary in ('response-trace', 'cmd1-completion-trace'):
                            event_state.gate.update(response_pointer_va=hex(run.FC_XNU_TXM_HANDLER_RESPONSE_POINTER), response_pointer_mapping=event_state.response_pointer_mapping, response_pointer_before_hex=event_state.response_pointer_before.hex() if event_state.response_pointer_before is not None else None, expected_response_stop=hex(run.FC_XNU_TXM_HANDLER_RESPONSE_STOP), expected_stop_before_completion_call=True)
                event_state.report_key = 'xnu_txm_handler_boundary' if event_state.handler_boundary is not None else 'xnu_txm_context_outbound_branch_one_step' if event_state.outbound else 'xnu_txm_context_x18_branch_one_step' if event_state.x18_branch else 'xnu_txm_context_stack_metadata_init' if event_state.metadata else 'xnu_txm_context_stack_claim_one_step' if event_state.claim else 'xnu_txm_context_entry_register_prefix' if event_state.prefix else 'xnu_txm_context_entry_one_step'
                run.report[event_state.report_key] = event_state.gate
                if all(event_state.checks.values()):
                    event_state.txm_context_step = True
                    event_state.classification['decision'] = 'txm-handler-' + event_state.handler_boundary if event_state.handler_boundary is not None else 'txm-context-outbound-branch-one-step' if event_state.outbound else 'txm-context-x18-branch-one-step' if event_state.x18_branch else 'txm-context-stack-metadata-init' if event_state.metadata else 'txm-context-stack-claim' if event_state.claim else 'txm-context-register-prefix' if event_state.prefix else 'txm-context-one-step'
                else:
                    run.report['stop_reason'] = 'txm-context-entry-gate-rejected'
            if event_state.completion_eret:
                event_state.classification['decision'] = 'cmd1-completion-eret'
                run.report['xnu_txm_sstep_fast_path']['completion_eret'] = dict(trap_pc=hex(event_state.ctx.elr), target_pc=hex(event_state.elr_gl1), target_spsr=hex(event_state.spsr_gl1), guarded_esr=hex(event_state.completion_guarded_esr), guarded_aspsr=hex(event_state.completion_guarded_aspsr), status=event_state.completion_fast_status, checks_passed=True)
                run.report['stop_reason'] = 'cmd1-completion-eret'
            elif event_state.phase53_eret:
                event_state.classification['decision'] = 'phase53-world-transition'
                run.report['stop_reason'] = 'phase53-world-transition'
            elif event_state.entry_launch:
                event_state.classification['decision'] = 'entry-launch'
                run.report['handoff'] = event_state.eret_record
                run.report['stop_reason'] = 'handoff-' + ('xnu' if event_state.handoff['image'] == 'kernelcache' else 'txm') + '-entry'
            elif event_state.txm_return:
                event_state.classification['decision'] = 'txm-world-return'
                run.report.setdefault('txm_world_returns', []).append(event_state.eret_record)
                run.report['stop_reason'] = 'txm-world-return'
            if event_state.txm_context_step:
                event_state.stack = run.FC_XNU_TXM_CONTEXT_STACK
                event_state.expected_states = [dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 4, sp=event_state.stack, regs={0: event_state.stack}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 8, sp=event_state.stack, regs={0: 1}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 12, sp=event_state.stack, regs={0: 1}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 16, sp=event_state.stack, regs={0: 1}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 20, sp=event_state.stack, regs={0: 1, 8: event_state.stack}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 24, sp=event_state.stack, regs={0: 1, 8: 0}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 40, sp=event_state.stack, regs={0: 1, 8: 0}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 44, sp=event_state.stack, regs={0: 1, 8: event_state.stack}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 48, sp=event_state.stack, regs={0: 1, 8: event_state.stack}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 52, sp=event_state.stack, regs={0: 1, 8: event_state.stack + run.PAGE}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 56, sp=event_state.stack, regs={0: 1, 8: event_state.stack + run.PAGE - 1024}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 60, sp=event_state.stack + run.PAGE - 1024, regs={0: 1, 8: event_state.stack + run.PAGE - 1024}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 64, sp=event_state.stack + run.PAGE - 1024, regs={0: 1, 8: event_state.stack + run.PAGE - 1024 + 88}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 68, sp=event_state.stack + run.PAGE - 1024, regs={0: 1, 8: event_state.stack + run.PAGE - 1024 + 88, 9: 0}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 72, sp=event_state.stack + run.PAGE - 1024, regs={0: 1, 8: event_state.stack + run.PAGE - 1024 + 88, 9: 0, 10: 1})]
                for event_state.state_index, event_state.state in enumerate(event_state.expected_states):
                    event_state.state['spsr'] = 5056 if event_state.state_index < 2 else 536875968
                if event_state.claim:
                    event_state.expected_states.append(dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 76, sp=event_state.stack + run.PAGE - 1024, spsr=536875968, regs={0: 1, 8: event_state.stack + run.PAGE - 1024 + 88, 9: 0, 10: 1}, memory={'claim': '01'}))
                if event_state.metadata:
                    event_state.frame = event_state.stack + run.PAGE - 1024
                    event_state.common = {0: 1, 8: event_state.frame + 88, 9: 0, 10: 1}
                    event_state.expected_states.extend([dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 92, sp=event_state.frame, spsr=536875968, regs=dict(event_state.common), memory={'claim': '01'}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 96, sp=event_state.frame, spsr=536875968, regs=dict(event_state.common), memory={'claim': '01', 'zero_word': '00000000'}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 100, sp=event_state.frame, spsr=536875968, regs=dict(event_state.common), memory={'claim': '01', 'zero_word': '00000000', 'zero_byte': '00'}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 104, sp=event_state.frame, spsr=536875968, regs={0: 1, 8: 1, 9: 0, 10: 1}, memory={'claim': '01', 'zero_word': '00000000', 'zero_byte': '00'}), dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 108, sp=event_state.frame, spsr=536875968, regs={0: 1, 8: 1, 9: 0, 10: 1}, memory={'state': '01', 'claim': '01', 'zero_word': '00000000', 'zero_byte': '00'})])
                if event_state.x18_branch:
                    event_state.expected_states.append(dict(pc=run.FC_XNU_TXM_CONTEXT_TARGET + 124, sp=event_state.frame, spsr=536875968, regs={0: 1, 8: 1, 9: 0, 10: 1}, memory={'state': '01', 'claim': '01', 'zero_word': '00000000', 'zero_byte': '00'}))
                if event_state.outbound:
                    event_state.outbound_state = dict(pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET, sp=event_state.frame, spsr=536875968, regs={0: 1, 8: 1, 9: 0, 10: 1}, memory={'state': '01', 'claim': '01', 'zero_word': '00000000', 'zero_byte': '00'})
                    if event_state.handler_boundary is not None:
                        event_state.outbound_state['capture_regs'] = tuple(range(30))
                    event_state.expected_states.append(event_state.outbound_state)
                if event_state.handler_boundary is not None:
                    event_state.expected_states.extend([dict(pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 4, sp=event_state.frame, spsr=536875968, regs={0: 1, 8: 1, 9: 0, 10: 1}, capture_regs=(30,), same_captured_regs=tuple(range(30)), memory={'state': '01', 'claim': '01', 'zero_word': '00000000', 'zero_byte': '00'}), dict(pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 8, sp=event_state.frame - 112, spsr=536875968, regs={0: 1, 8: 1, 9: 0, 10: 1}, same_captured_regs=tuple(range(31)), memory={'state': '01', 'claim': '01', 'zero_word': '00000000', 'zero_byte': '00'})])
                if event_state.handler_boundary in ('register-saves', 'local-setup', 'validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace'):
                    event_state.handler_sp = event_state.frame - 112
                    event_state.handler_memory = {'state': '01', 'claim': '01', 'zero_word': '00000000', 'zero_byte': '00'}
                    for event_state.pair_index in range(5):
                        event_state.expected_states.append(dict(pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 12 + event_state.pair_index * 4, sp=event_state.handler_sp, spsr=536875968, regs={0: 1, 8: 1, 9: 0, 10: 1}, same_captured_regs=tuple(range(31)), saved_pairs=event_state.pair_index + 1, memory=dict(event_state.handler_memory)))
                    event_state.expected_states.append(dict(pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 32, sp=event_state.handler_sp, spsr=536875968, regs={0: 1, 8: 1, 9: 0, 10: 1, 29: event_state.handler_sp + 96}, same_captured_regs=tuple((register for register in range(31) if register != 29)), saved_pairs=5, memory=dict(event_state.handler_memory)))
                if event_state.handler_boundary in ('local-setup', 'validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace'):
                    event_state.moved = {}
                    for event_state.offset, event_state.destination, event_state.source in ((36, 23, 5), (40, 24, 4), (44, 22, 3), (48, 21, 2), (52, 20, 1), (56, 25, 0)):
                        event_state.moved[event_state.destination] = event_state.source
                        event_state.expected_states.append(dict(pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + event_state.offset, sp=event_state.handler_sp, spsr=536875968, regs={29: event_state.handler_sp + 96}, same_captured_regs=tuple((register for register in range(31) if register not in set(event_state.moved) | {29})), captured_reg_values=dict(event_state.moved), saved_pairs=5, memory=dict(event_state.handler_memory)))
                    event_state.return_pc = run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 60
                    event_state.common_helper = dict(sp=event_state.handler_sp, spsr=536875968, same_captured_regs=tuple((register for register in range(31) if register not in set(event_state.moved) | {29, 30})), captured_reg_values=dict(event_state.moved), saved_pairs=5, memory=dict(event_state.handler_memory))
                    event_state.helper_states = ((run.FC_XNU_TXM_HANDLER_HELPER, 1), (run.FC_XNU_TXM_HANDLER_HELPER + 4, 1), (run.FC_XNU_TXM_HANDLER_HELPER + 8, event_state.handler_sp), (run.FC_XNU_TXM_HANDLER_HELPER + 12, event_state.stack), (run.FC_XNU_TXM_HANDLER_HELPER + 16, event_state.stack + run.PAGE), (run.FC_XNU_TXM_HANDLER_HELPER + 20, event_state.frame), (event_state.return_pc, event_state.frame))
                    for event_state.helper_index, (event_state.helper_pc, event_state.x0_value) in enumerate(event_state.helper_states):
                        event_state.state = dict(event_state.common_helper)
                        event_state.state.update(pc=event_state.helper_pc, regs={0: event_state.x0_value, 29: event_state.handler_sp + 96, 30: event_state.return_pc})
                        if event_state.helper_index >= 2:
                            event_state.state['same_captured_regs'] = tuple((register for register in event_state.state['same_captured_regs'] if register != 0))
                        event_state.expected_states.append(event_state.state)
                    event_state.post_helper_preserved = tuple((register for register in event_state.common_helper['same_captured_regs'] if register not in (0, 8)))
                    event_state.expected_states.append(dict(event_state.common_helper, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 64, regs={0: event_state.frame, 8: 1, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.post_helper_preserved))
                    event_state.local_memory = dict(event_state.handler_memory)
                    event_state.local_memory['local_marker'] = '0100000000000000'
                    event_state.expected_states.append(dict(event_state.common_helper, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 68, regs={0: event_state.frame, 8: 1, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, memory=event_state.local_memory, same_captured_regs=event_state.post_helper_preserved))
                if event_state.handler_boundary in ('validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace'):
                    event_state.global_page = run.FC_XNU_TXM_HANDLER_GLOBAL & ~(run.PAGE - 1)
                    event_state.validator_preserved = tuple((register for register in event_state.post_helper_preserved if register != 26))
                    event_state.validator_common = dict(sp=event_state.handler_sp, saved_pairs=5, captured_reg_values=dict(event_state.moved), memory=event_state.local_memory)
                    event_state.expected_states.extend([dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 72, spsr=536875968, regs={0: event_state.frame, 8: 1, 26: event_state.global_page, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.validator_preserved), dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 76, spsr=536875968, regs={0: event_state.frame, 8: 1, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.validator_preserved), dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 80, spsr=536875968, regs={0: event_state.frame, 8: 0, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.validator_preserved)])
                    event_state.route_preserved = tuple((register for register in event_state.validator_preserved if register != 9))
                    event_state.expected_states.extend([dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 84, spsr=536875968, regs={0: event_state.frame, 8: 0, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.validator_preserved), dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 88, spsr=536875968, regs={0: event_state.frame, 8: 0, 9: event_state.handler_sp + 24, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.route_preserved), dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 92, spsr=2147488704, regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 24, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.route_preserved), dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 116, spsr=2147488704, regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 24, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.route_preserved), dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 120, spsr=2147488704, regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 24, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.route_preserved), dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 132, spsr=2147488704, regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 24, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.route_preserved)])
                    event_state.after_x19 = tuple((register for register in event_state.route_preserved if register != 19))
                    event_state.expected_states.append(dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 136, spsr=2147488704, regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 24, 19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.after_x19))
                    event_state.validator_memory = dict(event_state.local_memory, validator_base=run.struct.pack('<Q', event_state.stack).hex())
                    event_state.expected_states.append(dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 140, spsr=2147488704, regs={0: event_state.frame, 8: event_state.stack, 9: event_state.handler_sp + 24, 19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.after_x19, memory=event_state.validator_memory))
                    event_state.expected_states.append(dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 144, spsr=2147488704, regs={0: event_state.frame, 8: run.PAGE, 9: event_state.handler_sp + 24, 19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.after_x19, memory=event_state.validator_memory))
                    event_state.expected_states.append(dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 148, spsr=2147488704, regs={0: event_state.frame, 8: run.PAGE, 9: event_state.handler_sp + 24, 19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.after_x19, memory=event_state.validator_memory))
                    event_state.validator_sizes = dict(event_state.validator_memory, validator_sizes=run.struct.pack('<QQ', run.PAGE, run.PAGE).hex())
                    event_state.expected_states.append(dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 152, spsr=2147488704, regs={0: event_state.frame, 8: run.PAGE, 9: event_state.handler_sp + 24, 19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.after_x19, memory=event_state.validator_sizes))
                    event_state.expected_states.append(dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 156, spsr=2147488704, regs={0: event_state.handler_sp, 8: run.PAGE, 9: event_state.handler_sp + 24, 19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.after_x19, memory=event_state.validator_sizes))
                    event_state.final_preserved = tuple((register for register in event_state.after_x19 if register != 1))
                    event_state.expected_states.append(dict(event_state.validator_common, pc=run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 160, spsr=2147488704, regs={0: event_state.handler_sp, 1: 45, 8: run.PAGE, 9: event_state.handler_sp + 24, 19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: event_state.return_pc}, same_captured_regs=event_state.final_preserved, memory=event_state.validator_sizes))
                    if event_state.handler_boundary in ('validator-trace', 'response-trace', 'cmd1-completion-trace'):
                        event_state.expected_states.append(dict(event_state.validator_common, pc=18446741875072371556, sp=event_state.handler_sp, spsr=2147488704, regs={0: event_state.handler_sp, 1: 45, 8: run.PAGE, 9: event_state.handler_sp + 24, 19: event_state.frame, 26: run.FC_XNU_TXM_HANDLER_GLOBAL, 29: event_state.handler_sp + 96, 30: run.FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET + 164}, same_captured_regs=event_state.final_preserved, captured_reg_values=dict(event_state.moved), saved_pairs=5, memory=event_state.validator_sizes, begin_validator_trace=True))
                if not event_state.prefix:
                    event_state.expected_states = event_state.expected_states[:1]
                run.txm_context_step_state.update(active=True, index=0, expected_states=event_state.expected_states, report_key=event_state.report_key, roots=dict(event_state.roots), first_touch_va=run.FC_XNU_TXM_CONTEXT_STACK + run.PAGE - 1024 + 88, first_touch_pa=event_state.first_touch_pa, stack_page_pa=event_state.stack_mapping['pa'] if event_state.stack_mapping is not None else None, metadata_frame_pa=event_state.metadata_frame_pa, metadata_page_before=event_state.metadata_page_before, response_pointer_before=event_state.response_pointer_before, handler_boundary=event_state.handler_boundary, captured_regs={}, metadata_offsets={'state': (0, 1), 'zero_word': (4, 4), 'claim': (88, 1), 'zero_byte': (121, 1), 'local_marker': (-88, 8), 'validator_base': (-112, 8), 'validator_sizes': (-104, 16)}, event_kind='txm-handler-' + event_state.handler_boundary if event_state.handler_boundary is not None else 'txm-context-outbound-branch-one-step' if event_state.outbound else 'txm-context-x18-branch-one-step' if event_state.x18_branch else 'txm-context-stack-metadata-init' if event_state.metadata else 'txm-context-stack-claim-one-step' if event_state.claim else 'txm-context-entry-register-prefix' if event_state.prefix else 'txm-context-entry-one-step', complete_reason='txm-handler-' + event_state.handler_boundary + '-complete' if event_state.handler_boundary is not None else 'txm-context-outbound-branch-one-step-complete' if event_state.outbound else 'txm-context-x18-branch-one-step-complete' if event_state.x18_branch else 'txm-context-stack-metadata-init-complete' if event_state.metadata else 'txm-context-stack-claim-one-step-complete' if event_state.claim else 'txm-context-entry-register-prefix-complete' if event_state.prefix else 'txm-context-entry-one-step-complete', mismatch_reason='txm-handler-' + event_state.handler_boundary + '-mismatch' if event_state.handler_boundary is not None else 'txm-context-outbound-branch-one-step-mismatch' if event_state.outbound else 'txm-context-x18-branch-one-step-mismatch' if event_state.x18_branch else 'txm-context-stack-metadata-init-mismatch' if event_state.metadata else 'txm-context-stack-claim-one-step-mismatch' if event_state.claim else 'txm-context-entry-register-prefix-mismatch' if event_state.prefix else 'txm-context-entry-one-step-mismatch')
                event_state.ctx.elr = event_state.elr_gl1
                event_state.ctx.spsr = type(event_state.ctx.spsr)(event_state.spsr_gl1)
                event_state.ctx.spsr.SS = 1
                run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                run.report.pop('stop_reason', None)
                event_state.ret = run.EXC_RET.HANDLED
            elif event_state.completion_eret:
                event_state.ctx.elr = event_state.elr_gl1
                event_state.ctx.spsr = type(event_state.ctx.spsr)(event_state.spsr_gl1)
                event_state.ctx.spsr.SS = 1
                run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                run.report.pop('stop_reason', None)
                event_state.ret = run.EXC_RET.HANDLED
            elif event_state.phase53_eret:
                event_state.ctx.elr = event_state.elr_gl1
                event_state.ctx.spsr = type(event_state.ctx.spsr)(event_state.spsr_gl1)
                event_state.ctx.spsr.SS = 1
                run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                run.report.pop('stop_reason', None)
                event_state.event['kind'] = 'phase53-world-transition'
                event_state.ret = run.EXC_RET.HANDLED
            elif event_state.entry_launch or event_state.txm_return:
                event_state.resume_txm = event_state.txm_return
                if run.a.handoff_steps and event_state.entry_launch or event_state.resume_txm:
                    event_state.ctx.elr = event_state.elr_gl1
                    event_state.ctx.spsr = type(event_state.ctx.spsr)(event_state.spsr_gl1)
                    if event_state.resume_txm:
                        event_state.eret_record['native_resume'] = True
                    else:
                        run.handoff_state['active'] = True
                        event_state.ctx.spsr.SS = 1
                        run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                    run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                    run.report.pop('stop_reason', None)
                    event_state.ret = run.EXC_RET.HANDLED
        else:
            run.report['stop_reason'] = 'eret-unknown-target'
            run.report['eret_unknown'] = dict(pc=hex(event_state.ctx.elr), note='ELR_GL1 read 0; stopped without emulating eret')
    elif run.entered and run.a.free_run and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.esr >> 26 == 22) and (event_state.esr & 65520 == 24704):
        run.report['stop_reason'] = 'unexpected-eret-overlay'
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.esr >> 26 == 22) and (event_state.esr & 65408 == 24576):
        event_state.imm = event_state.esr & 65535
        event_state.read, event_state.rt, event_state.sctlr = (bool(event_state.imm & 32), event_state.imm & 31, bool(event_state.imm & 64))
        event_state.value = 0 if event_state.rt == 31 else event_state.ctx.regs[event_state.rt]
        event_state.event.update(kind='probe-control', register='SCTLR_EL2' if event_state.sctlr else 'HCR_EL2', read=event_state.read, value=event_state.value)
        event_state.accepted = False
        for event_state.attempt in range(2):
            if event_state.read:
                if event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = run.shadow_sctlr if event_state.sctlr else run.shadow_hcr
                event_state.accepted = True
            elif not event_state.sctlr and event_state.value in (0, 17314086912) and (not run.shadow_sctlr & 1 or event_state.value == run.shadow_hcr):
                run.shadow_hcr = event_state.value
                event_state.accepted = True
            elif event_state.sctlr and event_state.value in (0, 818939904):
                if run.shadow_sctlr & 1:
                    run.u.msr(run.SCTLR_EL12, 818939904)
                    run.u.exec('isb; dsb ishst; tlbi vmalle1is; dsb ish; isb')
                run.shadow_sctlr = event_state.value
                event_state.accepted = True
            elif event_state.sctlr and run.a.allow_monitor_mmu and (event_state.value == 144132853210577213) and (run.shadow_hcr == 17314086912) and (run.shadow_sprr_config == 0):
                event_state.controls = dict(tcr=run.u.mrs(run.TCR_EL12), ttbr0=run.u.mrs(run.TTBR0_EL12), ttbr1=run.u.mrs(run.TTBR1_EL12), mair=run.u.mrs(run.MAIR_EL12))
                run.report['monitor_mmu_controls'] = event_state.controls
                if not run.monitor_mmu_validated:
                    if int(event_state.ctx.spsr) & 15 not in (4, 5):
                        raise ValueError('Unsupported physical guest mode for monitor entry')
                    event_state.active_sp = event_state.ctx.sp[0] if int(event_state.ctx.spsr) & 15 == 4 else event_state.ctx.sp[1]
                    event_state.checked = run.validate_monitor_entry(event_state.controls, event_state.ctx.elr, event_state.active_sp, run.base + run.args_off, run.base, run.guest_size, lambda addr: run.iface.readmem(addr, run.PAGE), pan=bool(int(event_state.ctx.spsr) & 1 << 22), on_check=lambda name, addr: run.report.update(monitor_mmu_check_pending=dict(name=name, va=addr)))
                    run.report['monitor_mmu_address_checks'] = event_state.checked
                    run.monitor_mmu_validated = True
                    event_state.event['kind'] = 'monitor-mmu-enabled'
                else:
                    event_state.event['kind'] = 'monitor-mmu-reentry'
                run.u.exec('dsb ishst; tlbi vmalle1is; dsb ish; isb')
                run.u.msr(run.SCTLR_EL12, event_state.value)
                run.u.exec('isb')
                run.shadow_sctlr = event_state.value
                event_state.accepted = True
            if event_state.accepted or event_state.attempt or (not (event_state.sctlr and (not event_state.read) and (event_state.value == 144132853210577213) and (run.shadow_hcr == 17314086912) and (run.shadow_sprr_config == 0) and run.pause_guard('monitor-translation-contract', 'allow_monitor_mmu', event_state.event))):
                break
        if event_state.accepted:
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            run.report['stop_reason'] = 'monitor-translation-contract'
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.esr >> 26 == 22) and (event_state.esr & 65520 in (24720, 24736)):
        event_state.imm = event_state.esr & 15
        event_state.exiting = event_state.esr & 65520 == 24736
        event_state.was_guarded = run.gxf_state['guarded']
        event_state.event.update(kind='guarded-instruction', instruction='gexit' if event_state.exiting else 'genter', imm=event_state.imm, guarded_before=event_state.was_guarded)
        event_state.mode = int(event_state.ctx.spsr) & 15
        if not run.a.virtual_gxf:
            run.report['stop_reason'] = 'unsupported-exception'
        elif not run.gxf_state['config'] & 1 or event_state.mode not in (4, 5) or (event_state.exiting and (not event_state.was_guarded)) or (not event_state.exiting and (not run.apple_shadow[run.GXF_ENTRY_EL1])):
            run.report['stop_reason'] = 'unsupported-guarded-transition'
        elif event_state.exiting:
            event_state.link_pc, event_state.link_pstate = (run.u.mrs(run.ELR_EL12), run.u.mrs(run.SPSR_EL12))
            for event_state.gl, event_state.el in run.gxf_banks.items():
                run.apple_shadow[event_state.gl] = run.u.mrs(event_state.el)
            for event_state.el, event_state.saved in run.gxf_state['el_bank'].items():
                run.u.msr(event_state.el, event_state.saved)
            event_state.ctx.sp[1], run.gxf_state['sp_bank'] = (run.gxf_state['sp_bank'], event_state.ctx.sp[1])
            run.gxf_state['guarded'] = False
            run.gxf_state['gexit'] += 1
            event_state.ctx.elr = event_state.link_pc
            event_state.ctx.spsr = type(event_state.ctx.spsr)(event_state.link_pstate)
            event_state.event.update(kind='virtual-gexit', link_pc=event_state.link_pc, link_pstate=event_state.link_pstate)
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.link_pc, event_state.link_pstate = (event_state.ctx.elr, int(event_state.ctx.spsr))
            if not event_state.was_guarded:
                run.gxf_state['el_bank'] = {el: run.u.mrs(el) for el in run.gxf_banks.values()}
                for event_state.gl, event_state.el in run.gxf_banks.items():
                    if event_state.gl != run.VBAR_GL1 or run.apple_shadow[event_state.gl]:
                        run.u.msr(event_state.el, run.apple_shadow[event_state.gl])
                event_state.ctx.sp[1], run.gxf_state['sp_bank'] = (run.gxf_state['sp_bank'], event_state.ctx.sp[1])
                run.gxf_state['guarded'] = True
            run.u.msr(run.SPSR_EL12, event_state.link_pstate)
            run.u.msr(run.ELR_EL12, event_state.link_pc)
            run.u.msr(run.ESR_EL12, 4261478400 | event_state.imm)
            run.apple_shadow[run.ASPSR_GL1] = run.apple_shadow[run.ASPSR_GL1] | 1 if event_state.was_guarded else run.apple_shadow[run.ASPSR_GL1] & ~1
            run.gxf_state['genter'] += 1
            event_state.ctx.elr = run.apple_shadow[run.GXF_ENTRY_EL1]
            event_state.ctx.spsr = type(event_state.ctx.spsr)((event_state.link_pstate | 960) & ~15 | 5)
            event_state.event.update(kind='virtual-genter', entry=event_state.ctx.elr, link_pc=event_state.link_pc, link_pstate=event_state.link_pstate, vector_swapped=bool(run.apple_shadow[run.VBAR_GL1]))
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        run.gxf_report().update(guarded=run.gxf_state['guarded'], genter=run.gxf_state['genter'], gexit=run.gxf_state['gexit'], last_transition_index=run.trace_count(run.report))
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.esr >> 26 == 22) and (event_state.esr & 49152 == 32768):
        event_state.imm = event_state.esr & 65535
        event_state.reg = run.extra_regs[(event_state.imm & 16383) >> 6]
        event_state.read, event_state.rt = (bool(event_state.imm & 32), event_state.imm & 31)
        event_state.value = 0 if event_state.rt == 31 else event_state.ctx.regs[event_state.rt]
        event_state.event.update(kind='probe-el2-register', register=run.sysreg_rev.get(event_state.reg, 'AGTCNTVOFF_EL2 (observed encoding)' if event_state.reg == run.apple_cntvoff else 'S3_%d_C%d_C%d_%d' % event_state.reg[1:]), read=event_state.read, value=event_state.value)
        if run.a.real_guarded and event_state.reg in run.real_redirect:
            event_state.xnu_gexit = run.a.native_handoff and (not event_state.read) and (event_state.reg == run.ASPSR_GL1) and (event_state.value == 0) and (event_state.ctx.elr == run.FC_XNU_GEXIT)
            if event_state.xnu_gexit:
                event_state.elr_gl1 = int(run.u.mrs(run.HV.MSR_REDIRECTS[run.ELR_GL1]))
                event_state.spsr_gl1 = int(run.u.mrs(run.HV.MSR_REDIRECTS[run.SPSR_GL1]))
                event_state.roots = dict(ttbr0=run.u.mrs(run.TTBR0_EL12), ttbr1=run.u.mrs(run.TTBR1_EL12))
                event_state.handoff = run.classify_entry(event_state.elr_gl1, run.layout, run.base, run.guest_size, event_state.roots, run.iface.readmem, run.sources)
                event_state.launch = dict(va=event_state.elr_gl1, saved_pstate=event_state.spsr_gl1, callback_pstate=int(event_state.ctx.spsr), permission_source='live guest aliases', controls=dict(event_state.roots), table_pages=[])
                run.report['xnu_launch_permissions'] = event_state.launch
                for event_state.name, event_state.register in (('tcr', run.TCR_EL12), ('mair', run.MAIR_EL12), ('sctlr', run.SCTLR_EL12)):
                    try:
                        event_state.launch['controls'][event_state.name] = int(run.u.mrs(event_state.register))
                    except Exception as capture_error:
                        event_state.launch[event_state.name + '_error'] = str(capture_error)
                for event_state.name, event_state.register in (('pperm_el1', run.SPRR_PPERM_EL1), ('uperm_el0', run.SPRR_UPERM_EL0)):
                    try:
                        event_state.launch[event_state.name] = int(run.u.mrs(run.HV.MSR_REDIRECTS[event_state.register]))
                    except Exception as capture_error:
                        event_state.launch[event_state.name + '_error'] = str(capture_error)

                def read_launch_page(table):
                    data = run.iface.readmem(table, run.PAGE)
                    filename = 'xnu-launch-%x.bin' % table
                    run.capture.save_input(filename, data)
                    event_state.launch['table_pages'].append(dict(pa=table, input=filename))
                    return data
                try:
                    event_state.leaf = run.translate(event_state.elr_gl1, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_launch_page)
                    event_state.launch['mapping'] = event_state.leaf
                    if 'pperm_el1' in event_state.launch and 'uperm_el0' in event_state.launch:
                        for event_state.world in ('ordinary', 'guarded'):
                            event_state.launch[event_state.world] = run.leaf_permissions(event_state.leaf['descriptor'], event_state.launch['pperm_el1'], event_state.launch['uperm_el0'], event_state.world)
                except Exception as capture_error:
                    event_state.launch['mapping_error'] = str(capture_error)
                event_state.verified = event_state.handoff['image'] == 'kernelcache' and event_state.handoff['entry_matches'] and event_state.handoff['bytes_match'] and (event_state.spsr_gl1 == 5065)
                event_state.event.update(kind='xnu-gexit-handoff', target=hex(event_state.elr_gl1), target_spsr=hex(event_state.spsr_gl1), verified=event_state.verified)
                if event_state.verified:
                    run.report['handoff'] = dict(event_state.handoff, spsr=hex(event_state.spsr_gl1), via='native GEXIT launch boundary', source_pc=hex(run.FC_XNU_GEXIT), instructions_executed=False)
                    run.report['stop_reason'] = 'handoff-xnu-entry'
                    if run.a.xnu_steps:
                        if not event_state.launch.get('ordinary', {}).get('kernel_execute') or any((key.endswith('_error') for key in event_state.launch)):
                            run.report['stop_reason'] = 'xnu-launch-permission-unverified'
                        else:
                            event_state.physical_spsr = 5061 | 1 << 21
                            run.u.msr(run.HV.MSR_REDIRECTS[run.SPSR_GL1], event_state.physical_spsr)
                            run.u.msr(run.HV.MSR_REDIRECTS[run.ASPSR_GL1], 0)
                            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                            run.report['handoff']['physical_spsr'] = hex(event_state.physical_spsr)
                            run.report['handoff']['native_resume'] = True
                            run.handoff_state.update(active=True, events=0, xnu=True, budget=run.a.xnu_steps)
                            event_state.ctx.spsr.SS = 1
                            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                            run.report.pop('stop_reason', None)
                            event_state.ret = run.EXC_RET.HANDLED
                else:
                    run.report['stop_reason'] = 'xnu-gexit-unverified'
            elif event_state.read:
                if event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = run.u.mrs(run.HV.MSR_REDIRECTS[event_state.reg])
            else:
                event_state.alias = run.HV.MSR_REDIRECTS[event_state.reg]
                run.u.msr(event_state.alias, event_state.value)
                if event_state.reg == run.VBAR_GL1:
                    event_state.readback = int(run.u.mrs(event_state.alias))
                    if event_state.readback != event_state.value:
                        raise ValueError('Guarded VBAR readback mismatch')
                    run.guarded_vbar = event_state.readback
                    run.report.setdefault('real_guarded_vbar', []).append(dict(index=run.trace_count(run.report), requested=event_state.value, readback=event_state.readback))
                    event_state.event['readback'] = event_state.readback
                if event_state.reg == run.SPRR_CONFIG_EL1:
                    event_state.enable = run.report.setdefault('sprr_real_enable', dict(enforced=True, events=[]))
                    event_state.enable['events'].append(dict(index=run.trace_count(run.report), value=event_state.value, controls=dict(tcr=run.u.mrs(run.TCR_EL12), ttbr0=run.u.mrs(run.TTBR0_EL12), ttbr1=run.u.mrs(run.TTBR1_EL12), mair=run.u.mrs(run.MAIR_EL12)), enable=bool(event_state.value & 1), lock_config=bool(event_state.value & 2), lock_perm=bool(event_state.value & 16), lock_kernel_perm=bool(event_state.value & 32)))
            if not event_state.xnu_gexit:
                event_state.event['kind'] = 'real-guarded-redirect'
                event_state.ctx.spsr.SS = 1
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg in run.translation_banks:
            event_state.bank = run.translation_banks[event_state.reg]
            event_state.current_value = run.u.mrs(event_state.bank)
            if run.a.free_run:
                if event_state.read:
                    if event_state.rt != 31:
                        event_state.ctx.regs[event_state.rt] = event_state.current_value
                elif event_state.value != event_state.current_value:
                    run.u.exec('dsb ishst')
                    run.u.msr(event_state.bank, event_state.value)
                    run.u.exec('isb; dsb ishst; tlbi vmalle1is; dsb ish; isb')
                event_state.event['kind'] = 'free-run-translation-control'
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                event_state.ret = run.EXC_RET.HANDLED
            elif not event_state.read and run.shadow_sctlr & 1 and (event_state.value != event_state.current_value):
                for event_state.attempt in range(2):
                    if run.a.allow_live_ttbr and event_state.bank in (run.TTBR0_EL12, run.TTBR1_EL12):
                        event_state.controls = dict(tcr=run.u.mrs(run.TCR_EL12), ttbr0=run.u.mrs(run.TTBR0_EL12), ttbr1=run.u.mrs(run.TTBR1_EL12), mair=run.u.mrs(run.MAIR_EL12))
                        event_state.mode = int(event_state.ctx.spsr) & 15
                        if event_state.mode not in (4, 5):
                            raise ValueError('Unsupported guest mode for live root switch')
                        event_state.sequence = len(run.report.get('live_ttbr_switches', []))

                        def read_switch_page(address):
                            data = run.iface.readmem(address, run.PAGE)
                            run.capture.save_input(f'ttbr-{event_state.sequence}-{address:x}.bin', data)
                            return data
                        event_state.checked = run.validate_root_switch(event_state.controls, 'ttbr0' if event_state.bank == run.TTBR0_EL12 else 'ttbr1', event_state.value, event_state.ctx.elr, event_state.ctx.sp[event_state.mode - 4], run.u.mrs(run.VBAR_EL12), run.base, run.guest_size, read_switch_page, pan=bool(int(event_state.ctx.spsr) & 1 << 22))
                        event_state.switch = dict(previous_controls=event_state.controls, validation=event_state.checked, applied=False)
                        run.report.setdefault('live_ttbr_switches', []).append(event_state.switch)
                        run.u.exec('dsb ishst')
                        run.u.msr(event_state.bank, event_state.value)
                        run.u.exec('isb; dsb ishst; tlbi vmalle1is; dsb ish; isb')
                        if run.u.mrs(event_state.bank) != event_state.value:
                            raise ValueError('Live root readback mismatch')
                        event_state.switch['applied'] = True
                        run.report['monitor_mmu_controls'] = event_state.checked['controls']
                        event_state.event['kind'] = 'validated-live-ttbr-switch'
                        event_state.ctx.spsr.SS = 1
                        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                        event_state.ret = run.EXC_RET.HANDLED
                        break
                    if not event_state.attempt and event_state.bank in (run.TTBR0_EL12, run.TTBR1_EL12) and run.pause_guard('live-translation-control-change', 'allow_live_ttbr', event_state.event):
                        continue
                    run.report['stop_reason'] = 'live-translation-control-change'
                    break
            else:
                if event_state.read and event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = event_state.current_value
                elif not event_state.read and (not run.shadow_sctlr & 1):
                    run.u.msr(event_state.bank, event_state.value)
                event_state.ctx.spsr.SS = 1
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg in (run.CNTVOFF_EL2, run.apple_cntvoff, run.VM_TMR_FIQ_ENA_EL2) and (event_state.read or event_state.value == 0):
            if event_state.read and event_state.rt != 31:
                event_state.ctx.regs[event_state.rt] = 0
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg in (run.APCTL_EL1, run.KERNKEYLO_EL1, run.KERNKEYHI_EL1):
            if event_state.read and event_state.rt != 31:
                event_state.ctx.regs[event_state.rt] = run.u.mrs(run.HV.MSR_REDIRECTS[event_state.reg])
            elif not event_state.read:
                run.u.msr(run.HV.MSR_REDIRECTS[event_state.reg], event_state.value)
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg == run.SPRR_CONFIG_EL1 and (event_state.read or run.a.observe_sprr or run.a.real_guarded or (not run.shadow_sctlr & 1 and event_state.value in (0, 1))):
            if run.a.real_guarded:
                if event_state.read:
                    if event_state.rt != 31:
                        event_state.ctx.regs[event_state.rt] = run.u.mrs(run.SPRR_CONFIG_EL1) if run.real_sprr_on else run.shadow_sprr_config
                    event_state.event['kind'] = 'real-sprr-config'
                elif not run.shadow_sctlr & 1:
                    run.shadow_sprr_config = event_state.value
                    event_state.event['kind'] = 'staged-sprr-config'
                else:
                    event_state.controls = dict(tcr=run.u.mrs(run.TCR_EL12), ttbr0=run.u.mrs(run.TTBR0_EL12), ttbr1=run.u.mrs(run.TTBR1_EL12), mair=run.u.mrs(run.MAIR_EL12))
                    run.u.msr(run.SPRR_CONFIG_EL1, event_state.value)
                    run.shadow_sprr_config = event_state.value
                    run.real_sprr_on = bool(event_state.value & 1) or run.real_sprr_on
                    event_state.enable = run.report.setdefault('sprr_real_enable', dict(enforced=True, events=[]))
                    event_state.enable['events'].append(dict(index=run.trace_count(run.report), value=event_state.value, controls=event_state.controls, enable=bool(event_state.value & 1), lock_config=bool(event_state.value & 2), lock_perm=bool(event_state.value & 16), lock_kernel_perm=bool(event_state.value & 32), unknown_bits=event_state.value & ~51, permissions={run.sysreg_rev.get(r, 'S3_%d_C%d_C%d_%d' % r[1:]): v for r, v in run.permission_shadow.items()}))
                    event_state.event['kind'] = 'real-sprr-config'
            else:
                if event_state.read and event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = run.shadow_sprr_config
                elif not event_state.read:
                    run.shadow_sprr_config = event_state.value
                event_state.event['kind'] = 'staged-sprr-config'
                if not event_state.read and run.shadow_sctlr & 1:
                    event_state.event['kind'] = 'observed-sprr-config'
                    event_state.observation = run.report.setdefault('sprr_observation', dict(enforced=False, events=[]))
                    event_state.observation['events'].append(dict(index=run.trace_count(run.report), value=event_state.value, enable=bool(event_state.value & 1), lock_config=bool(event_state.value & 2), lock_perm=bool(event_state.value & 16), lock_kernel_perm=bool(event_state.value & 32), unknown_bits=event_state.value & ~51, permissions={run.sysreg_rev[r]: v for r, v in run.permission_shadow.items()}))
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg in run.permission_shadow:
            if event_state.read and event_state.rt != 31:
                event_state.ctx.regs[event_state.rt] = run.permission_shadow[event_state.reg]
            elif not event_state.read:
                run.permission_shadow[event_state.reg] = event_state.value
            event_state.event['kind'] = 'staged-sprr-permission'
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg == run.GXF_CONFIG_EL1 and run.a.real_guarded and (event_state.read or event_state.value in (0, 1)):
            if event_state.read:
                if event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = run.u.mrs(run.GXF_CONFIG_EL1) if run.shadow_sctlr & 1 else 0
            elif run.shadow_sctlr & 1:
                run.u.msr(run.GXF_CONFIG_EL1, event_state.value)
            event_state.event['kind'] = 'real-gxf-config'
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg == run.GXF_CONFIG_EL1 and run.a.virtual_gxf and (event_state.read or event_state.value in (0, 1)):
            if event_state.read and event_state.rt != 31:
                event_state.ctx.regs[event_state.rt] = run.gxf_state['config']
            elif not event_state.read:
                run.gxf_state['config'] = event_state.value
                run.gxf_report()['config_events'].append(dict(index=run.trace_count(run.report), value=event_state.value))
            event_state.event['kind'] = 'virtual-gxf-config'
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg in run.apple_shadow or (event_state.reg == run.GXF_STATUS_EL1 and event_state.read):
            if event_state.reg == run.GXF_STATUS_EL1:
                if event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = int(run.gxf_state['guarded'])
                event_state.event['kind'] = 'staged-apple-register'
            elif run.gxf_state['guarded'] and event_state.reg in run.gxf_banks:
                if event_state.read and event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = run.u.mrs(run.gxf_banks[event_state.reg])
                elif not event_state.read:
                    run.u.msr(run.gxf_banks[event_state.reg], event_state.value)
                event_state.event['kind'] = 'guarded-bank-register'
            else:
                if event_state.read and event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = run.apple_shadow.get(event_state.reg, 0)
                elif not event_state.read:
                    run.apple_shadow[event_state.reg] = event_state.value
                    run.report['staged_apple_registers'] = {run.sysreg_rev.get(r, 'S3_%d_C%d_C%d_%d' % r[1:]): v for r, v in run.apple_shadow.items()}
                event_state.event['kind'] = 'staged-apple-register'
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif run.a.stage_el2_config:
            if event_state.read and event_state.rt != 31:
                event_state.ctx.regs[event_state.rt] = run.el2_shadow.get(event_state.reg, 0)
            elif not event_state.read:
                run.el2_shadow[event_state.reg] = event_state.value
                run.report['staged_el2_registers'] = {run.sysreg_rev.get(r, 'S3_%d_C%d_C%d_%d' % r[1:]): v for r, v in run.el2_shadow.items()}
            event_state.event['kind'] = 'staged-el2-register'
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            run.report['stop_reason'] = 'unsupported-el2-register'
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.esr >> 26 == 24):
        event_state.access = run.ESR_ISS_MSR(event_state.esr & 33554431)
        event_state.reg = (event_state.access.Op0, event_state.access.Op1, event_state.access.CRn, event_state.access.CRm, event_state.access.Op2)
        event_state.value = 0 if event_state.access.Rt == 31 else event_state.ctx.regs[event_state.access.Rt]
        event_state.event['sysreg'] = dict(encoding=list(event_state.reg), name=run.sysreg_rev.get(event_state.reg), read=bool(event_state.access.DIR), rt=event_state.access.Rt, value=event_state.value)
        event_state.debug_effect = run.guest_debug.access(event_state.reg, bool(event_state.access.DIR), event_state.value)
        if event_state.debug_effect is not None:
            if event_state.access.DIR and event_state.access.Rt != 31:
                event_state.ctx.regs[event_state.access.Rt] = event_state.debug_effect['value']
            event_state.event['kind'] = event_state.debug_effect['kind']
            event_state.event['sysreg']['value'] = event_state.debug_effect['value']
            run.report['guest_debug'] = run.guest_debug.snapshot()
            if run.guest_debug.oslock is not None:
                run.report['guest_oslock'] = run.guest_debug.oslock
            event_state.ctx.elr += 4
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            run.report['stop_reason'] = 'unsupported-system-register'
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.esr >> 26 == 1) and run.a.free_run:
        if event_state.ctx.elr == run.FC_IDLE_PC:
            run.report['stop_reason'] = 'sptm-panic-halt'
            run.report['sptm_panic_halt'] = dict(pc=hex(event_state.ctx.elr), note='reached the panic wfe halt in free-run; panic args were consumed at 0xf8ca0 -- re-run single-stepped near here for the message', prior_pcs=[hex(e['pc']) for e in run.report.get('trace', [])[-6:] if isinstance(e.get('pc'), int)])
            event_state.event['kind'] = 'panic-halt'
        else:
            event_state.ctx.elr += 4
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.event['kind'] = 'wfx-skip'
            event_state.ret = run.EXC_RET.HANDLED
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.esr >> 26 in (36, 37)) and run.a.on_demand_stage2 and (event_state.esr & 60 == 4):
        event_state.fault_write = bool(event_state.esr >> 6 & 1)
        event_state.ipa = run.p.hv_translate(event_state.ctx.far, True, event_state.fault_write)
        event_state.od = run.report.setdefault('on_demand_stage2', dict(count=0, samples=[], capped=False, stage1_faults=0))
        if not event_state.ipa:
            event_state.od['stage1_faults'] += 1
            run.report['stop_reason'] = 'on-demand-stage1-fault'
            event_state.event['kind'] = 'on-demand-stage1-fault'
            event_state.event['fault_va'] = event_state.ctx.far
        elif event_state.od['count'] >= run.a.on_demand_stage2:
            event_state.od['capped'] = True
            run.report['stop_reason'] = 'on-demand-stage2-exhausted'
            event_state.event['kind'] = 'on-demand-stage2-exhausted'
            event_state.event.update(fault_va=event_state.ctx.far, fault_ipa=event_state.ipa & ~(run.PAGE - 1))
        else:
            event_state.page = event_state.ipa & ~(run.PAGE - 1)
            event_state.host = run.u.memalign(run.PAGE, run.PAGE)
            run.p.memset64(event_state.host, 0, run.PAGE)
            if run.p.hv_map(event_state.page, event_state.host | run.HV.PTE_ATTRIBUTES | run.HV.PTE_VALID, run.PAGE, 1) < 0:
                run.report['stop_reason'] = 'on-demand-map-failed'
                event_state.event['kind'] = 'on-demand-map-failed'
                event_state.event.update(fault_va=event_state.ctx.far, fault_ipa=event_state.page)
            else:
                event_state.od['count'] += 1
                if len(event_state.od['samples']) < 64:
                    event_state.od['samples'].append(dict(va=event_state.ctx.far, ipa=event_state.page, host=event_state.host, write=event_state.fault_write))
                event_state.event['kind'] = 'on-demand-stage2-map'
                event_state.event.update(fault_va=event_state.ctx.far, fault_ipa=event_state.page)
                event_state.ctx.spsr.SS = 1
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                event_state.ret = run.EXC_RET.HANDLED
    else:
        run.report['stop_reason'] = 'unsupported-exception'
        try:
            event_state.ec = event_state.esr >> 26 & 63
            if event_state.ec in (32, 33, 36, 37):
                event_state.hpfar = run.u.mrs((3, 4, 6, 0, 4))
                event_state.ipa = (event_state.hpfar & 1099511627760) << 8
                event_state.event['hpfar_el2'] = event_state.hpfar
                event_state.event['fault_ipa'] = event_state.ipa
                run.report['unsupported_exception_fault'] = dict(ec=event_state.ec, esr=event_state.esr, far=event_state.event.get('far'), hpfar=event_state.hpfar, ipa=event_state.ipa, dfsc=event_state.esr & 63, write=bool(event_state.esr >> 6 & 1))
        except Exception as hpfar_error:
            event_state.event['hpfar_error'] = str(hpfar_error)
