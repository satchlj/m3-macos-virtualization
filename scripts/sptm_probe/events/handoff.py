# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Handoff event handlers extracted from the original probe callback."""
from . import txm_entry, txm_entry_setup


def handle_bounded_handoff(run, event_state):
    event_state.ctx = run.iface.readstruct(event_state.info, run.ExcInfo)
    event_state.event.update(kind='handoff-step', pc=event_state.ctx.elr, esr=int(event_state.ctx.esr),
                 spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs), far=event_state.ctx.far, sp=list(event_state.ctx.sp))
    run.handoff_state['events'] += 1
    run.report['handoff']['observed_events'] = run.handoff_state['events']
    run.report['handoff']['last_pc'] = hex(event_state.ctx.elr)
    if event_state.reason == run.START.EXCEPTION_LOWER and event_state.code == run.EXC.SYNC and int(event_state.ctx.esr) >> 26 == 0x32:
        # A step at the entry can be completion of the native GEXIT;
        # it does not prove an instruction in the target image retired.
        if run.handoff_state.get('xnu'):
            event_state.target = int(run.report['handoff']['target_pc'], 0)
            if event_state.ctx.elr == event_state.target:
                run.report['handoff']['entry_reached'] = True
            elif run.report['handoff'].get('entry_reached'):
                run.report['handoff']['instructions_executed'] = True
        else:
            run.report['handoff']['instructions_executed'] = True
        if run.handoff_state['events'] < run.handoff_state.get('budget', run.a.handoff_steps):
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif (run.handoff_state.get('xnu') and run.a.xnu_run
              and run.report['handoff'].get('instructions_executed')):
            event_state.roots = dict(ttbr0=run.u.mrs(run.TTBR0_EL12), ttbr1=run.u.mrs(run.TTBR1_EL12))
            event_state.continuation = run.classify_entry(event_state.ctx.elr, run.layout, run.base, run.guest_size,
                                          event_state.roots, run.iface.readmem, run.sources)
            if event_state.continuation['image'] == 'kernelcache' and event_state.continuation['bytes_match']:
                run.report['handoff']['free_run_from'] = hex(event_state.ctx.elr)
                event_state.fast_shadow_ready = True
                if run.a.xnu_tpidr_gl2_fast_shadow:
                    event_state.initial_value = run.apple_shadow[run.tpidr_gl2_register]
                    try:
                        event_state.enabled_status = run.tpidr_gl2_fast_shadow.enable(
                            run.tpidr_gl2_shadow_tag_base, event_state.initial_value)
                        run.report['xnu_tpidr_gl2_fast_shadow'].update(
                            activated=True,
                            initial_value=event_state.initial_value,
                            initial_value_hex=hex(event_state.initial_value),
                            enable_status=event_state.enabled_status,
                            activated_at_trace_index=run.trace_count(run.report),
                            activated_from_pc=hex(event_state.ctx.elr))
                    except Exception as fast_shadow_error:
                        event_state.fast_shadow_ready = False
                        run.report['xnu_tpidr_gl2_fast_shadow'][
                            'activation_error'] = str(fast_shadow_error)
                        run.report['stop_reason'] = (
                            'xnu-tpidr-gl2-fast-shadow-enable-failed')
                if event_state.fast_shadow_ready:
                    # This transition is deliberately after the accelerator's
                    # strict enable readback. A missing/malformed proxy API can
                    # therefore never release XNU into native execution.
                    run.handoff_state.update(active=False, native=True)
                    event_state.ctx.spsr.SS = 0
                    run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) & ~1)
                    run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                    event_state.ret = run.EXC_RET.HANDLED
            else:
                run.report['stop_reason'] = 'xnu-native-unverified'
        else:
            run.report['stop_reason'] = 'handoff-instruction-budget'
    else:
        run.report['stop_reason'] = 'handoff-exception'


def handle_guarded_exit(run, event_state):
    run.report['eret_trap'] = dict(pc=hex(event_state.ctx.elr), spsr=hex(int(event_state.ctx.spsr)),
                                      x3=hex(event_state.ctx.regs[3]), phase='before-bank-read')
    run.save()
    # The first boot eret targets TXM. Resolve actual guest mappings;
    # a numeric VA range or a nonzero bank does not identify XNU.
    event_state.elr_gl1 = event_state.spsr_gl1 = 0
    try:
        event_state.rg = run.sysreg_fwd['ELR_GL1']; event_state.rs = run.sysreg_fwd['SPSR_GL1']
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
        event_state.classification = dict(status='classified', decision='rejected',
            trap_pc=hex(event_state.ctx.elr), target_pc=hex(event_state.elr_gl1),
            target_spsr=hex(event_state.spsr_gl1),
            translation_roots={name: hex(value) for name, value in event_state.roots.items()})
        try:
            event_state.handoff = run.classify_entry(event_state.elr_gl1, run.layout, run.base, run.guest_size,
                                     event_state.roots, run.iface.readmem, run.sources)
            event_state.classification.update(event_state.handoff)
            event_state.classification_ok = True
        except Exception as classification_error:
            event_state.classification.update(status='error', error=str(classification_error))
            run.report.setdefault('eret_classifications', []).append(event_state.classification)
            run.report['stop_reason'] = 'eret-classification-error'
            event_state.classification_ok = False
            event_state.handoff = dict(image=None, segment=None, entry_matches=False,
                bytes_match=False, linked_pc=None, bytes_hex='',
                target_pc=hex(event_state.elr_gl1), instructions_executed=False)
        if event_state.classification_ok:
            run.report.setdefault('eret_classifications', []).append(event_state.classification)
        event_state.eret_record = dict(event_state.handoff, spsr=hex(event_state.spsr_gl1), via='ERET_HVC guarded banks')
        event_state.completion_fast_status = None
        event_state.completion_guarded_esr = None
        event_state.completion_guarded_aspsr = None
        if (event_state.classification_ok and
                run.txm_validator_trace_state.get('active') and
                run.txm_validator_trace_state.get('phase') == 'completion' and
                run.txm_validator_trace_state.get('fast_path_armed') and
                getattr(run.a, 'xnu_txm_sstep_fast_path', False)):
            try:
                event_state.completion_fast_status = run.txm_sstep_fast_path.status()
                event_state.completion_guarded_esr = int(run.u.mrs(
                    run.HV.MSR_REDIRECTS[run.ESR_GL1]))
                event_state.completion_guarded_aspsr = int(run.u.mrs(
                    run.HV.MSR_REDIRECTS[run.ASPSR_GL1]))
                event_state.classification.update(
                    completion_fast_status=event_state.completion_fast_status,
                    guarded_esr=hex(event_state.completion_guarded_esr),
                    guarded_aspsr=hex(event_state.completion_guarded_aspsr))
            except Exception as completion_gate_error:
                event_state.classification['completion_gate_error'] = str(
                    completion_gate_error)
        event_state.completion_eret = (event_state.classification_ok and
            event_state.completion_fast_status is not None and
            event_state.ctx.elr == run.FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET and
            event_state.elr_gl1 == run.FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC + 4 and
            event_state.spsr_gl1 == 0x800013c0 and
            event_state.completion_guarded_esr ==
                run.FC_XNU_TXM_HANDLER_CMD1_GUARDED_ESR and
            event_state.completion_guarded_aspsr ==
                run.FC_XNU_TXM_HANDLER_CMD1_GUARDED_ASPSR and
            event_state.handoff['image'] == 'txm' and
            event_state.handoff['segment'] == '__TEXT_EXEC' and
            event_state.handoff['linked_pc'] ==
                hex(run.FC_XNU_TXM_HANDLER_CMD1_RETURN_LINKED) and
            event_state.handoff['bytes_match'] and
            bytes.fromhex(event_state.handoff['bytes_hex']).startswith(
                run.FC_XNU_TXM_HANDLER_CMD1_RETURN_BYTES) and
            event_state.completion_fast_status['active'] and
            event_state.completion_fast_status['status'] ==
                run.FC_VEL2_STEP_FILTER_RUNNING and
            0 < event_state.completion_fast_status['steps'] <=
                run.FC_TXM_COMPLETION_FAST_STEPS and
            event_state.completion_fast_status['first_pc'] ==
                run.FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR and
            event_state.completion_fast_status['last_pc'] == event_state.ctx.elr - 8 and
            event_state.completion_fast_status['range0_hits'] == 0 and
            event_state.completion_fast_status['range1_hits'] ==
                event_state.completion_fast_status['steps'] and
            event_state.completion_fast_status['terminal_pc'] ==
                run.FC_XNU_TXM_HANDLER_CMD1_RETAB and
            event_state.completion_fast_status['expected_first_pc'] ==
                run.FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR)
        event_state.entry_launch = (event_state.classification_ok and event_state.handoff['entry_matches'] and event_state.handoff['bytes_match']
            and event_state.spsr_gl1 == 0x13c0
            and event_state.handoff['image'] in ('txm', 'kernelcache'))
        event_state.txm_return = (event_state.classification_ok and run.a.native_handoff and event_state.handoff['image'] == 'txm'
            and (event_state.entry_launch or (event_state.handoff['segment'] in ('__TEXT_EXEC', '__TEXT_BOOT_EXEC')
                and run.report.get('handoff', {}).get('image') == 'txm'
                and event_state.ctx.elr == 0xfffffe00070a4edc
                and event_state.handoff['linked_pc'] in run.TXM_WORLD_RETURN_LINKED
                and len(run.report.get('txm_world_returns', [])) < 128
                and sum(previous['linked_pc'] == event_state.handoff['linked_pc']
                    for previous in run.report.get('txm_world_returns', [])) < 64
                and event_state.handoff['bytes_match'] and event_state.handoff['bytes_hex'].startswith('ff0f5fd6')
                and 0 <= event_state.spsr_gl1 < 1 << 32
                and event_state.spsr_gl1 & ~0xf0000000 == 0x13c0)))
        event_state.phase53_eret_candidate = bool(
            run.phase53_allocation_trace_state.get('active') or
            run.phase53_retype_survey_state.get('active'))
        event_state.phase53_eret = False
        if event_state.phase53_eret_candidate:
            event_state.phase53_filter_state = (
                run.phase53_retype_survey_state
                if run.phase53_retype_survey_state.get('active')
                else run.phase53_allocation_trace_state)
            event_state.phase53_report_key = (
                'xnu_phase53_retype_survey'
                if run.phase53_retype_survey_state.get('active')
                else 'xnu_phase53_allocation_trace')
            event_state.transition = dict(
                trap_pc=hex(event_state.ctx.elr), target_pc=hex(event_state.elr_gl1),
                target_spsr=hex(event_state.spsr_gl1),
                target_image=event_state.handoff.get('image'),
                target_segment=event_state.handoff.get('segment'))
            event_state.target_range = ({
                'txm': run.FC_TXM_RUNTIME_TEXT,
                'kernelcache': run.FC_XNU_RUNTIME_TEXT,
            }.get(event_state.handoff.get('image')) if event_state.classification_ok
                else None)
            event_state.source_offset = event_state.ctx.elr - 4 - run.FC_IMAGE_BASE
            event_state.source_eret = (run.sources.get('sptm', b'')[
                event_state.source_offset:event_state.source_offset + 4]
                if 0 <= event_state.source_offset <=
                    len(run.sources.get('sptm', b'')) - 4 else b'')
            event_state.transition_checks = {
                'classified': event_state.classification_ok,
                'trap_in_sptm_text':
                    run.FC_SPTM_RUNTIME_TEXT[0] <= event_state.ctx.elr <
                        run.FC_SPTM_RUNTIME_TEXT[1],
                'source_eret': event_state.source_eret == run.struct.pack(
                    '<I', run.FC_XNU_TXM_CONTEXT_ERET_WORD),
                'target_world': event_state.target_range is not None,
                'target_segment': event_state.handoff.get('segment') in
                    ('__TEXT_EXEC', '__TEXT_BOOT_EXEC'),
                'target_source_match':
                    event_state.handoff.get('bytes_match') is True,
                'target_pc_in_range': (event_state.target_range is not None and
                    event_state.target_range[0] <= event_state.elr_gl1 < event_state.target_range[1]),
                'target_mode': (event_state.spsr_gl1 & 15) in (0, 4, 5),
            }
            try:
                event_state.prior_status = run.txm_sstep_fast_path.status()
                event_state.current_range = event_state.phase53_filter_state['range0']
                event_state.segment_start = event_state.phase53_filter_state[
                    'segment_start']
                event_state.survey_aggregate = (
                    event_state.phase53_filter_state.get(
                        'aggregate_steps', 0) +
                    event_state.prior_status['steps'])
                event_state.transition_checks.update(
                    filter_running=(event_state.prior_status['active'] and
                        event_state.prior_status['status'] ==
                            run.FC_VEL2_STEP_FILTER_RUNNING),
                    filter_bounded=(0 < event_state.prior_status['steps'] <=
                        run.FC_XNU_PHASE53_FAST_STEPS),
                    filter_last_pc=
                        event_state.prior_status['last_pc'] == event_state.ctx.elr - 4,
                    filter_segment=(
                        event_state.prior_status['first_pc'] == event_state.segment_start and
                        event_state.prior_status['expected_first_pc'] ==
                            event_state.segment_start and
                        event_state.prior_status['range0_hits'] +
                            event_state.prior_status['range1_hits'] ==
                            event_state.prior_status['steps']),
                    filter_contract=(
                        event_state.prior_status['range0_start'] ==
                            event_state.current_range[0] and
                        event_state.prior_status['range0_end'] ==
                            event_state.current_range[1] and
                        event_state.prior_status['range1_start'] ==
                            run.FC_SPTM_RUNTIME_TEXT[0] and
                        event_state.prior_status['range1_end'] ==
                            run.FC_SPTM_RUNTIME_TEXT[1] and
                        event_state.prior_status['terminal_pc'] ==
                            event_state.phase53_filter_state[
                                'terminal_pc'] and
                        event_state.prior_status['max_steps'] ==
                            run.FC_XNU_PHASE53_FAST_STEPS))
                if run.phase53_retype_survey_state.get('active'):
                    event_state.transition_checks.update(
                        aggregate_budget=(event_state.survey_aggregate <=
                            run.FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS),
                        rearm_budget=(event_state.phase53_filter_state[
                            'rearms'] <
                            run.FC_XNU_PHASE53_RETYPE_SURVEY_MAX_REARMS))
                if all(event_state.transition_checks.values()):
                    event_state.enabled_status = run.txm_sstep_fast_path.enable(
                        event_state.target_range, run.FC_SPTM_RUNTIME_TEXT,
                        event_state.phase53_filter_state[
                            'terminal_pc'],
                        run.FC_XNU_PHASE53_FAST_STEPS, event_state.elr_gl1)
                    event_state.phase53_filter_state['range0'] = event_state.target_range
                    event_state.phase53_filter_state['segment_start'] = event_state.elr_gl1
                    if run.phase53_retype_survey_state.get('active'):
                        event_state.phase53_filter_state['aggregate_steps'] = (
                            event_state.survey_aggregate)
                        event_state.phase53_filter_state['rearms'] += 1
                    event_state.transition.update(
                        source_hex=event_state.source_eret.hex(),
                        prior_status=event_state.prior_status,
                        enable_status=event_state.enabled_status,
                        checks=event_state.transition_checks,
                        complete=True)
                    event_state.phase53_filter_state[
                        'world_transitions'].append(event_state.transition)
                    run.report[event_state.phase53_report_key][
                        'world_transitions'] = list(
                            event_state.phase53_filter_state[
                                'world_transitions'])
                    if run.phase53_retype_survey_state.get('active'):
                        run.report[event_state.phase53_report_key].update(
                            aggregate_steps=event_state.survey_aggregate,
                            rearms=event_state.phase53_filter_state['rearms'])
                    event_state.phase53_eret = True
                else:
                    event_state.transition.update(
                        source_hex=event_state.source_eret.hex(),
                        prior_status=event_state.prior_status,
                        checks=event_state.transition_checks,
                        complete=False)
            except Exception as transition_error:
                event_state.transition_checks['filter_readback'] = False
                event_state.transition.update(
                    source_hex=event_state.source_eret.hex(),
                    checks=event_state.transition_checks,
                    error=str(transition_error), complete=False)
            if not event_state.phase53_eret:
                event_state.phase53_filter_state['active'] = False
                run.report[event_state.phase53_report_key][
                    'world_transition_rejection'] = event_state.transition
                run.report['stop_reason'] = (
                    'phase53-world-transition-gate-rejected')
        event_state.txm_context_step = False
        if (event_state.classification_ok and (run.a.xnu_txm_context_entry_one_step
                or run.a.xnu_txm_context_entry_register_prefix
                or run.a.xnu_txm_context_stack_claim_one_step
                or run.a.xnu_txm_context_stack_metadata_init
                or run.a.xnu_txm_context_x18_branch_one_step
                or run.a.xnu_txm_context_outbound_branch_one_step
                or run.a.xnu_txm_handler_boundary is not None)
                and event_state.ctx.elr == run.FC_XNU_TXM_CONTEXT_ERET_PC
                and not event_state.entry_launch and not event_state.txm_return
                and not event_state.phase53_eret_candidate):
            txm_entry.validate_context_entry(run, event_state)
        if event_state.completion_eret:
            event_state.classification['decision'] = 'cmd1-completion-eret'
            run.report['xnu_txm_sstep_fast_path'][
                'completion_eret'] = dict(
                    trap_pc=hex(event_state.ctx.elr), target_pc=hex(event_state.elr_gl1),
                    target_spsr=hex(event_state.spsr_gl1),
                    guarded_esr=hex(event_state.completion_guarded_esr),
                    guarded_aspsr=hex(event_state.completion_guarded_aspsr),
                    status=event_state.completion_fast_status,
                    checks_passed=True)
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
            txm_entry_setup.prepare_context_entry(run, event_state)
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
            if (run.a.handoff_steps and event_state.entry_launch) or event_state.resume_txm:
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
