# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Txm trace event handlers extracted from the original probe callback."""


def handle_debug_gate(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.debug_gate = dict(
        pc=hex(event_state.ctx.elr), esr=hex(int(event_state.ctx.esr)),
        spsr=hex(int(event_state.ctx.spsr)), x9=hex(int(event_state.ctx.regs[9])))
    event_state.checks = {
        'exact_pc': event_state.ctx.elr == run.FC_XNU_TXM_HANDLER_CMD1_MDSCR_PC,
        'exact_esr': int(event_state.ctx.esr) == run.FC_XNU_TXM_HANDLER_CMD1_MDSCR_ESR,
        'tdcc_only': int(event_state.ctx.regs[9]) ==
            run.FC_XNU_TXM_HANDLER_CMD1_MDSCR_VALUE,
    }
    try:
        event_state.roots = run.txm_validator_trace_state['roots']
        def read_fast_debug_page(table):
            if (table & (run.PAGE - 1) or
                    not run.base <= table < table + run.PAGE <= run.base + run.guest_size):
                raise ValueError('MDSCR table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)
        event_state.debug_leaf = run.translate(event_state.ctx.elr, event_state.roots['ttbr0'], event_state.roots['ttbr1'],
                               read_fast_debug_page)
        event_state.debug_live = run.iface.readmem(event_state.debug_leaf['pa'], 4)
        event_state.debug_source_offset = event_state.ctx.elr - run.FC_IMAGE_BASE
        event_state.debug_source = run.sources['sptm'][event_state.debug_source_offset:
                                       event_state.debug_source_offset + 4]
        event_state.expected_debug = run.struct.pack(
            '<I', run.FC_XNU_TXM_HANDLER_CMD1_MDSCR_WORD)
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.checks.update(
            source_word=event_state.debug_source == event_state.expected_debug,
            live_word=(event_state.debug_live == event_state.expected_debug and
                       event_state.debug_live == event_state.debug_source),
            level_three=event_state.debug_leaf['level'] == 3,
            access_flag=event_state.debug_leaf['access_flag'],
            filter_running=(event_state.fast_status['active'] and
                event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_RUNNING),
            filter_bounded=(0 < event_state.fast_status['steps'] <=
                run.FC_TXM_COMPLETION_FAST_STEPS),
            filter_last_pc=event_state.fast_status['last_pc'] == event_state.ctx.elr,
            filter_previous_pc=(event_state.fast_status['previous_pc'] ==
                event_state.ctx.elr - 8),
            filter_contract=(event_state.fast_status['terminal_pc'] ==
                run.FC_XNU_TXM_HANDLER_CMD1_RETAB and
                event_state.fast_status['expected_first_pc'] ==
                run.FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR))
        event_state.debug_gate.update(
            source_hex=event_state.debug_source.hex(), live_hex=event_state.debug_live.hex(),
            pa=hex(event_state.debug_leaf['pa']), filter_status=event_state.fast_status)
    except Exception as debug_gate_error:
        event_state.checks['gate_readback'] = False
        event_state.debug_gate['error'] = str(debug_gate_error)
    event_state.debug_gate['checks'] = event_state.checks
    run.report['xnu_txm_sstep_fast_path']['mdscr_tdcc'] = event_state.debug_gate
    if all(event_state.checks.values()):
        event_state.debug_effect = run.guest_debug.access(
            (2, 0, 0, 2, 2), False,
            run.FC_XNU_TXM_HANDLER_CMD1_MDSCR_VALUE)
        event_state.event.update(kind=event_state.debug_effect['kind'], native_handoff=True,
                     firmware_step_filter_rearmed=True,
                     pc=event_state.ctx.elr, esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr),
                     regs=list(event_state.ctx.regs), far=event_state.ctx.far, sp=list(event_state.ctx.sp),
                     sysreg=dict(encoding=[2, 0, 0, 2, 2],
                         name='MDSCR_EL1', read=False, rt=9,
                         value=event_state.debug_effect['value']))
        run.report['guest_debug'] = run.guest_debug.snapshot()
        event_state.ctx.elr += 4
        event_state.ctx.spsr.SS = 1
        run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED
    else:
        run.report['stop_reason'] = 'cmd1-fast-path-mdscr-gate-rejected'


def handle_trace_step(run, event_state):
    event_state.ctx = event_state.native_ctx if run.handoff_state.get('native') else run.iface.readstruct(
        event_state.info, run.ExcInfo)
    run.txm_validator_trace_state['steps'] += 1
    event_state.trace_step = run.txm_validator_trace_state['steps']
    event_state.trace_phase = run.txm_validator_trace_state['phase']
    event_state.in_txm_text = 0xfffffe0017024000 <= event_state.ctx.elr < 0xfffffe0017068000
    event_state.checks = {
        'lower_sync': event_state.reason == run.START.EXCEPTION_LOWER and event_state.code == run.EXC.SYNC,
        'software_step': int(event_state.ctx.esr) >> 26 == 0x32,
        'txm_text_or_return': (event_state.in_txm_text
            or event_state.ctx.elr in (run.txm_validator_trace_state['return_pc'],
                          run.txm_validator_trace_state['response_stop'],
                          run.FC_XNU_TXM_HANDLER_CMD1_RETAB,
                          run.FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN)),
    }
    event_state.record = dict(index=event_state.trace_step, pc=hex(event_state.ctx.elr),
                  sp_el0=hex(int(event_state.ctx.sp[0])), spsr=hex(int(event_state.ctx.spsr)),
                  x0=hex(int(event_state.ctx.regs[0])), x1=hex(int(event_state.ctx.regs[1])),
                  x30=hex(int(event_state.ctx.regs[30])), checks=event_state.checks)
    event_state.probe = run.report[run.txm_validator_trace_state['report_key']]
    event_state.fast_status = None
    event_state.retab_transition = False
    if run.txm_validator_trace_state.get('fast_path_armed'):
        try:
            event_state.fast_status = run.txm_sstep_fast_path.status()
            event_state.expected_terminal = (run.FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN
                if run.txm_validator_trace_state.get('retab_crossed')
                else run.FC_XNU_TXM_HANDLER_CMD1_RETAB)
            event_state.checks['fast_path_forwarded_terminal'] = (
                not event_state.fast_status['active'] and
                event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_TERMINAL and
                event_state.fast_status['last_pc'] == event_state.ctx.elr and
                event_state.ctx.elr == event_state.expected_terminal)
        except Exception as fast_status_error:
            event_state.checks['fast_path_forwarded_terminal'] = False
            event_state.record['fast_path_status_error'] = str(fast_status_error)
        if event_state.fast_status is not None:
            event_state.record['fast_path_status'] = event_state.fast_status
    if (event_state.trace_phase == 'completion' and
            not run.txm_validator_trace_state.get('retab_crossed') and
            event_state.ctx.elr == run.FC_XNU_TXM_HANDLER_CMD1_RETAB and
            event_state.fast_status is not None):
        event_state.retab_checks = {
            'exact_spsr': int(event_state.ctx.spsr) ==
                run.FC_XNU_TXM_HANDLER_CMD1_RETAB_SPSR,
            'authenticated_return_target': (
                int(event_state.ctx.regs[30]) & ((1 << 40) - 1) ==
                run.FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN &
                ((1 << 40) - 1)),
            'prior_filter_terminal': (
                not event_state.fast_status['active'] and
                event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_TERMINAL and
                event_state.fast_status['last_pc'] == event_state.ctx.elr and
                event_state.fast_status['previous_pc'] ==
                    run.FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS and
                0 < event_state.fast_status['steps'] <=
                    run.FC_TXM_COMPLETION_FAST_STEPS and
                event_state.fast_status['terminal_pc'] ==
                    run.FC_XNU_TXM_HANDLER_CMD1_RETAB),
        }
        event_state.retab_gate = dict(pc=hex(event_state.ctx.elr), x30=hex(int(event_state.ctx.regs[30])),
                          spsr=hex(int(event_state.ctx.spsr)),
                          prior_status=event_state.fast_status)
        try:
            event_state.roots = run.txm_validator_trace_state['roots']
            def read_retab_page(table):
                if (table & (run.PAGE - 1) or
                        not run.base <= table < table + run.PAGE <= run.base + run.guest_size):
                    raise ValueError('RETAB table outside owned RAM')
                return run.iface.readmem(table, run.PAGE)
            event_state.retab_leaf = run.translate(event_state.ctx.elr, event_state.roots['ttbr0'], event_state.roots['ttbr1'],
                                   read_retab_page)
            event_state.retab_live = run.iface.readmem(event_state.retab_leaf['pa'], 4)
            event_state.kernel_segment = run.layout['images']['kernelcache'][
                'segments']['__TEXT_EXEC']
            event_state.retab_source_offset = (event_state.kernel_segment['fileoff'] +
                run.FC_XNU_TXM_HANDLER_CMD1_RETAB_LINKED -
                event_state.kernel_segment['va'])
            event_state.retab_source = run.sources['kernelcache'][
                event_state.retab_source_offset:event_state.retab_source_offset + 4]
            event_state.expected_retab = run.struct.pack(
                '<I', run.FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD)
            event_state.retab_checks.update(
                source_word=event_state.retab_source == event_state.expected_retab,
                live_word=(event_state.retab_live == event_state.expected_retab and
                           event_state.retab_live == event_state.retab_source),
                level_three=event_state.retab_leaf['level'] == 3,
                access_flag=event_state.retab_leaf['access_flag'])
            event_state.retab_gate.update(pa=hex(event_state.retab_leaf['pa']),
                              source_hex=event_state.retab_source.hex(),
                              live_hex=event_state.retab_live.hex())
        except Exception as retab_gate_error:
            event_state.retab_checks['gate_readback'] = False
            event_state.retab_gate['error'] = str(retab_gate_error)
        event_state.retab_gate['checks'] = event_state.retab_checks
        event_state.record['retab_gate'] = event_state.retab_gate
        event_state.retab_transition = all(event_state.retab_checks.values())
        event_state.checks['retab_transition'] = event_state.retab_transition
    event_state.record['phase'] = event_state.trace_phase
    event_state.validator_trace = event_state.probe.setdefault('validator_trace', [])
    event_state.validator_trace.append(event_state.record)
    event_state.event.update(kind='txm-handler-' + event_state.trace_phase + '-trace', pc=event_state.ctx.elr,
                 esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs),
                 far=event_state.ctx.far, sp=list(event_state.ctx.sp), checks=event_state.checks,
                 validator_trace_step=event_state.trace_step)
    event_state.returned = (event_state.trace_phase == 'validator'
        and event_state.ctx.elr == run.txm_validator_trace_state['return_pc'])
    if event_state.returned:
        event_state.protected_after = run.iface.readmem(
            run.txm_validator_trace_state['protected_pa'],
            run.txm_validator_trace_state['protected_size'])
        event_state.checks.update(
            expected_return_sp=(int(event_state.ctx.sp[0])
                == run.txm_validator_trace_state['expected_sp']),
            expected_result=(int(event_state.ctx.regs[0]) & 0xffffffff
                == run.txm_validator_trace_state['expected_result']),
            caller_frame_preserved=(event_state.protected_after
                == run.txm_validator_trace_state['protected_before']))
        event_state.record.update(returned=True,
            protected_after_sha256=run.hashlib.sha256(
                event_state.protected_after).hexdigest())
    event_state.validator_complete = event_state.returned and all(event_state.checks.values())
    event_state.continue_to_response = (event_state.validator_complete
        and run.txm_validator_trace_state['boundary'] in (
            'response-trace', 'cmd1-completion-trace'))
    event_state.response_done = (event_state.trace_phase == 'response'
        and event_state.ctx.elr == run.txm_validator_trace_state['response_stop'])
    if event_state.response_done:
        event_state.frame_pa = run.txm_validator_trace_state['metadata_frame_pa']
        event_state.response = run.iface.readmem(event_state.frame_pa, 0x38)
        event_state.marker = run.iface.readmem(
            run.txm_validator_trace_state['protected_pa'] + 0x18, 8)
        event_state.expected_pointer = run.txm_validator_trace_state['response_pointer']
        event_state.checks.update(
            expected_response_sp=(int(event_state.ctx.sp[0])
                == run.txm_validator_trace_state['expected_sp']),
            response_result_zero=(event_state.response[8:16] == b'\x00' * 8),
            response_type_three=(event_state.response[0x18:0x20]
                == run.struct.pack('<Q', 3)),
            response_pointer=(event_state.response[0x20:0x28]
                == run.struct.pack('<Q', event_state.expected_pointer)),
            response_global_four=(event_state.response[0x28:0x30]
                == run.struct.pack('<Q', run.FC_XNU_TXM_HANDLER_GLOBAL + 4)),
            response_global_eight=(event_state.response[0x30:0x38]
                == run.struct.pack('<Q', run.FC_XNU_TXM_HANDLER_GLOBAL + 8)),
            completion_slot_zero=(event_state.marker == b'\x00' * 8))
        event_state.record.update(response_hex=event_state.response.hex(),
                      completion_slot_hex=event_state.marker.hex())
    event_state.response_complete = event_state.response_done and all(event_state.checks.values())
    event_state.continue_to_completion = (event_state.response_complete
        and run.txm_validator_trace_state['boundary']
            == 'cmd1-completion-trace')
    event_state.fast_arm_gate = (event_state.trace_phase == 'completion'
        and getattr(run.a, 'xnu_txm_sstep_fast_path', False)
        and not run.txm_validator_trace_state.get('fast_path_armed')
        and event_state.ctx.elr == run.FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC)
    if event_state.fast_arm_gate:
        try:
            event_state.roots = run.txm_validator_trace_state['roots']
            def read_fast_gate_page(table):
                if (table & (run.PAGE - 1) or
                        not run.base <= table < table + run.PAGE <= run.base + run.guest_size):
                    raise ValueError(
                        'Completion SVC table outside owned RAM')
                return run.iface.readmem(table, run.PAGE)
            event_state.svc_leaf = run.translate(event_state.ctx.elr, event_state.roots['ttbr0'], event_state.roots['ttbr1'],
                                 read_fast_gate_page)
            event_state.svc_live = run.iface.readmem(event_state.svc_leaf['pa'], 4)
            event_state.txm_segment = run.layout['images']['txm']['segments']['__TEXT_EXEC']
            event_state.svc_linked = (run.FC_XNU_TXM_HANDLER_HELPER_LINKED +
                          run.FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC -
                          run.FC_XNU_TXM_HANDLER_HELPER)
            event_state.svc_source_offset = (event_state.txm_segment['fileoff'] + event_state.svc_linked -
                                 event_state.txm_segment['va'])
            event_state.svc_source = run.sources['txm'][event_state.svc_source_offset:
                                        event_state.svc_source_offset + 4]
            event_state.expected_svc = run.struct.pack(
                '<I', run.FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC_WORD)
            event_state.checks.update(
                completion_svc_level_three=event_state.svc_leaf['level'] == 3,
                completion_svc_access_flag=event_state.svc_leaf['access_flag'],
                completion_svc_source=event_state.svc_source == event_state.expected_svc,
                completion_svc_live=(event_state.svc_live == event_state.expected_svc and
                                     event_state.svc_live == event_state.svc_source))
            event_state.record.update(
                completion_svc_linked=hex(event_state.svc_linked),
                completion_svc_pa=hex(event_state.svc_leaf['pa']),
                completion_svc_source_hex=event_state.svc_source.hex(),
                completion_svc_live_hex=event_state.svc_live.hex())
        except Exception as fast_gate_error:
            event_state.checks['completion_svc_gate'] = False
            event_state.record['completion_svc_gate_error'] = str(fast_gate_error)
    event_state.completion_done = (event_state.trace_phase == 'completion'
        and event_state.ctx.elr == run.FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN)
    if event_state.completion_done:
        event_state.retab_record = run.report.get('xnu_txm_sstep_fast_path', {}).get(
            'retab_transition', {})
        event_state.prior_fast_status = event_state.retab_record.get('prior_status')
        event_state.claim_after_completion = run.iface.readmem(
            run.txm_validator_trace_state['metadata_frame_pa'] + 0x58, 1)
        event_state.checks.update(
            xnu_return_pc=(event_state.ctx.elr
                == run.FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN),
            claim_released=(event_state.claim_after_completion == b'\x00'))
        if getattr(run.a, 'xnu_txm_sstep_fast_path', False):
            event_state.checks.update(
                fast_path_terminal=(event_state.fast_status is not None and
                    not event_state.fast_status['active'] and
                    event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_TERMINAL),
                fast_path_bounded=(event_state.fast_status is not None and
                    event_state.prior_fast_status is not None and
                    event_state.fast_status['steps'] == 0 and
                    0 < event_state.prior_fast_status['steps'] <=
                        run.FC_TXM_COMPLETION_FAST_STEPS),
                fast_path_crossed_both_worlds=(
                    event_state.prior_fast_status is not None and
                    event_state.prior_fast_status['range0_hits'] > 0 and
                    event_state.prior_fast_status['range1_hits'] > 0),
                fast_path_contract=(event_state.fast_status is not None and
                    event_state.prior_fast_status is not None and
                    event_state.prior_fast_status['first_pc'] ==
                        run.FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR and
                    event_state.prior_fast_status['expected_first_pc'] ==
                        run.FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR and
                    event_state.prior_fast_status['range0_start'] ==
                        run.FC_TXM_RUNTIME_TEXT[0] and
                    event_state.prior_fast_status['range0_end'] ==
                        run.FC_TXM_RUNTIME_TEXT[1] and
                    event_state.prior_fast_status['range1_start'] ==
                        run.FC_SPTM_RUNTIME_TEXT[0] and
                    event_state.prior_fast_status['range1_end'] ==
                        run.FC_SPTM_RUNTIME_TEXT[1] and
                    event_state.prior_fast_status['terminal_pc'] ==
                        run.FC_XNU_TXM_HANDLER_CMD1_RETAB and
                    event_state.fast_status['first_pc'] == 0 and
                    event_state.fast_status['expected_first_pc'] ==
                        run.FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN and
                    event_state.fast_status['range0_start'] ==
                        run.FC_XNU_RUNTIME_TEXT[0] and
                    event_state.fast_status['range0_end'] ==
                        run.FC_XNU_RUNTIME_TEXT[1] and
                    event_state.fast_status['range1_start'] ==
                        run.FC_SPTM_RUNTIME_TEXT[0] and
                    event_state.fast_status['range1_end'] ==
                        run.FC_SPTM_RUNTIME_TEXT[1] and
                    event_state.fast_status['terminal_pc'] ==
                        run.FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN and
                    event_state.fast_status['max_steps'] ==
                        run.FC_TXM_COMPLETION_FAST_STEPS))
        event_state.record['claim_after_completion_hex'] = (
            event_state.claim_after_completion.hex())
    event_state.complete = (event_state.validator_complete
        if run.txm_validator_trace_state['boundary'] == 'validator-trace'
        else (event_state.completion_done and all(event_state.checks.values())
            if run.txm_validator_trace_state['boundary']
                == 'cmd1-completion-trace'
            else event_state.response_complete))
    event_state.exhausted = event_state.trace_step >= run.txm_validator_trace_state['limit']
    event_state.phase53_continue = (event_state.complete and
        getattr(run.a, 'xnu_phase53_allocation_trace', False))
    if event_state.continue_to_response:
        run.txm_validator_trace_state['phase'] = 'response'
        event_state.probe['validator_result'] = dict(event_state.record)
        event_state.ctx.spsr.SS = 1
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED
    elif event_state.continue_to_completion:
        run.txm_validator_trace_state['phase'] = 'completion'
        event_state.probe['response_result'] = dict(event_state.record)
        event_state.ctx.spsr.SS = 1
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED
    elif event_state.fast_arm_gate and all(event_state.checks.values()):
        try:
            event_state.enabled_status = run.txm_sstep_fast_path.enable(
                run.FC_TXM_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT,
                run.FC_XNU_TXM_HANDLER_CMD1_RETAB,
                run.FC_TXM_COMPLETION_FAST_STEPS,
                run.FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR)
            run.txm_validator_trace_state['fast_path_armed'] = True
            run.report['xnu_txm_sstep_fast_path'].update(
                activated=True, activated_at_pc=hex(event_state.ctx.elr),
                activated_at_trace_step=event_state.trace_step,
                enable_status=event_state.enabled_status,
                activation_record=dict(event_state.record))
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        except Exception as fast_enable_error:
            event_state.checks['fast_path_enable'] = False
            event_state.record['fast_path_enable_error'] = str(fast_enable_error)
            run.report['xnu_txm_sstep_fast_path'][
                'activation_error'] = str(fast_enable_error)
            run.txm_validator_trace_state['active'] = False
            run.report['stop_reason'] = 'xnu-txm-sstep-fast-path-enable-failed'
    elif event_state.retab_transition:
        try:
            event_state.prior_status = dict(event_state.fast_status)
            event_state.enabled_status = run.txm_sstep_fast_path.enable(
                run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT,
                run.FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN,
                run.FC_TXM_COMPLETION_FAST_STEPS,
                run.FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN)
            run.txm_validator_trace_state.update(
                retab_crossed=True,
                fast_path_prior_steps=event_state.prior_status['steps'])
            event_state.transition_record = dict(
                event_state.record, prior_status=event_state.prior_status,
                enable_status=event_state.enabled_status,
                expected_first_pc=hex(
                    run.FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN))
            run.report['xnu_txm_sstep_fast_path'][
                'retab_transition'] = event_state.transition_record
            event_state.event['kind'] = 'cmd1-retab-transition'
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        except Exception as retab_enable_error:
            event_state.record['retab_enable_error'] = str(retab_enable_error)
            run.txm_validator_trace_state['active'] = False
            run.report['stop_reason'] = (
                'cmd1-retab-fast-path-enable-failed')
    elif event_state.phase53_continue:
        event_state.boundary = run.txm_validator_trace_state['boundary']
        event_state.prior_steps = run.txm_validator_trace_state.get(
            'fast_path_prior_steps', 0)
        event_state.cmd1_result = dict(
            event_state.record, boundary=event_state.boundary,
            extension_instructions=(39 + event_state.trace_step + event_state.prior_steps +
                (event_state.fast_status['steps'] if event_state.fast_status is not None else 0)),
            validator_trace_steps=event_state.trace_step,
            validator_returned=True, response_completed=True,
            cmd1_xnu_return=True, complete=True)
        event_state.probe['result'] = event_state.cmd1_result
        event_state.probe['complete'] = True
        run.txm_validator_trace_state['active'] = False
        try:
            event_state.allocation_enable = run.txm_sstep_fast_path.enable(
                run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT,
                run.FC_XNU_PHASE53_ALLOC_CALL,
                run.FC_XNU_PHASE53_FAST_STEPS,
                run.FC_XNU_PHASE53_AFTER_CMD1_FIRST)
            run.phase53_allocation_trace_state.update(
                active=True,
                roots=run.txm_validator_trace_state['roots'],
                range0=run.FC_XNU_RUNTIME_TEXT,
                segment_start=run.FC_XNU_PHASE53_AFTER_CMD1_FIRST,
                stage='allocation-call',
                terminal_pc=run.FC_XNU_PHASE53_ALLOC_CALL,
                world_transitions=[])
            run.report['xnu_phase53_allocation_trace'] = dict(
                requested=True, activated=True,
                from_pc=hex(event_state.ctx.elr),
                expected_first_pc=hex(
                    run.FC_XNU_PHASE53_AFTER_CMD1_FIRST),
                terminal_pc=hex(run.FC_XNU_PHASE53_ALLOC_CALL),
                target_pc=hex(run.FC_XNU_PHASE53_ALLOC_ENTRY),
                current_stage='allocation-call',
                enable_status=event_state.allocation_enable,
                cmd1_result=event_state.cmd1_result)
            run.report['xnu_txm_sstep_fast_path'][
                'allocation_transition'] = dict(
                    prior_status=event_state.fast_status,
                    enable_status=event_state.allocation_enable)
            event_state.event['kind'] = 'phase53-allocation-trace-start'
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            run.report.pop('stop_reason', None)
            event_state.ret = run.EXC_RET.HANDLED
        except Exception as allocation_enable_error:
            run.report['xnu_phase53_allocation_trace'] = dict(
                requested=True, activated=False,
                error=str(allocation_enable_error))
            run.report['stop_reason'] = (
                'phase53-allocation-fast-path-enable-failed')
    elif event_state.complete or event_state.exhausted or not all(event_state.checks.values()):
        run.txm_validator_trace_state['active'] = False
        run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) & ~1)
        event_state.boundary = run.txm_validator_trace_state['boundary']
        event_state.result = dict(event_state.record, boundary=event_state.boundary,
                      extension_instructions=(39 + event_state.trace_step +
                        run.txm_validator_trace_state.get(
                            'fast_path_prior_steps', 0) +
                        (event_state.fast_status['steps']
                         if event_state.fast_status is not None else 0)),
                      validator_trace_steps=event_state.trace_step,
                      validator_returned=(event_state.validator_complete
                        or 'validator_result' in event_state.probe),
                      response_completed=((event_state.response_complete or
                        'response_result' in event_state.probe)
                        if event_state.boundary in ('response-trace',
                            'cmd1-completion-trace') else None),
                      cmd1_xnu_return=(event_state.complete
                        if event_state.boundary == 'cmd1-completion-trace' else None),
                      complete=event_state.complete)
        event_state.probe['result'] = event_state.result
        event_state.probe['complete'] = event_state.complete
        run.report['stop_reason'] = ('txm-handler-' + event_state.boundary + '-complete'
            if event_state.complete else ('txm-handler-' + event_state.boundary + '-limit'
            if event_state.exhausted else 'txm-handler-' + event_state.boundary + '-mismatch'))
    else:
        event_state.ctx.spsr.SS = 1
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED
