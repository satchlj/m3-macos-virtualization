# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Callback lifecycle and ordered dispatch, shared by live code and host replay.

Run bindings live for one probe run. EventState lives for one callback, retaining
intermediate values across handler boundaries without making them persistent.
The exception handling and finalization order match the original callback.
"""
from types import SimpleNamespace
from .events import allocation, exceptions, handoff, native_platform, retype, txm_step, txm_trace, descriptor

class RunBindings:
    """Shared run dependencies and mutable state; replay may replace bindings.

    Keep the mapping by identity: the replay harness exposes this same mapping
    to its synthetic fixtures. No source code is evaluated by this class.
    """

    def __init__(self, bindings):
        self.__dict__ = bindings

def stopped(run, reason, code, info):
    event_state = SimpleNamespace(reason=reason, code=code, info=info)
    event_state.ret = run.EXC_RET.EXIT_GUEST
    event_state.event = dict(reason=int(event_state.reason), code=int(event_state.code))
    try:
        event_state.native_sptm_callback = False
        event_state.native_xnu_agt_callback = False
        event_state.native_xnu_cntp_ctl_callback = False
        event_state.native_xnu_apple_timer_callback = False
        event_state.native_xnu_pperm_site = None
        event_state.native_dockchannel_site = None
        event_state.native_panic_carveout = False
        event_state.native_socd_trace = False
        if run.handoff_state.get('native'):
            event_state.native_ctx = run.iface.readstruct(event_state.info, run.ExcInfo)
            if run.dockchannel_mmio is not None and run.report.get('handoff', {}).get('target_pc'):
                event_state.native_dockchannel_site = run.match_xnu_dockchannel_uart(event_state.native_ctx, int(run.report['handoff']['target_pc'], 0), run.dockchannel_mmio)
            if run.panic_carveout is not None and run.report.get('handoff', {}).get('target_pc'):
                event_state.native_panic_carveout = run.match_xnu_panic_carveout(event_state.native_ctx, int(run.report['handoff']['target_pc'], 0))
            if run.socd_trace is not None and run.report.get('handoff', {}).get('target_pc'):
                event_state.native_socd_trace = run.match_xnu_socd_trace(event_state.native_ctx, int(run.report['handoff']['target_pc'], 0))
            if event_state.reason == run.START.EXCEPTION_LOWER and event_state.code == run.EXC.SYNC and (int(event_state.native_ctx.esr) >> 26 == 22):
                event_state.segment = run.layout.get('images', {}).get('sptm', {}).get('segments', {}).get('__TEXT_EXEC', {})
                event_state.off = event_state.native_ctx.elr - 4 - run.FC_IMAGE_BASE
                event_state.lo = event_state.segment.get('fileoff', 0)
                event_state.hi = event_state.lo + event_state.segment.get('filesize', 0)
                event_state.original_word = run.sources.get('sptm', b'')[event_state.off:event_state.off + 4] if event_state.lo <= event_state.off < event_state.hi else b''
                event_state.expected = run.struct.pack('<I', 3556769794 | (int(event_state.native_ctx.esr) & 65535) << 5)
                if len(event_state.original_word) == 4 and run.patch_probe_code(event_state.original_word) == event_state.expected:
                    event_state.native_sptm_callback = True
                    run.report['xnu_sptm_callbacks'] = run.report.get('xnu_sptm_callbacks', 0) + 1
                if run.a.xnu_pperm_guest_window:
                    event_state.tag = int(event_state.native_ctx.esr) & 65535
                    for event_state.index, event_state.site in enumerate(run.FC_XNU_PPERM_SITES):
                        event_state.pc, event_state.word, event_state.expected_tag, event_state.operation = event_state.site
                        event_state.runtime_pc = int(run.report['handoff']['target_pc'], 0) + event_state.pc - run.FC_XNU_ENTRY_LINKED
                        event_state.kseg = run.layout.get('images', {}).get('kernelcache', {}).get('segments', {}).get('__TEXT_EXEC', {})
                        event_state.source_off = event_state.kseg.get('fileoff', 0) + event_state.pc - event_state.kseg.get('va', 0)
                        event_state.source_original = run.sources.get('kernelcache', b'')[event_state.source_off:event_state.source_off + 4]
                        if event_state.tag == event_state.expected_tag and event_state.native_ctx.elr - 4 == event_state.runtime_pc and (event_state.source_original == run.struct.pack('<I', event_state.word)):
                            event_state.native_xnu_pperm_site = (event_state.index, event_state.site)
                            event_state.native_sptm_callback = False
                            break
            if event_state.reason == run.START.EXCEPTION_LOWER and event_state.code == run.EXC.SYNC and (int(event_state.native_ctx.esr) == run.FC_XNU_AGT_ESR):
                event_state.segment = run.layout.get('images', {}).get('kernelcache', {}).get('segments', {}).get('__TEXT_EXEC', {})
                event_state.within_segment = event_state.segment.get('va', 0) <= run.FC_XNU_AGT_LINKED and run.FC_XNU_AGT_LINKED + 4 <= event_state.segment.get('va', 0) + event_state.segment.get('filesize', 0)
                event_state.source_off = event_state.segment.get('fileoff', 0) + run.FC_XNU_AGT_LINKED - event_state.segment.get('va', 0)
                event_state.original_word = run.sources.get('kernelcache', b'')[event_state.source_off:event_state.source_off + 4] if event_state.within_segment else b''
                event_state.runtime_pc = int(run.report.get('handoff', {}).get('target_pc', '0'), 0) + run.FC_XNU_AGT_LINKED - run.FC_XNU_ENTRY_LINKED
                event_state.native_xnu_agt_callback = event_state.native_ctx.elr - 4 == event_state.runtime_pc and event_state.original_word == run.struct.pack('<I', run.FC_XNU_AGT_WORD)
            if event_state.reason == run.START.EXCEPTION_LOWER and event_state.code == run.EXC.SYNC and (int(event_state.native_ctx.esr) == run.FC_XNU_CNTP_CTL_ESR):
                event_state.segment = run.layout.get('images', {}).get('kernelcache', {}).get('segments', {}).get('__TEXT_EXEC', {})
                event_state.within_segment = event_state.segment.get('va', 0) <= run.FC_XNU_CNTP_CTL_LINKED and run.FC_XNU_CNTP_CTL_LINKED + 4 <= event_state.segment.get('va', 0) + event_state.segment.get('filesize', 0)
                event_state.source_off = event_state.segment.get('fileoff', 0) + run.FC_XNU_CNTP_CTL_LINKED - event_state.segment.get('va', 0)
                event_state.original_word = run.sources.get('kernelcache', b'')[event_state.source_off:event_state.source_off + 4] if event_state.within_segment else b''
                event_state.runtime_pc = int(run.report.get('handoff', {}).get('target_pc', '0'), 0) + run.FC_XNU_CNTP_CTL_LINKED - run.FC_XNU_ENTRY_LINKED
                event_state.native_xnu_cntp_ctl_callback = event_state.native_ctx.elr == event_state.runtime_pc and event_state.original_word == run.struct.pack('<I', run.FC_XNU_CNTP_CTL_WORD)
            if run.a.xnu_apple_physical_timer_hypothesis and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr) == run.FC_XNU_APPLE_PHYS_TIMER_ESR):
                event_state.segment = run.layout.get('images', {}).get('kernelcache', {}).get('segments', {}).get('__TEXT_EXEC', {})
                event_state.within_segment = event_state.segment.get('va', 0) <= run.FC_XNU_APPLE_PHYS_TIMER_LINKED and run.FC_XNU_APPLE_PHYS_TIMER_LINKED + 4 <= event_state.segment.get('va', 0) + event_state.segment.get('filesize', 0)
                event_state.source_off = event_state.segment.get('fileoff', 0) + run.FC_XNU_APPLE_PHYS_TIMER_LINKED - event_state.segment.get('va', 0)
                event_state.original_word = run.sources.get('kernelcache', b'')[event_state.source_off:event_state.source_off + 4] if event_state.within_segment else b''
                event_state.runtime_pc = int(run.report.get('handoff', {}).get('target_pc', '0'), 0) + run.FC_XNU_APPLE_PHYS_TIMER_LINKED - run.FC_XNU_ENTRY_LINKED
                event_state.native_xnu_apple_timer_callback = event_state.native_ctx.elr == event_state.runtime_pc and event_state.original_word == run.struct.pack('<I', run.FC_XNU_APPLE_PHYS_TIMER_WORD)
        if run.batch is not None:
            try:
                run.batch.drain(run.report)
            except Exception:
                run.report['trace_incomplete'] = True
                raise
        if run.watchdog is not None and run.watchdog.expired:
            event_state.ctx = run.iface.readstruct(event_state.info, run.ExcInfo)
            event_state.event.update(kind='hang-budget', pc=event_state.ctx.elr, spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs))
            run.report['stop_reason'] = 'hang'
        elif (run.phase53_allocation_trace_state.get('active') or run.phase53_descriptor_bind_state.get('active') or run.phase53_retype_survey_state.get('active')) and run.handoff_state.get('native') and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr) >> 26 == 50) and (event_state.native_ctx.elr == run.FC_XNU_TXM_HANDLER_CMD1_RETAB):
            allocation.handle_authenticated_return(run, event_state)
        elif run.phase53_descriptor_bind_state.get('active') and run.phase53_descriptor_bind_state.get('stage') == 'leaf-map-call' and run.handoff_state.get('native') and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr) >> 26 == 50) and (int(event_state.native_ctx.spsr) & 15 == 4) and (int(event_state.native_ctx.sp[0]) + 144 != run.phase53_descriptor_bind_state.get('parent_sp')):
            descriptor.handle_leaf_rearm(run, event_state)
        elif run.phase53_descriptor_bind_state.get('active') and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr if run.handoff_state.get('native') else run.iface.readstruct(event_state.info, run.ExcInfo).esr) >> 26 == 50):
            descriptor.handle_step(run, event_state)
        elif run.phase53_retype_survey_state.get('active') and run.phase53_retype_survey_state.get('stage') == 'seek-entry' and (run.phase53_retype_survey_state.get('completed_calls', 0) > 0) and (run.phase53_retype_survey_state.get('range0') == run.FC_TXM_RUNTIME_TEXT) and run.handoff_state.get('native') and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr) >> 26 == 50) and (run.FC_XNU_RUNTIME_TEXT[0] <= event_state.native_ctx.elr < run.FC_XNU_RUNTIME_TEXT[1]):
            retype.handle_unrelated_return(run, event_state)
        elif run.phase53_retype_survey_state.get('active') and run.handoff_state.get('native') and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr) >> 26 == 50) and (event_state.native_ctx.elr == run.FC_XNU_PHASE53_GENTER_RETURN) and (run.phase53_retype_survey_state.get('stage') == 'seek-genter-return'):
            retype.handle_guarded_return(run, event_state)
        elif run.phase53_allocation_trace_state.get('active') and run.handoff_state.get('native') and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr) >> 26 == 50) and (event_state.native_ctx.elr == run.FC_XNU_PHASE53_GENTER_RETURN):
            allocation.handle_guarded_return(run, event_state)
        elif run.phase53_retype_survey_state.get('active') and run.phase53_retype_survey_state.get('stage') == 'seek-entry' and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr if run.handoff_state.get('native') else run.iface.readstruct(event_state.info, run.ExcInfo).esr) >> 26 == 50) and (int(event_state.native_ctx.elr if run.handoff_state.get('native') else run.iface.readstruct(event_state.info, run.ExcInfo).elr) != run.FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY):
            retype.handle_bounded_step_limit(run, event_state)
        elif run.phase53_retype_survey_state.get('active') and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr if run.handoff_state.get('native') else run.iface.readstruct(event_state.info, run.ExcInfo).esr) >> 26 == 50):
            retype.handle_survey_step(run, event_state)
        elif run.phase53_allocation_trace_state.get('active') and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr if run.handoff_state.get('native') else run.iface.readstruct(event_state.info, run.ExcInfo).esr) >> 26 == 50):
            allocation.handle_allocation_step(run, event_state)
        elif run.txm_validator_trace_state.get('active') and run.txm_validator_trace_state.get('phase') == 'completion' and run.txm_validator_trace_state.get('fast_path_armed') and run.handoff_state.get('native') and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr) == run.FC_XNU_TXM_HANDLER_CMD1_MDSCR_ESR) and (event_state.native_ctx.elr == run.FC_XNU_TXM_HANDLER_CMD1_MDSCR_PC):
            txm_trace.handle_debug_gate(run, event_state)
        elif run.txm_validator_trace_state['active'] and (not event_state.native_sptm_callback) and (not run.handoff_state.get('native') or int(event_state.native_ctx.esr) >> 26 == 50):
            txm_trace.handle_trace_step(run, event_state)
        elif run.txm_context_step_state['active']:
            txm_step.handle_context_step(run, event_state)
        elif run.handoff_state.get('native') and event_state.native_xnu_pperm_site is not None:
            native_platform.handle_permission_window(run, event_state)
        elif run.handoff_state.get('native') and event_state.native_xnu_agt_callback:
            native_platform.handle_timer_redirect(run, event_state)
        elif run.handoff_state.get('native') and event_state.native_xnu_apple_timer_callback:
            native_platform.handle_apple_timer(run, event_state)
        elif run.handoff_state.get('native') and event_state.native_xnu_cntp_ctl_callback:
            native_platform.handle_physical_timer(run, event_state)
        elif run.handoff_state.get('native') and event_state.native_dockchannel_site is not None and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC):
            native_platform.handle_console(run, event_state)
        elif run.handoff_state.get('native') and event_state.native_panic_carveout and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC):
            native_platform.handle_panic_buffer(run, event_state)
        elif run.handoff_state.get('native') and event_state.native_socd_trace and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC):
            native_platform.handle_trace_buffer(run, event_state)
        elif run.handoff_state.get('native') and (not event_state.native_sptm_callback) and (event_state.reason == run.START.EXCEPTION_LOWER) and (event_state.code == run.EXC.SYNC) and (int(event_state.native_ctx.esr) >> 26 == 24):
            native_platform.handle_debug_access(run, event_state)
        elif run.handoff_state.get('native') and (not event_state.native_sptm_callback):
            event_state.ctx = event_state.native_ctx
            event_state.event.update(kind='xnu-native-exception', pc=event_state.ctx.elr, esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs), far=event_state.ctx.far, sp=list(event_state.ctx.sp))
            run.report['stop_reason'] = 'xnu-native-exception'
            run.report['handoff']['last_pc'] = hex(event_state.ctx.elr)
        elif run.handoff_state['active']:
            handoff.handle_bounded_handoff(run, event_state)
        elif run.trace_count(run.report) >= run.a.steps:
            run.report['stop_reason'] = 'instruction-budget'
        elif event_state.reason in (run.START.EXCEPTION, run.START.EXCEPTION_LOWER) and event_state.code != run.EXC.SYNC:
            run.report['stop_reason'] = 'asynchronous-exception'
        elif event_state.reason in (run.START.EXCEPTION, run.START.EXCEPTION_LOWER):
            exceptions.handle_exception(run, event_state)
        else:
            run.report['stop_reason'] = 'hypervisor-event'
    except run.UnsupportedGuestDebug as error:
        event_state.event['unsupported_detail'] = str(error)
        run.report['stop_reason'] = 'unsupported-guest-debug-control'
        event_state.ret = run.EXC_RET.EXIT_GUEST
    except run.PpermWindowLimit:
        run.report['stop_reason'] = 'xnu-pperm-window-limit'
        event_state.ret = run.EXC_RET.EXIT_GUEST
    except Exception as error:
        run.report['error'] = str(error)
        run.report['stop_reason'] = 'probe-validation-error'
        event_state.ret = run.EXC_RET.EXIT_GUEST
    finally:
        run.append_event(run.report, event_state.event)
        if event_state.ret == run.EXC_RET.HANDLED and run.trace_count(run.report) > run.a.steps:
            event_state.ret = run.EXC_RET.EXIT_GUEST
            run.report['stop_reason'] = 'instruction-budget'
        if event_state.ret == run.EXC_RET.HANDLED and 'sptm_panic' not in run.report:
            for event_state._pi, event_state._ev in enumerate(run.report.get('trace', [])):
                if event_state._ev.get('pc') == run.FC_PANIC and isinstance(event_state._ev.get('regs'), list) and (len(event_state._ev['regs']) >= 31):
                    event_state._r = event_state._ev['regs']
                    run.report['sptm_panic'] = dict(pc=run.FC_PANIC, args=list(event_state._r[:6]), lr=event_state._r[30], prior_pcs=[e.get('pc') for e in run.report['trace'][max(0, event_state._pi - 16):event_state._pi]])
                    run.report['stop_reason'] = 'sptm-panic'
                    event_state.ret = run.EXC_RET.EXIT_GUEST
                    break
        if event_state.ret == run.EXC_RET.HANDLED and run.vector_stop is not None:
            try:
                event_state.hit = run.vector_stop.observe(run.report['trace'], start_index=run.report.get('trace_start_index', 0), vbar=run.u.mrs(run.VBAR_EL12))
                if event_state.hit is not None:
                    event_state.ret = run.EXC_RET.EXIT_GUEST
                    run.report['stop_reason'] = 'guest-vector-range-entry'
                    run.report['guest_vector_stop'] = event_state.hit
                    try:
                        run.report['guest_vector_stop'] = run.vector_stop.snapshot_cause({name: run.u.mrs(reg) for name, reg in run.exception_registers.items()})
                    except Exception as error:
                        run.report['guest_vector_stop_error'] = str(error)
            except Exception as error:
                event_state.ret = run.EXC_RET.EXIT_GUEST
                run.report['error'] = str(error)
                run.report['stop_reason'] = 'vector-stop-error'
        if event_state.ret == run.EXC_RET.HANDLED and run.guarded_vector_stop is not None:
            try:
                if not run.guarded_vbar:
                    event_state.last = run.report['trace'][-1] if run.report.get('trace') else None
                    if event_state.last and isinstance(event_state.last.get('spsr'), int) and event_state.last['spsr'] & 4194304:
                        event_state.reg = run.sysreg_fwd['VBAR_GL1']
                        if event_state.reg in run.HV.MSR_REDIRECTS:
                            run.guarded_vbar = int(run.u.mrs(run.HV.MSR_REDIRECTS[event_state.reg])) or 0
                event_state.hit = run.guarded_vector_stop.observe(run.report['trace'], start_index=run.report.get('trace_start_index', 0), vbar=run.guarded_vbar)
                if event_state.hit is not None:
                    event_state.ret = run.EXC_RET.EXIT_GUEST
                    run.report['stop_reason'] = 'guarded-vector-entry'
                    event_state.bank = {}
                    for event_state.name in ('VBAR_GL1', 'ESR_GL1', 'ELR_GL1', 'SPSR_GL1', 'ASPSR_GL1', 'GXF_ENTRY_EL1', 'GXF_PABENTRY_EL1'):
                        try:
                            event_state.reg = run.sysreg_fwd[event_state.name]
                            event_state.bank[event_state.name] = run.u.mrs(run.HV.MSR_REDIRECTS[event_state.reg]) if event_state.reg in run.HV.MSR_REDIRECTS else None
                            if event_state.bank[event_state.name] is None:
                                event_state.bank[event_state.name + '_error'] = 'no MSR_REDIRECTS alias'
                        except Exception as bank_error:
                            event_state.bank[event_state.name + '_error'] = str(bank_error)
                    event_state.hit['guarded_bank'] = event_state.bank
                    run.report['guarded_vector_stop'] = event_state.hit
            except Exception as error:
                event_state.ret = run.EXC_RET.EXIT_GUEST
                run.report['error'] = str(error)
                run.report['stop_reason'] = 'guarded-vector-stop-error'
        if event_state.ret == run.EXC_RET.HANDLED and run.a.first_contact:
            event_state.last = run.report['trace'][-1] if run.report.get('trace') else None
            event_state.pc = event_state.last.get('pc') if event_state.last else None
            event_state.reason = {run.FC_STOP: 'first-contact-service-boundary', run.FC_INIT: 'first-contact-wrong-entry-init', run.FC_SERVICE: 'first-contact-service-entered'}.get(event_state.pc)
            if event_state.reason is not None:
                event_state.ret = run.EXC_RET.EXIT_GUEST
                run.report['stop_reason'] = event_state.reason
                event_state.fc = dict(stop_pc=hex(event_state.pc), reason=event_state.reason, reached_dispatcher=any((e.get('pc') == run.FC_DISPATCH for e in run.report.get('trace', []))))
                try:
                    event_state.fc['gxf_enter'] = run.u.mrs(run.GXF_ENTER_ENC)
                except Exception as e:
                    event_state.fc['gxf_enter_error'] = str(e)
                run.report['first_contact'] = event_state.fc
        if event_state.ret == run.EXC_RET.HANDLED and run.a.real_guarded and ('sptm_panic' not in run.report):
            event_state.last = run.report['trace'][-1] if run.report.get('trace') else None
            if event_state.last and event_state.last.get('pc') == run.FC_PANIC:
                event_state.regs = event_state.last.get('regs') or []

                def _h(i):
                    return hex(event_state.regs[i]) if len(event_state.regs) > i and isinstance(event_state.regs[i], int) else None
                run.report['sptm_panic'] = dict(pc=hex(run.FC_PANIC), lr=_h(30), args=[_h(i) for i in range(8)], prior_pcs=[hex(e['pc']) for e in run.report.get('trace', [])[-6:] if isinstance(e.get('pc'), int)])
                run.report['stop_reason'] = 'sptm-panic'
                event_state.ret = run.EXC_RET.EXIT_GUEST
        try:
            event_state.interval = 128 if run.trace_count(run.report) <= 4096 else 4096
            if run.trace_count(run.report) - run.report.get('trace_checkpoint_events', 0) >= event_state.interval or event_state.ret == run.EXC_RET.EXIT_GUEST:
                run.report['trace_checkpoint_events'] = run.trace_count(run.report)
                run.save()
        except Exception as error:
            run.report['report_save_error'] = str(error)
            run.report['stop_reason'] = 'report-write-error'
            event_state.ret = run.EXC_RET.EXIT_GUEST
        finally:
            if run.a.free_run and (not run.handoff_state['active']) and (not run.txm_context_step_state['active']) and (not run.txm_validator_trace_state['active']) and (event_state.ret == run.EXC_RET.HANDLED) and run.entered:
                try:
                    event_state.fc = run.iface.readstruct(event_state.info, run.ExcInfo)
                    if int(event_state.fc.spsr) & 1 << 21:
                        event_state.fc.spsr.SS = 0
                        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.fc))
                except Exception as error:
                    run.report['free_run_resume_error'] = str(error)
            if run.batch is not None:
                try:
                    if not run.a.free_run and event_state.ret == run.EXC_RET.HANDLED and run.entered and run.shadow_sctlr & 1 and (not (run.a.single_step_after and run.trace_count(run.report) >= run.a.single_step_after)) and (not (run.ss_window and run.ss_window[0] <= run.trace_count(run.report) < run.ss_window[1])):
                        run.batch.arm(run.report, run.a.steps)
                    else:
                        run.batch.disable()
                except Exception as error:
                    run.report['batch_error'] = str(error)
                    run.report['error'] = str(error)
                    run.report['stop_reason'] = 'native-batch-error'
                    run.report['trace_incomplete'] = True
                    event_state.ret = run.EXC_RET.EXIT_GUEST
            run.p.exit(event_state.ret)
