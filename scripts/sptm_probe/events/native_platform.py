# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Native platform event handlers extracted from the original probe callback."""


def handle_permission_window(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.index, (event_state._, event_state._, event_state._, event_state.operation) = event_state.native_xnu_pperm_site
    event_state.event.update(kind='xnu-pperm-guest-window', pc=event_state.ctx.elr,
                 esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs),
                 far=event_state.ctx.far, sp=list(event_state.ctx.sp), operation=event_state.operation,
                 site_index=event_state.index)
    if event_state.index == 0 and run.xnu_pperm_state['step'] == 4:
        if (run.xnu_pperm_state['modified'] or
                run.xnu_pperm_state['completed'] != run.xnu_pperm_state['started']):
            raise ValueError('XNU PPERM prior window incomplete')
        if run.xnu_pperm_state['completed'] >= run.a.xnu_pperm_guest_window_limit:
            raise run.PpermWindowLimit('XNU PPERM guest window limit exhausted')
        run.xnu_pperm_state['step'] = 0
    if event_state.index != run.xnu_pperm_state['step']:
        raise ValueError('XNU PPERM callback order mismatch')
    event_state.reg = run.HV.MSR_REDIRECTS[run.SPRR_PPERM_EL1]
    if event_state.operation.startswith('read'):
        event_state.raw = int(run.u.mrs(event_state.reg))
        event_state.nibble = (event_state.raw >> 8) & 0xf
        event_state.expected = 0xa if event_state.index == 0 else 0xb
        if event_state.nibble != event_state.expected:
            raise ValueError('XNU PPERM read nibble mismatch')
        if event_state.index == 0:
            if run.xnu_pperm_state['previous'] is None:
                run.xnu_pperm_state['previous'] = event_state.raw
            elif event_state.raw != run.xnu_pperm_state['previous']:
                raise ValueError('XNU PPERM baseline A drift')
            run.xnu_pperm_state['started'] += 1
        else:
            event_state.expected_raw = ((run.xnu_pperm_state['previous'] & ~(0xf << 8))
                            | (0xb << 8))
            if event_state.raw != event_state.expected_raw:
                raise ValueError('XNU PPERM post-copy full value mismatch')
            run.xnu_pperm_state['modified'] = True
            run.report['xnu_pperm_guest_window']['memcpy_crossed'] = True
            run.report['xnu_pperm_guest_window']['memcpy_crossed_windows'] += 1
        event_state.ctx.regs[8] = event_state.raw
        event_state.readback = event_state.raw
    else:
        event_state.requested = int(event_state.ctx.regs[8])
        event_state.previous = run.xnu_pperm_state['previous']
        event_state.expected = ((event_state.previous & ~(0xf << 8)) | ((0xb if event_state.index == 1 else 0xa) << 8))
        if event_state.requested != event_state.expected:
            raise ValueError('XNU PPERM write value mismatch')
        if event_state.index == 1:
            run.xnu_pperm_state['modified'] = True
        run.u.msr(event_state.reg, event_state.requested)
        event_state.readback = int(run.u.mrs(event_state.reg))
        if event_state.readback != event_state.requested:
            raise ValueError('XNU PPERM full readback mismatch')
        if event_state.index == 3:
            run.xnu_pperm_state['modified'] = False
            run.xnu_pperm_state['completed'] += 1
    run.xnu_pperm_state['step'] += 1
    run.report['xnu_pperm_guest_window']['started_windows'] = run.xnu_pperm_state['started']
    run.report['xnu_pperm_guest_window']['completed_windows'] = run.xnu_pperm_state['completed']
    run.report['xnu_pperm_guest_window']['sequence'].append(dict(
        step=event_state.index, operation=event_state.operation, raw=event_state.readback,
        index2_nibble=(event_state.readback >> 8) & 0xf))
    event_state.ctx.elr += 0  # HVC reports the following PC already
    run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
    event_state.event.update(raw=event_state.readback, memcpy_crossed=event_state.index >= 2,
                 window=run.xnu_pperm_state['started'])
    event_state.ret = run.EXC_RET.HANDLED


def handle_timer_redirect(run, event_state):
    event_state.ctx = run.iface.readstruct(event_state.info, run.ExcInfo)
    event_state.requested = int(event_state.ctx.regs[8])
    if event_state.requested != 3:
        event_state.event.update(kind='xnu-agtcnt-rdir-rejected', register='AGTCNTRDIR_EL12',
                     read=False, value=event_state.requested)
        run.report['stop_reason'] = 'xnu-agtcnt-rdir-contract'
    else:
        event_state.previous = int(run.u.mrs(run.AGTCNTRDIR_EL12))
        if run.xnu_agt_state['previous'] is None:
            run.xnu_agt_state['previous'] = event_state.previous
        run.u.msr(run.AGTCNTRDIR_EL12, event_state.requested)
        run.xnu_agt_state['writes'] += 1
        event_state.event.update(kind='xnu-guest-register', register='AGTCNTRDIR_EL12',
                     read=False, value=event_state.requested, previous=event_state.previous,
                     source_pc=hex(event_state.ctx.elr - 4), bank='guest-el12')
        run.report.setdefault('xnu_guest_registers', []).append(dict(
            register='AGTCNTRDIR_EL12', previous=event_state.previous, value=event_state.requested,
            source_pc=hex(event_state.ctx.elr - 4), bank='guest-el12'))
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED


def handle_apple_timer(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.requested = int(event_state.ctx.regs[8])
    if event_state.requested != 2:
        event_state.event.update(kind='xnu-apple-physical-timer-hypothesis-rejected',
                     reason_detail='requested-value-mismatch', value=event_state.requested)
        run.report['stop_reason'] = 'xnu-apple-physical-timer-hypothesis'
    else:
        event_state.previous = int(run.u.mrs(run.FC_XNU_APPLE_PHYS_TIMER_EL02))
        if event_state.previous != run.FC_XNU_APPLE_PHYS_TIMER_OBSERVED_PRIOR:
            event_state.event.update(kind='xnu-apple-physical-timer-hypothesis-rejected',
                         reason_detail='candidate-prior-mismatch',
                         observed_prior_raw=event_state.previous,
                         expected_prior_raw=run.FC_XNU_APPLE_PHYS_TIMER_OBSERVED_PRIOR)
            run.report['stop_reason'] = 'xnu-apple-physical-timer-hypothesis'
        else:
            if run.xnu_apple_timer_state['previous'] is None:
                run.xnu_apple_timer_state['previous'] = event_state.previous
            run.u.msr(run.FC_XNU_APPLE_PHYS_TIMER_EL02, event_state.requested)
            event_state.readback = int(run.u.mrs(run.FC_XNU_APPLE_PHYS_TIMER_EL02))
            run.xnu_apple_timer_state['writes'] += 1
            event_state.ctx.elr += 4
            event_state.hypothesis = dict(
                enabled=True, register='S3_4_C15_C4_3',
                candidate_encoding=list(run.FC_XNU_APPLE_PHYS_TIMER_EL02),
                observed_prior_raw=event_state.previous, requested_raw=event_state.requested,
                readback_raw=event_state.readback, source_pc=hex(event_state.ctx.elr - 4),
                routing_established=False, bit_semantics_established=False,
                physical_s3_1_bank_touched=False)
            run.report['xnu_apple_physical_timer_hypothesis'] = event_state.hypothesis
            event_state.event.update(kind='xnu-apple-physical-timer-hypothesis', **event_state.hypothesis)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED


def handle_physical_timer(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.requested = int(event_state.ctx.regs[8])
    if event_state.requested != 2:
        event_state.event.update(kind='xnu-cntp-ctl-contract-rejected',
                     register='CNTP_CTL_EL02', read=False, value=event_state.requested)
        run.report['stop_reason'] = 'xnu-cntp-ctl-contract'
    else:
        event_state.previous = int(run.u.mrs(run.CNTP_CTL_EL02))
        if run.xnu_cntp_ctl_state['previous'] is None:
            run.xnu_cntp_ctl_state['previous'] = event_state.previous
        run.u.msr(run.CNTP_CTL_EL02, event_state.requested)
        run.xnu_cntp_ctl_state['writes'] += 1
        event_state.ctx.elr += 4
        event_state.event.update(kind='xnu-guest-register', register='CNTP_CTL_EL02',
                     read=False, value=event_state.requested, previous=event_state.previous,
                     source_pc=hex(event_state.ctx.elr - 4), bank='guest-el02',
                     host_timer_bank_touched=False)
        run.report.setdefault('xnu_guest_registers', []).append(dict(
            register='CNTP_CTL_EL02', previous=event_state.previous, value=event_state.requested,
            source_pc=hex(event_state.ctx.elr - 4), bank='guest-el02',
            host_timer_bank_touched=False))
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED


def handle_console(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.dockchannel_site = event_state.native_dockchannel_site
    event_state.fault_write = bool((int(event_state.ctx.esr) >> 6) & 1)
    event_state.ipa = run.p.hv_translate(event_state.ctx.far, True, event_state.fault_write)
    event_state.page = event_state.ipa & ~(run.PAGE - 1) if event_state.ipa else 0
    event_state.expected_page = event_state.dockchannel_site['ipa']
    event_state.od = run.report.setdefault('on_demand_stage2',
        dict(count=0, samples=[], capped=False, stage1_faults=0))
    # Only this exact DT-verified device page can bypass the native stop.
    if event_state.ipa != event_state.dockchannel_site['expected_ipa']:
        event_state.event.update(kind='xnu-native-exception', pc=event_state.ctx.elr,
                     esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr),
                     regs=list(event_state.ctx.regs), far=event_state.ctx.far, sp=list(event_state.ctx.sp),
                     fault_ipa=event_state.ipa or 0,
                     note='not the verified dockchannel-uart page')
        run.report['stop_reason'] = 'xnu-native-exception'
        run.report['handoff']['last_pc'] = hex(event_state.ctx.elr)
    elif event_state.od['count'] >= run.a.on_demand_stage2:
        event_state.od['capped'] = True
        event_state.event.update(kind='on-demand-stage2-exhausted', fault_va=event_state.ctx.far,
                     fault_ipa=event_state.page, mmio=True)
        run.report['stop_reason'] = 'on-demand-stage2-exhausted'
    elif run.p.hv_map(event_state.page, event_state.page | run.HV.PTE_ATTRIBUTES | run.HV.PTE_VALID,
                  run.PAGE, 1) < 0:
        event_state.event.update(kind='dockchannel-uart-map-failed', fault_va=event_state.ctx.far,
                     fault_ipa=event_state.page)
        run.report['stop_reason'] = 'dockchannel-uart-map-failed'
    else:
        run.u.exec('dsb ishst; tlbi vmalls12e1is; dsb ish; isb')
        event_state.od['count'] += 1
        event_state.sample = dict(va=event_state.ctx.far, ipa=event_state.page, host=event_state.page,
                      write=event_state.fault_write, mmio=True, identity=True,
                      site=event_state.dockchannel_site['name'], size=run.PAGE,
                      device_size=event_state.dockchannel_site['device_size'],
                      mapped_device_size=event_state.dockchannel_site['mapped_device_size'],
                      extra_before=event_state.dockchannel_site['extra_before'],
                      extra_after=event_state.dockchannel_site['extra_after'])
        if len(event_state.od['samples']) < 64:
            event_state.od['samples'].append(event_state.sample)
        for event_state.mapping in run.report['xnu_dockchannel_uart_mmio']['mappings']:
            if event_state.mapping['name'] == event_state.dockchannel_site['name']:
                event_state.mapping.update(mapped=True, fault_va=event_state.ctx.far,
                               fault_ipa=event_state.ipa, write=event_state.fault_write)
                break
        event_state.event.update(kind='dockchannel-uart-map', fault_va=event_state.ctx.far,
                     fault_ipa=event_state.page, identity=True, size=run.PAGE,
                     site=event_state.dockchannel_site['name'])
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED


def handle_panic_buffer(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.ipa = run.p.hv_translate(event_state.ctx.far, True, False)
    event_state.od = run.report.setdefault('on_demand_stage2',
        dict(count=0, samples=[], capped=False, stage1_faults=0))
    if event_state.ipa != run.panic_carveout['ipa']:
        event_state.event.update(kind='xnu-native-exception', pc=event_state.ctx.elr,
                     esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs),
                     far=event_state.ctx.far, sp=list(event_state.ctx.sp), fault_ipa=event_state.ipa or 0,
                     note='panic carveout translated IPA mismatch')
        run.report['stop_reason'] = 'xnu-native-exception'
        run.report['handoff']['last_pc'] = hex(event_state.ctx.elr)
    elif event_state.od['count'] + run.panic_carveout['pages'] > run.a.on_demand_stage2:
        event_state.od['capped'] = True
        event_state.event.update(kind='on-demand-stage2-exhausted', fault_va=event_state.ctx.far,
                     fault_ipa=event_state.ipa, pages=run.panic_carveout['pages'])
        run.report['stop_reason'] = 'on-demand-stage2-exhausted'
    elif run.p.hv_map(run.panic_carveout['ipa'],
                  run.panic_carveout['private_host'] | run.HV.PTE_ATTRIBUTES | run.HV.PTE_VALID,
                  run.panic_carveout['size'], 1) < 0:
        event_state.event.update(kind='panic-carveout-map-failed', fault_va=event_state.ctx.far,
                     fault_ipa=event_state.ipa)
        run.report['stop_reason'] = 'panic-carveout-map-failed'
    else:
        run.u.exec('dsb ishst; tlbi vmalls12e1is; dsb ish; isb')
        event_state.od['count'] += run.panic_carveout['pages']
        event_state.sample = dict(va=event_state.ctx.far, ipa=run.panic_carveout['ipa'],
                      host=run.panic_carveout['private_host'],
                      size=run.panic_carveout['size'], pages=run.panic_carveout['pages'],
                      write=False, private_copy=True, original_writes=False)
        if len(event_state.od['samples']) < 64:
            event_state.od['samples'].append(event_state.sample)
        run.report['xnu_private_panic_carveout'].update(
            mapped=True, fault_va=event_state.ctx.far, fault_ipa=event_state.ipa)
        event_state.event.update(kind='panic-carveout-private-map', **event_state.sample)
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED


def handle_trace_buffer(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.ipa = run.p.hv_translate(event_state.ctx.far, True, True)
    event_state.od = run.report.setdefault('on_demand_stage2',
        dict(count=0, samples=[], capped=False, stage1_faults=0))
    event_state.expected_ipa = run.socd_trace['source']
    if event_state.ipa != event_state.expected_ipa or run.report['xnu_private_socd_trace']['mapped']:
        event_state.event.update(kind='xnu-native-exception', pc=event_state.ctx.elr,
                     esr=int(event_state.ctx.esr), spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs),
                     far=event_state.ctx.far, sp=list(event_state.ctx.sp), fault_ipa=event_state.ipa or 0,
                     note='SOCd translated IPA or first-map mismatch')
        run.report['stop_reason'] = 'xnu-native-exception'
        run.report['handoff']['last_pc'] = hex(event_state.ctx.elr)
    elif event_state.od['count'] + 1 > run.a.on_demand_stage2:
        event_state.od['capped'] = True
        event_state.event.update(kind='on-demand-stage2-exhausted', fault_va=event_state.ctx.far,
                     fault_ipa=event_state.ipa, pages=1)
        run.report['stop_reason'] = 'on-demand-stage2-exhausted'
    elif run.p.hv_map(run.socd_trace['ipa'],
                  run.socd_trace['private_host'] | run.HV.PTE_ATTRIBUTES | run.HV.PTE_VALID,
                  run.PAGE, 1) < 0:
        event_state.event.update(kind='socd-trace-map-failed', fault_va=event_state.ctx.far, fault_ipa=event_state.ipa)
        run.report['stop_reason'] = 'socd-trace-map-failed'
    else:
        run.u.exec('dsb ishst; tlbi vmalls12e1is; dsb ish; isb')
        event_state.od['count'] += 1
        event_state.sample = dict(va=event_state.ctx.far, ipa=run.socd_trace['ipa'],
                      fault_ipa=event_state.ipa, host=run.socd_trace['private_host'], size=run.PAGE,
                      pages=1, write=True, private_copy=True, original_writes=False)
        if len(event_state.od['samples']) < 64:
            event_state.od['samples'].append(event_state.sample)
        run.report['xnu_private_socd_trace'].update(
            mapped=True, fault_va=event_state.ctx.far, fault_ipa=event_state.ipa)
        event_state.event.update(kind='socd-trace-private-map', **event_state.sample)
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED


def handle_debug_access(run, event_state):
    # Native XNU can re-enter SPTM paths that use the same guest debug
    # controls seen during the stepped prefix. Keep those accesses in the
    # existing disabled-debug model; never expose the host MDSCR/OS lock.
    event_state.ctx = event_state.native_ctx
    event_state.esr = int(event_state.ctx.esr)
    event_state.access = run.ESR_ISS_MSR(event_state.esr & 0x1ffffff)
    event_state.reg = (event_state.access.Op0, event_state.access.Op1, event_state.access.CRn, event_state.access.CRm, event_state.access.Op2)
    event_state.value = 0 if event_state.access.Rt == 31 else event_state.ctx.regs[event_state.access.Rt]
    event_state.event.update(pc=event_state.ctx.elr, esr=event_state.esr, far=event_state.ctx.far,
                 spsr=int(event_state.ctx.spsr), regs=list(event_state.ctx.regs), sp=list(event_state.ctx.sp),
                 sysreg=dict(encoding=list(event_state.reg), name=run.sysreg_rev.get(event_state.reg),
                             read=bool(event_state.access.DIR), rt=event_state.access.Rt, value=event_state.value))
    event_state.debug_effect = run.guest_debug.access(event_state.reg, bool(event_state.access.DIR), event_state.value)
    if event_state.debug_effect is None:
        event_state.event['kind'] = 'xnu-native-exception'
        run.report['stop_reason'] = 'xnu-native-exception'
        run.report['handoff']['last_pc'] = hex(event_state.ctx.elr)
    else:
        if event_state.access.DIR and event_state.access.Rt != 31:
            event_state.ctx.regs[event_state.access.Rt] = event_state.debug_effect['value']
        event_state.event['kind'] = event_state.debug_effect['kind']
        event_state.event['native_handoff'] = True
        event_state.event['sysreg']['value'] = event_state.debug_effect['value']
        run.report['guest_debug'] = run.guest_debug.snapshot()
        if run.guest_debug.oslock is not None:
            run.report['guest_oslock'] = run.guest_debug.oslock
        event_state.ctx.elr += 4
        event_state.ctx.spsr.SS = 0
        run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
        event_state.ret = run.EXC_RET.HANDLED
