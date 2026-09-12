# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Exceptions event handlers extracted from the original probe callback."""
from . import handoff


def handle_exception(run, event_state):
    event_state.ctx = run.iface.readstruct(event_state.info,run.ExcInfo)
    event_state.esr = int(event_state.ctx.esr)
    event_state.event.update(pc=event_state.ctx.elr,esr=event_state.esr,far=event_state.ctx.far,spsr=int(event_state.ctx.spsr),regs=list(event_state.ctx.regs),sp=list(event_state.ctx.sp))
    if not run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (
        (event_state.esr == 0x5a007ffe and event_state.ctx.elr == run.entry+4) or
        (event_state.esr >> 26 == 0x32 and event_state.ctx.elr == run.entry)):
        run.entered = True
        run.iface.writemem(run.entry,run.original)
        run.p.dc_cvau(run.entry,4);run.p.ic_ivau(run.entry,4)
        event_state.ctx.elr = run.entry
        # Establish masked entry state before monitor vectors exist.
        event_state.ctx.spsr.D = event_state.ctx.spsr.A = event_state.ctx.spsr.I = event_state.ctx.spsr.F = 1
        event_state.ctx.spsr.SS = 1
        run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
        event_state.event['kind'] = 'entry-guard'
        event_state.ret = run.EXC_RET.HANDLED
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and event_state.esr >> 26 == 0x32:
        event_state.event['kind'] = 'instruction-step'
        event_state.off = event_state.ctx.elr-run.base
        event_state.effect = run.recognize_zero_loop(bytes(run.blob[event_state.off:event_state.off+12]),event_state.ctx.regs,event_state.ctx.elr,run.base,run.guest_size) if run.a.emulate_zero_loops and 0 <= event_state.off <= len(run.blob)-12 else None
        if event_state.effect is not None:
            # Match live bytes as well: self-modified code is never accelerated.
            if run.iface.readmem(event_state.ctx.elr,12) == bytes(run.blob[event_state.off:event_state.off+12]):
                run.p.memset64(event_state.effect['address'],0,event_state.effect['bytes'])
                run.p.dc_cvau(event_state.effect['address'],event_state.effect['bytes'])
                event_state.ctx.regs[1],event_state.ctx.regs[2] = event_state.effect['x1'],event_state.effect['x2']
                event_state.ctx.elr = event_state.effect['pc']
                event_state.ctx.spsr.N,event_state.ctx.spsr.Z,event_state.ctx.spsr.C,event_state.ctx.spsr.V = 0,1,1,0
                event_state.event.update(kind='emulated-zero-loop',effects=event_state.effect)
        # Multi-call: the patched idle is a genter loop. At each genter (FC_IDLE_PC)
        # set x16 = the next selector; at each return (FC_IDLE_PC+4) capture x0.
        event_state.gc_done = False
        if run.multi_call_selectors is not None:
            if event_state.ctx.elr == run.FC_IDLE_PC and not run.gc_state['in_call'] and run.gc_state['index'] < len(run.multi_call_selectors):
                event_state.sel = run.multi_call_selectors[run.gc_state['index']]
                event_state.ctx.regs[16] = event_state.sel
                run.gc_state['in_call'] = True; run.gc_state['started'] = run.trace_count(run.report)
                event_state.event.update(kind='guarded-call-genter', call_index=run.gc_state['index'], selector=hex(event_state.sel))
            elif event_state.ctx.elr == run.FC_IDLE_PC + 4 and run.gc_state['in_call']:
                run.report.setdefault('guarded_calls', []).append(dict(
                    index=run.gc_state['index'], selector=hex(run.multi_call_selectors[run.gc_state['index']]),
                    result=event_state.ctx.regs[0], steps=run.trace_count(run.report)-run.gc_state['started']))
                event_state.event.update(kind='guarded-call-return', call_index=run.gc_state['index'], result=event_state.ctx.regs[0])
                run.gc_state['in_call'] = False; run.gc_state['index'] += 1
                if run.gc_state['index'] >= len(run.multi_call_selectors):
                    run.report['stop_reason'] = 'guarded-calls-complete'; event_state.gc_done = True
            elif event_state.ctx.elr == run.FC_PANIC and run.gc_state['in_call']:
                # Invalid/not-permitted call: SPTM's panic is noreturn (would hang/reboot).
                # Halt here, BEFORE the panic runs, and record it (non-mutating, non-launching).
                run.report.setdefault('guarded_calls', []).append(dict(
                    index=run.gc_state['index'], selector=hex(run.multi_call_selectors[run.gc_state['index']]),
                    result=None, panicked=True, steps=run.trace_count(run.report)-run.gc_state['started']))
                event_state.event.update(kind='guarded-call-panic', call_index=run.gc_state['index'])
                run.report['stop_reason'] = 'guarded-call-panic'; event_state.gc_done = True
        if event_state.gc_done:
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))  # persist captured state; exit (no SS)
        elif run.trace_count(run.report) < run.a.steps:
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            run.report['stop_reason'] = 'instruction-budget'
    elif run.entered and run.a.free_run and run.a.real_guarded and event_state.reason == run.START.EXCEPTION_LOWER and event_state.esr >> 26 == 0x16 and (event_state.esr & 0xffff) == 0x4800:
        handoff.handle_guarded_exit(run, event_state)
    elif run.entered and run.a.free_run and event_state.reason == run.START.EXCEPTION_LOWER and event_state.esr >> 26 == 0x16 and (event_state.esr & 0xfff0) == 0x6080:
        run.report['stop_reason'] = 'unexpected-eret-overlay'
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and event_state.esr >> 26 == 0x16 and (event_state.esr & 0xff80) == 0x6000:
        event_state.imm = event_state.esr & 0xffff
        event_state.read, event_state.rt, event_state.sctlr = bool(event_state.imm & 0x20), event_state.imm & 31, bool(event_state.imm & 0x40)
        event_state.value = 0 if event_state.rt == 31 else event_state.ctx.regs[event_state.rt]
        event_state.event.update(kind='probe-control', register='SCTLR_EL2' if event_state.sctlr else 'HCR_EL2', read=event_state.read, value=event_state.value)
        event_state.accepted = False
        # A deliberately rejected recognized profile may pause once for a local
        # policy decision, then retry this same trap with the flag enabled.
        for event_state.attempt in range(2):
            if event_state.read:
                if event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = run.shadow_sctlr if event_state.sctlr else run.shadow_hcr
                event_state.accepted = True
            elif not event_state.sctlr and event_state.value in (0,0x408000000) and (not run.shadow_sctlr & 1 or event_state.value == run.shadow_hcr):
                run.shadow_hcr = event_state.value
                event_state.accepted = True
            elif event_state.sctlr and event_state.value in (0,0x30d00800):
                # No active guest translation/cache regime in this entry-only probe.
                if run.shadow_sctlr & 1:
                    run.u.msr(run.SCTLR_EL12,0x30d00800)
                    run.u.exec('isb; dsb ishst; tlbi vmalle1is; dsb ish; isb')
                run.shadow_sctlr = event_state.value
                event_state.accepted = True
            elif event_state.sctlr and run.a.allow_monitor_mmu and event_state.value == 0x02001010fc14793d and run.shadow_hcr == 0x408000000 and run.shadow_sprr_config == 0:
                event_state.controls = dict(tcr=run.u.mrs(run.TCR_EL12),ttbr0=run.u.mrs(run.TTBR0_EL12),ttbr1=run.u.mrs(run.TTBR1_EL12),mair=run.u.mrs(run.MAIR_EL12))
                run.report['monitor_mmu_controls'] = event_state.controls
                # The entry contract is validated ONCE, at the genuine first
                # monitor MMU enable. SPTM re-writes this same SCTLR value during
                # later world switches (e.g. the guarded context-save at 0xa4dc0+),
                # where the mode is EL1h and SP_EL1 is mid-restore (0) -- re-running
                # the entry check there wrongly rejects a valid transition
                # (attempt-33). After the first validation, just apply the write.
                if not run.monitor_mmu_validated:
                    if (int(event_state.ctx.spsr) & 15) not in (4, 5):
                        raise ValueError('Unsupported physical guest mode for monitor entry')
                    event_state.active_sp = event_state.ctx.sp[0] if int(event_state.ctx.spsr) & 15 == 4 else event_state.ctx.sp[1]
                    event_state.checked = run.validate_monitor_entry(
                        event_state.controls, event_state.ctx.elr, event_state.active_sp, run.base+run.args_off, run.base, run.guest_size,
                        lambda addr: run.iface.readmem(addr,run.PAGE), pan=bool(int(event_state.ctx.spsr) & (1 << 22)),
                        on_check=lambda name, addr: run.report.update(
                            monitor_mmu_check_pending=dict(name=name, va=addr)))
                    run.report['monitor_mmu_address_checks'] = event_state.checked
                    run.monitor_mmu_validated = True
                    event_state.event['kind'] = 'monitor-mmu-enabled'
                else:
                    event_state.event['kind'] = 'monitor-mmu-reentry'
                run.u.exec('dsb ishst; tlbi vmalle1is; dsb ish; isb')
                run.u.msr(run.SCTLR_EL12,event_state.value)
                run.u.exec('isb')
                run.shadow_sctlr = event_state.value
                event_state.accepted = True
            if event_state.accepted or event_state.attempt or not (event_state.sctlr and not event_state.read and event_state.value == 0x02001010fc14793d
                                           and run.shadow_hcr == 0x408000000 and run.shadow_sprr_config == 0
                                           and run.pause_guard('monitor-translation-contract', 'allow_monitor_mmu', event_state.event)):
                break
        if event_state.accepted:
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            run.report['stop_reason'] = 'monitor-translation-contract'
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and event_state.esr >> 26 == 0x16 and (event_state.esr & 0xfff0) in (0x6090, 0x60a0):
        event_state.imm = event_state.esr & 0xf
        event_state.exiting = (event_state.esr & 0xfff0) == 0x60a0
        event_state.was_guarded = run.gxf_state['guarded']
        event_state.event.update(kind='guarded-instruction', instruction='gexit' if event_state.exiting else 'genter', imm=event_state.imm, guarded_before=event_state.was_guarded)
        event_state.mode = int(event_state.ctx.spsr) & 15
        if not run.a.virtual_gxf:
            run.report['stop_reason'] = 'unsupported-exception'
        elif not run.gxf_state['config'] & 1 or event_state.mode not in (4, 5) or (event_state.exiting and not event_state.was_guarded) or (not event_state.exiting and not run.apple_shadow[run.GXF_ENTRY_EL1]):
            run.report['stop_reason'] = 'unsupported-guarded-transition'
        elif event_state.exiting:
            event_state.link_pc, event_state.link_pstate = run.u.mrs(run.ELR_EL12), run.u.mrs(run.SPSR_EL12)
            # Capture the guarded bank, then restore the ordinary EL1 exception bank.
            for event_state.gl, event_state.el in run.gxf_banks.items():
                run.apple_shadow[event_state.gl] = run.u.mrs(event_state.el)
            for event_state.el, event_state.saved in run.gxf_state['el_bank'].items():
                run.u.msr(event_state.el, event_state.saved)
            event_state.ctx.sp[1], run.gxf_state['sp_bank'] = run.gxf_state['sp_bank'], event_state.ctx.sp[1]
            run.gxf_state['guarded'] = False
            run.gxf_state['gexit'] += 1
            event_state.ctx.elr = event_state.link_pc
            event_state.ctx.spsr = type(event_state.ctx.spsr)(event_state.link_pstate)
            event_state.event.update(kind='virtual-gexit', link_pc=event_state.link_pc, link_pstate=event_state.link_pstate)
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.link_pc, event_state.link_pstate = event_state.ctx.elr, int(event_state.ctx.spsr)
            if not event_state.was_guarded:
                run.gxf_state['el_bank'] = {el: run.u.mrs(el) for el in run.gxf_banks.values()}
                for event_state.gl, event_state.el in run.gxf_banks.items():
                    if event_state.gl != run.VBAR_GL1 or run.apple_shadow[event_state.gl]:
                        run.u.msr(event_state.el, run.apple_shadow[event_state.gl])
                event_state.ctx.sp[1], run.gxf_state['sp_bank'] = run.gxf_state['sp_bank'], event_state.ctx.sp[1]
                run.gxf_state['guarded'] = True
            run.u.msr(run.SPSR_EL12, event_state.link_pstate)
            run.u.msr(run.ELR_EL12, event_state.link_pc)
            run.u.msr(run.ESR_EL12, 0xfe010000 | event_state.imm)
            run.apple_shadow[run.ASPSR_GL1] = (run.apple_shadow[run.ASPSR_GL1] | 1) if event_state.was_guarded else (run.apple_shadow[run.ASPSR_GL1] & ~1)
            run.gxf_state['genter'] += 1
            event_state.ctx.elr = run.apple_shadow[run.GXF_ENTRY_EL1]
            event_state.ctx.spsr = type(event_state.ctx.spsr)(((event_state.link_pstate | 0x3c0) & ~0xf) | 5)
            event_state.event.update(kind='virtual-genter', entry=event_state.ctx.elr, link_pc=event_state.link_pc, link_pstate=event_state.link_pstate,
                         vector_swapped=bool(run.apple_shadow[run.VBAR_GL1]))
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        run.gxf_report().update(guarded=run.gxf_state['guarded'], genter=run.gxf_state['genter'], gexit=run.gxf_state['gexit'],
                                     last_transition_index=run.trace_count(run.report))
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and event_state.esr >> 26 == 0x16 and (event_state.esr & 0xc000) == 0x8000:
        event_state.imm = event_state.esr & 0xffff
        event_state.reg = run.extra_regs[(event_state.imm & 0x3fff)>>6]
        event_state.read, event_state.rt = bool(event_state.imm & 0x20), event_state.imm & 31
        event_state.value = 0 if event_state.rt == 31 else event_state.ctx.regs[event_state.rt]
        event_state.event.update(kind='probe-el2-register', register=run.sysreg_rev.get(event_state.reg, 'AGTCNTVOFF_EL2 (observed encoding)' if event_state.reg == run.apple_cntvoff else 'S3_%d_C%d_C%d_%d' % event_state.reg[1:]), read=event_state.read, value=event_state.value)
        if run.a.real_guarded and event_state.reg in run.real_redirect:
            # R2 SYSREG_MAP: redirect the guest's EL1 access to its EL12/GL12 alias,
            # which reaches the guest's EL1 bank from EL2 (the vel2 HV's own mechanism).
            event_state.xnu_gexit = (run.a.native_handoff and not event_state.read and event_state.reg == run.ASPSR_GL1
                and event_state.value == 0 and event_state.ctx.elr == run.FC_XNU_GEXIT)
            if event_state.xnu_gexit:
                # The final SPTM launch is a native GEXIT, not an ERET.  The
                # rewritten ASPSR_GL1 write immediately before it is our last
                # existing trap.  Verify the already-written guarded banks and
                # stop before executing GEXIT; attempt 48 independently proved
                # that resuming here transfers to this PC (and then faults there).
                event_state.elr_gl1 = int(run.u.mrs(run.HV.MSR_REDIRECTS[run.ELR_GL1]))
                event_state.spsr_gl1 = int(run.u.mrs(run.HV.MSR_REDIRECTS[run.SPSR_GL1]))
                event_state.roots = dict(ttbr0=run.u.mrs(run.TTBR0_EL12), ttbr1=run.u.mrs(run.TTBR1_EL12))
                event_state.handoff = run.classify_entry(event_state.elr_gl1, run.layout, run.base, run.guest_size,
                                         event_state.roots, run.iface.readmem, run.sources)
                # Capture the live launch bank before teardown changes it.  In
                # real mode the permission shadows are intentionally stale:
                # accesses go straight to the hypervisor's guest aliases.
                event_state.launch = dict(va=event_state.elr_gl1, saved_pstate=event_state.spsr_gl1,
                              callback_pstate=int(event_state.ctx.spsr),
                              permission_source='live guest aliases',
                              controls=dict(event_state.roots), table_pages=[])
                run.report['xnu_launch_permissions'] = event_state.launch
                for event_state.name, event_state.register in (('tcr', run.TCR_EL12), ('mair', run.MAIR_EL12),
                                       ('sctlr', run.SCTLR_EL12)):
                    try:
                        event_state.launch['controls'][event_state.name] = int(run.u.mrs(event_state.register))
                    except Exception as capture_error:
                        event_state.launch[event_state.name + '_error'] = str(capture_error)
                for event_state.name, event_state.register in (('pperm_el1', run.SPRR_PPERM_EL1),
                                       ('uperm_el0', run.SPRR_UPERM_EL0)):
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
                            event_state.launch[event_state.world] = run.leaf_permissions(event_state.leaf['descriptor'],
                                event_state.launch['pperm_el1'], event_state.launch['uperm_el0'], event_state.world)
                except Exception as capture_error:
                    event_state.launch['mapping_error'] = str(capture_error)
                event_state.verified = (event_state.handoff['image'] == 'kernelcache'
                    and event_state.handoff['entry_matches'] and event_state.handoff['bytes_match']
                    and event_state.spsr_gl1 == 0x13c9)
                event_state.event.update(kind='xnu-gexit-handoff', target=hex(event_state.elr_gl1),
                             target_spsr=hex(event_state.spsr_gl1), verified=event_state.verified)
                if event_state.verified:
                    run.report['handoff'] = dict(event_state.handoff, spsr=hex(event_state.spsr_gl1),
                        via='native GEXIT launch boundary',
                        source_pc=hex(run.FC_XNU_GEXIT), instructions_executed=False)
                    run.report['stop_reason'] = 'handoff-xnu-entry'
                    if run.a.xnu_steps:
                        if (not event_state.launch.get('ordinary', {}).get('kernel_execute')
                                or any(key.endswith('_error') for key in event_state.launch)):
                            run.report['stop_reason'] = 'xnu-launch-permission-unverified'
                        else:
                            # Synthetic CurrentEL reports EL2, but native GEXIT
                            # must return to physical EL1h.  Attempt 48's EL2h
                            # request instead set PSTATE.IL and stayed EL1t.
                            event_state.physical_spsr = 0x13c5 | (1 << 21)
                            run.u.msr(run.HV.MSR_REDIRECTS[run.SPSR_GL1], event_state.physical_spsr)
                            run.u.msr(run.HV.MSR_REDIRECTS[run.ASPSR_GL1], 0)
                            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                            run.report['handoff']['physical_spsr'] = hex(event_state.physical_spsr)
                            run.report['handoff']['native_resume'] = True
                            run.handoff_state.update(active=True, events=0,
                                                 xnu=True, budget=run.a.xnu_steps)
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
                    run.report.setdefault('real_guarded_vbar', []).append(dict(
                        index=run.trace_count(run.report), requested=event_state.value,
                        readback=event_state.readback))
                    event_state.event['readback'] = event_state.readback
                if event_state.reg == run.SPRR_CONFIG_EL1:
                    event_state.enable = run.report.setdefault('sprr_real_enable', dict(enforced=True, events=[]))
                    event_state.enable['events'].append(dict(index=run.trace_count(run.report), value=event_state.value,
                        controls=dict(tcr=run.u.mrs(run.TCR_EL12), ttbr0=run.u.mrs(run.TTBR0_EL12),
                                      ttbr1=run.u.mrs(run.TTBR1_EL12), mair=run.u.mrs(run.MAIR_EL12)),
                        enable=bool(event_state.value & 1), lock_config=bool(event_state.value & 2),
                        lock_perm=bool(event_state.value & 0x10), lock_kernel_perm=bool(event_state.value & 0x20)))
            if not event_state.xnu_gexit:
                event_state.event['kind'] = 'real-guarded-redirect'
                event_state.ctx.spsr.SS = 1
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg in run.translation_banks:
            event_state.bank = run.translation_banks[event_state.reg]
            event_state.current_value = run.u.mrs(event_state.bank)
            if run.a.free_run:
                # Free-run trusts the monitor: apply translation-control writes
                # (TCR/TTBR/MAIR to the guest EL1 regime) and continue, without
                # the boot-time root-switch validation. SPTM reconfigures the
                # regime during its world switch to XNU; applying the redirected
                # write is what actually lets the launch proceed.
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
            elif not event_state.read and run.shadow_sctlr & 1 and event_state.value != event_state.current_value:
                for event_state.attempt in range(2):
                    if run.a.allow_live_ttbr and event_state.bank in (run.TTBR0_EL12, run.TTBR1_EL12):
                        event_state.controls = dict(tcr=run.u.mrs(run.TCR_EL12),ttbr0=run.u.mrs(run.TTBR0_EL12),ttbr1=run.u.mrs(run.TTBR1_EL12),mair=run.u.mrs(run.MAIR_EL12))
                        event_state.mode = int(event_state.ctx.spsr) & 15
                        if event_state.mode not in (4,5):
                            raise ValueError('Unsupported guest mode for live root switch')
                        event_state.sequence = len(run.report.get('live_ttbr_switches', []))
                        def read_switch_page(address):
                            data = run.iface.readmem(address,run.PAGE)
                            run.capture.save_input(f'ttbr-{event_state.sequence}-{address:x}.bin', data)
                            return data
                        event_state.checked = run.validate_root_switch(event_state.controls,
                            'ttbr0' if event_state.bank == run.TTBR0_EL12 else 'ttbr1', event_state.value,
                            event_state.ctx.elr, event_state.ctx.sp[event_state.mode-4], run.u.mrs(run.VBAR_EL12), run.base, run.guest_size,
                            read_switch_page, pan=bool(int(event_state.ctx.spsr) & (1 << 22)))
                        event_state.switch = dict(previous_controls=event_state.controls, validation=event_state.checked, applied=False)
                        run.report.setdefault('live_ttbr_switches', []).append(event_state.switch)
                        # The guest is stopped: order its table stores, publish the root,
                        # then invalidate the guest stage-1 TLB before continuation.
                        run.u.exec('dsb ishst')
                        run.u.msr(event_state.bank,event_state.value)
                        run.u.exec('isb; dsb ishst; tlbi vmalle1is; dsb ish; isb')
                        if run.u.mrs(event_state.bank) != event_state.value:
                            raise ValueError('Live root readback mismatch')
                        event_state.switch['applied'] = True
                        run.report['monitor_mmu_controls'] = event_state.checked['controls']
                        event_state.event['kind'] = 'validated-live-ttbr-switch'
                        event_state.ctx.spsr.SS = 1
                        run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
                        event_state.ret = run.EXC_RET.HANDLED
                        break
                    if not event_state.attempt and event_state.bank in (run.TTBR0_EL12, run.TTBR1_EL12) and run.pause_guard('live-translation-control-change', 'allow_live_ttbr', event_state.event):
                        continue
                    run.report['stop_reason'] = 'live-translation-control-change'
                    break
            else:
                if event_state.read and event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = event_state.current_value
                elif not event_state.read and not run.shadow_sctlr & 1:
                    run.u.msr(event_state.bank,event_state.value)
                event_state.ctx.spsr.SS = 1
                run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
                event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg in (run.CNTVOFF_EL2,run.apple_cntvoff,run.VM_TMR_FIQ_ENA_EL2) and (event_state.read or event_state.value == 0):
            if event_state.read and event_state.rt != 31:
                event_state.ctx.regs[event_state.rt] = 0
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg in (run.APCTL_EL1,run.KERNKEYLO_EL1,run.KERNKEYHI_EL1):
            # Public hv_exc.c maps this guest control to its EL12 bank.
            if event_state.read and event_state.rt != 31:
                event_state.ctx.regs[event_state.rt] = run.u.mrs(run.HV.MSR_REDIRECTS[event_state.reg])
            elif not event_state.read:
                run.u.msr(run.HV.MSR_REDIRECTS[event_state.reg],event_state.value)
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg == run.SPRR_CONFIG_EL1 and (event_state.read or run.a.observe_sprr or run.a.real_guarded or (not run.shadow_sctlr & 1 and event_state.value in (0,1))):
            # Public hv-sprr also defers permission mirrors until SCTLR.M.
            # Both SCTLR aliases are intercepted; translated SPRR activation stops
            # unless observation-only staging was requested: nothing is enforced.
            if run.a.real_guarded:
                # R2: really apply SPRR config to the guest, and snapshot the enable point
                # for offline leaf validation. Nothing is faked. Whether an EL2 msr reaches
                # the guest's SPRR (vs the HV's own) is the first thing the pre-idle dry run
                # must confirm before this path is trusted.
                if event_state.read:
                    if event_state.rt != 31:
                        event_state.ctx.regs[event_state.rt] = run.u.mrs(run.SPRR_CONFIG_EL1) if run.real_sprr_on else run.shadow_sprr_config
                    event_state.event['kind'] = 'real-sprr-config'
                elif not run.shadow_sctlr & 1:
                    # SPRR governs stage-1 leaf permissions; before the guest MMU is on it is
                    # inert. The monitor writes SPRR_CONFIG early (pre-MMU); stage those and
                    # apply for real only from the post-MMU enable point.
                    run.shadow_sprr_config = event_state.value
                    event_state.event['kind'] = 'staged-sprr-config'
                else:
                    event_state.controls = dict(tcr=run.u.mrs(run.TCR_EL12), ttbr0=run.u.mrs(run.TTBR0_EL12),
                                    ttbr1=run.u.mrs(run.TTBR1_EL12), mair=run.u.mrs(run.MAIR_EL12))
                    run.u.msr(run.SPRR_CONFIG_EL1, event_state.value)
                    run.shadow_sprr_config = event_state.value
                    run.real_sprr_on = bool(event_state.value & 1) or run.real_sprr_on
                    event_state.enable = run.report.setdefault('sprr_real_enable', dict(enforced=True, events=[]))
                    event_state.enable['events'].append(dict(index=run.trace_count(run.report), value=event_state.value, controls=event_state.controls,
                        enable=bool(event_state.value & 1), lock_config=bool(event_state.value & 2), lock_perm=bool(event_state.value & 0x10),
                        lock_kernel_perm=bool(event_state.value & 0x20), unknown_bits=event_state.value & ~0x33,
                        permissions={run.sysreg_rev.get(r, 'S3_%d_C%d_C%d_%d' % r[1:]): v for r, v in run.permission_shadow.items()}))
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
                    # Bit names from the pinned runtime's cpu_regs.h; other bits are recorded as unknown.
                    event_state.observation['events'].append(dict(index=run.trace_count(run.report), value=event_state.value,
                        enable=bool(event_state.value & 1), lock_config=bool(event_state.value & 2), lock_perm=bool(event_state.value & 0x10),
                        lock_kernel_perm=bool(event_state.value & 0x20), unknown_bits=event_state.value & ~0x33,
                        permissions={run.sysreg_rev[r]: v for r, v in run.permission_shadow.items()}))
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg in run.permission_shadow:
            if event_state.read and event_state.rt != 31:
                event_state.ctx.regs[event_state.rt] = run.permission_shadow[event_state.reg]
            elif not event_state.read:
                run.permission_shadow[event_state.reg] = event_state.value
            # Redirectable perms (PPERM/UPERM) are applied via their EL12 alias in the
            # real-guarded branch above; the rest (PMPRR, SH variants) have no alias and
            # stage until a mechanism for them is established.
            event_state.event['kind'] = 'staged-sprr-permission'
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg == run.GXF_CONFIG_EL1 and run.a.real_guarded and (event_state.read or event_state.value in (0, 1)):
            # R2: really enable GXF so native genter/gexit transitions are defined.
            # Apply only once the guest MMU is on (GXF setup is post-MMU); stage earlier.
            if event_state.read:
                if event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = run.u.mrs(run.GXF_CONFIG_EL1) if run.shadow_sctlr & 1 else 0
            elif run.shadow_sctlr & 1:
                run.u.msr(run.GXF_CONFIG_EL1, event_state.value)
            event_state.event['kind'] = 'real-gxf-config'
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg == run.GXF_CONFIG_EL1 and run.a.virtual_gxf and (event_state.read or event_state.value in (0, 1)):
            if event_state.read and event_state.rt != 31:
                event_state.ctx.regs[event_state.rt] = run.gxf_state['config']
            elif not event_state.read:
                run.gxf_state['config'] = event_state.value
                run.gxf_report()['config_events'].append(dict(index=run.trace_count(run.report), value=event_state.value))
            event_state.event['kind'] = 'virtual-gxf-config'
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.reg in run.apple_shadow or (event_state.reg == run.GXF_STATUS_EL1 and event_state.read):
            if event_state.reg == run.GXF_STATUS_EL1:
                if event_state.rt != 31:
                    event_state.ctx.regs[event_state.rt] = int(run.gxf_state['guarded'])
                event_state.event['kind'] = 'staged-apple-register'
            elif run.gxf_state['guarded'] and event_state.reg in run.gxf_banks:
                # While guarded the GL1 bank is the live EL1 exception bank.
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
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif run.a.stage_el2_config:
            if event_state.read and event_state.rt != 31:
                event_state.ctx.regs[event_state.rt] = run.el2_shadow.get(event_state.reg, 0)
            elif not event_state.read:
                run.el2_shadow[event_state.reg] = event_state.value
                run.report['staged_el2_registers'] = {run.sysreg_rev.get(r, 'S3_%d_C%d_C%d_%d' % r[1:]): v for r, v in run.el2_shadow.items()}
            event_state.event['kind'] = 'staged-el2-register'
            event_state.ctx.spsr.SS = 1
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            run.report['stop_reason'] = 'unsupported-el2-register'
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and event_state.esr >> 26 == 0x18:
        event_state.access = run.ESR_ISS_MSR(event_state.esr & 0x1ffffff)
        event_state.reg = (event_state.access.Op0,event_state.access.Op1,event_state.access.CRn,event_state.access.CRm,event_state.access.Op2)
        event_state.value = 0 if event_state.access.Rt == 31 else event_state.ctx.regs[event_state.access.Rt]
        event_state.event['sysreg'] = dict(encoding=list(event_state.reg), name=run.sysreg_rev.get(event_state.reg),
                               read=bool(event_state.access.DIR), rt=event_state.access.Rt, value=event_state.value)
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
            run.iface.writemem(event_state.info,run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            run.report['stop_reason'] = 'unsupported-system-register'
    elif run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.esr >> 26) == 0x01 and run.a.free_run:
        # WFE/WFI trapped (HCR.TWE) during free-run. The panic halt is a wfe
        # self-loop at FC_IDLE_PC (0xf8b88); stop there. Any other wait is
        # benign -- skip it (advance ELR past the wfe) and resume natively.
        if event_state.ctx.elr == run.FC_IDLE_PC:
            run.report['stop_reason'] = 'sptm-panic-halt'
            run.report['sptm_panic_halt'] = dict(pc=hex(event_state.ctx.elr),
                note='reached the panic wfe halt in free-run; panic args were consumed at 0xf8ca0 -- re-run single-stepped near here for the message',
                prior_pcs=[hex(e['pc']) for e in run.report.get('trace', [])[-6:] if isinstance(e.get('pc'), int)])
            event_state.event['kind'] = 'panic-halt'
        else:
            event_state.ctx.elr += 4
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.event['kind'] = 'wfx-skip'
            event_state.ret = run.EXC_RET.HANDLED
    elif (run.entered and event_state.reason == run.START.EXCEPTION_LOWER and (event_state.esr >> 26) in (0x24, 0x25)
          and run.a.on_demand_stage2 and (event_state.esr & 0x3c) == 0x04):
        # On-demand stage-2 backing. SPTM writes to a VA whose IPA is not
        # mapped in the guest stage-2 (data-abort translation fault, DFSC
        # 0b0001LL). Translate the faulting VA stage-1-only (AT S1E1x) to get
        # the IPA -- valid even though stage-2 faults -- back that IPA page with
        # a fresh zeroed host page, and retry the instruction (do not advance
        # ELR). Bounded by --on-demand-stage2 MAXPAGES.
        event_state.fault_write = bool((event_state.esr >> 6) & 1)
        event_state.ipa = run.p.hv_translate(event_state.ctx.far, True, event_state.fault_write)
        event_state.od = run.report.setdefault('on_demand_stage2',
                               dict(count=0, samples=[], capped=False, stage1_faults=0))
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
        # For an instruction/data abort from the guest, capture HPFAR_EL2 so a
        # stage-2 fault reports its IPA directly (no offline stage-1 table walk).
        # HPFAR_EL2[43:4] = faulting IPA[51:12]; IPA page = (HPFAR & mask) << 8.
        try:
            event_state.ec = (event_state.esr >> 26) & 0x3f
            if event_state.ec in (0x20, 0x21, 0x24, 0x25):
                event_state.hpfar = run.u.mrs((3, 4, 6, 0, 4))
                event_state.ipa = (event_state.hpfar & 0xfffffffff0) << 8
                event_state.event['hpfar_el2'] = event_state.hpfar
                event_state.event['fault_ipa'] = event_state.ipa
                run.report['unsupported_exception_fault'] = dict(
                    ec=event_state.ec, esr=event_state.esr, far=event_state.event.get('far'), hpfar=event_state.hpfar,
                    ipa=event_state.ipa, dfsc=event_state.esr & 0x3f, write=bool((event_state.esr >> 6) & 1))
        except Exception as hpfar_error:
            event_state.event['hpfar_error'] = str(hpfar_error)
