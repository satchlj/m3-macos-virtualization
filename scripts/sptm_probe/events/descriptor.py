# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Descriptor and leaf binding event handlers."""

def handle_leaf_rearm(run, event_state):
    event_state.ctx = event_state.native_ctx
    event_state.state = run.phase53_descriptor_bind_state
    event_state.observation = dict(pc=hex(event_state.ctx.elr), caller_sp=hex(int(event_state.ctx.sp[0])), expected_parent_sp=hex(event_state.state['parent_sp']))
    event_state.checks = {'expected_pc': event_state.ctx.elr == run.FC_XNU_PHASE53_LEAF_MAP_CALL, 'caller_mode_el1t': int(event_state.ctx.spsr) & 15 == 4, 'different_parent_sp': int(event_state.ctx.sp[0]) + 144 != event_state.state['parent_sp']}
    try:
        event_state.roots = event_state.state['roots']

        def read_leaf_rearm_page(table):
            if table & run.PAGE - 1 or not run.base <= table < table + run.PAGE <= run.base + run.guest_size:
                raise ValueError('Phase53 leaf-rearm table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)
        event_state.leaf = run.translate(event_state.ctx.elr, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_leaf_rearm_page)
        event_state.live = run.iface.readmem(event_state.leaf['pa'], 4)
        event_state.kernel_segment = run.layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        event_state.offset = event_state.kernel_segment['fileoff'] + run.FC_XNU_PHASE53_LEAF_MAP_CALL_LINKED - event_state.kernel_segment['va']
        event_state.source = run.sources['kernelcache'][event_state.offset:event_state.offset + 4]
        event_state.expected = run.struct.pack('<I', run.FC_XNU_PHASE53_LEAF_MAP_CALL_WORD)
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.aggregate_steps = event_state.state['aggregate_steps'] + event_state.fast_status['steps']
        event_state.checks.update(source_word=event_state.source == event_state.expected, live_word=event_state.live == event_state.expected and event_state.live == event_state.source, level_three=event_state.leaf['level'] == 3, access_flag=event_state.leaf['access_flag'], filter_stopped=not event_state.fast_status['active'] and event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_TERMINAL, filter_last_pc=event_state.fast_status['last_pc'] == event_state.ctx.elr, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_LEAF_MAP_PREP[-1][0], filter_bounded=0 < event_state.fast_status['steps'] <= event_state.state['max_steps'], filter_contract=event_state.fast_status['first_pc'] == event_state.state['segment_start'] and event_state.fast_status['expected_first_pc'] == event_state.state['segment_start'] and (event_state.fast_status['range0_hits'] + event_state.fast_status['range1_hits'] == event_state.fast_status['steps']) and (event_state.fast_status['range0_start'] == event_state.state['range0'][0]) and (event_state.fast_status['range0_end'] == event_state.state['range0'][1]) and (event_state.fast_status['range1_start'] == run.FC_SPTM_RUNTIME_TEXT[0]) and (event_state.fast_status['range1_end'] == run.FC_SPTM_RUNTIME_TEXT[1]) and (event_state.fast_status['terminal_pc'] == event_state.ctx.elr) and (event_state.fast_status['max_steps'] == event_state.state['max_steps']), aggregate_budget=event_state.aggregate_steps <= event_state.state['aggregate_limit'], rearm_budget=event_state.state['rearms'] < event_state.state['rearm_limit'])
        event_state.observation.update(pa=hex(event_state.leaf['pa']), source_hex=event_state.source.hex(), live_hex=event_state.live.hex(), filter_status=event_state.fast_status, aggregate_steps=event_state.aggregate_steps, checks=event_state.checks, complete=all(event_state.checks.values()))
        if event_state.observation['complete']:
            event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, run.FC_XNU_PHASE53_LEAF_MAP_CALL, event_state.state['max_steps'], event_state.ctx.elr)
            event_state.state.update(range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.ctx.elr, aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'] + 1)
            event_state.observation['next_enable_status'] = event_state.enabled_status
            run.report['xnu_phase53_leaf_page_bind'].setdefault('unrelated_candidates', []).append(event_state.observation)
            run.report['xnu_phase53_leaf_page_bind'].update(aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'])
            event_state.event.update(kind='phase53-leaf-page-bind-unrelated', pc=event_state.ctx.elr, checks=event_state.checks)
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        else:
            event_state.state['active'] = False
            run.report['xnu_phase53_leaf_page_bind']['rejection'] = event_state.observation
            run.report['stop_reason'] = 'phase53-leaf-page-bind-unrelated-gate-rejected'
    except Exception as leaf_rearm_error:
        event_state.checks['gate_readback'] = False
        event_state.observation.update(checks=event_state.checks, complete=False, error=str(leaf_rearm_error))
        event_state.state['active'] = False
        run.report['xnu_phase53_leaf_page_bind']['rejection'] = event_state.observation
        run.report['stop_reason'] = 'phase53-leaf-page-bind-unrelated-gate-rejected'

def handle_step(run, event_state):
    event_state.ctx = event_state.native_ctx if run.handoff_state.get('native') else run.iface.readstruct(event_state.info, run.ExcInfo)
    event_state.state = run.phase53_descriptor_bind_state
    event_state.stage_name = event_state.state['stage']
    event_state.specs = {'twig-branch': (run.FC_XNU_PHASE53_TWIG_BRANCH, run.FC_XNU_PHASE53_TWIG_BRANCH_LINKED, run.FC_XNU_PHASE53_TWIG_BRANCH_WORD), 'kernel-branch': (run.FC_XNU_PHASE53_KERNEL_BRANCH, run.FC_XNU_PHASE53_KERNEL_BRANCH_LINKED, run.FC_XNU_PHASE53_KERNEL_BRANCH_WORD), 'rozone-end-branch': (run.FC_XNU_PHASE53_ROZONE_END_BRANCH, run.FC_XNU_PHASE53_ROZONE_END_BRANCH_LINKED, run.FC_XNU_PHASE53_ROZONE_END_BRANCH_WORD), 'rozone-start-branch': (run.FC_XNU_PHASE53_ROZONE_START_BRANCH, run.FC_XNU_PHASE53_ROZONE_START_BRANCH_LINKED, run.FC_XNU_PHASE53_ROZONE_START_BRANCH_WORD), 'rozone-retype1-call': (run.FC_XNU_PHASE53_ROZONE_RETYPE1_CALL, run.FC_XNU_PHASE53_ROZONE_RETYPE1_CALL_LINKED, run.FC_XNU_PHASE53_ROZONE_RETYPE1_CALL_WORD), 'rozone-retype1-return': (run.FC_XNU_PHASE53_ROZONE_RETYPE1_RETURN, run.FC_XNU_PHASE53_ROZONE_RETYPE1_RETURN_LINKED, run.FC_XNU_PHASE53_ROZONE_RETYPE1_RETURN_WORD), 'rozone-retype2-call': (run.FC_XNU_PHASE53_ROZONE_RETYPE2_CALL, run.FC_XNU_PHASE53_ROZONE_RETYPE2_CALL_LINKED, run.FC_XNU_PHASE53_ROZONE_RETYPE2_CALL_WORD), 'rozone-retype2-return': (run.FC_XNU_PHASE53_ROZONE_RETYPE2_RETURN, run.FC_XNU_PHASE53_ROZONE_RETYPE2_RETURN_LINKED, run.FC_XNU_PHASE53_ROZONE_RETYPE2_RETURN_WORD), 'pre-map-call': (run.FC_XNU_PHASE53_PRE_MAP_CALL, run.FC_XNU_PHASE53_PRE_MAP_CALL_LINKED, run.FC_XNU_PHASE53_PRE_MAP_CALL_WORD), 'wrapper-entry': (run.FC_XNU_PHASE53_MAP_WRAPPER_ENTRY, run.FC_XNU_PHASE53_MAP_WRAPPER_ENTRY_LINKED, run.FC_XNU_PHASE53_MAP_WRAPPER_ENTRY_WORD), 'genter': (run.FC_XNU_PHASE53_MAP_GENTER, run.FC_XNU_PHASE53_MAP_GENTER_LINKED, run.FC_XNU_PHASE53_MAP_GENTER_WORD), 'genter-return': (run.FC_XNU_PHASE53_MAP_GENTER_RETURN, run.FC_XNU_PHASE53_MAP_GENTER_RETURN_LINKED, run.FC_XNU_PHASE53_MAP_GENTER_RETURN_WORD), 'wrapper-retab': (run.FC_XNU_PHASE53_MAP_WRAPPER_RETAB, run.FC_XNU_PHASE53_MAP_WRAPPER_RETAB_LINKED, run.FC_XNU_PHASE53_MAP_WRAPPER_RETAB_WORD), 'caller-return': (run.FC_XNU_PHASE53_MAP_CALLER_RETURN, run.FC_XNU_PHASE53_MAP_CALLER_RETURN_LINKED, run.FC_XNU_PHASE53_MAP_CALLER_RETURN_WORD), 'leaf-map-call': (run.FC_XNU_PHASE53_LEAF_MAP_CALL, run.FC_XNU_PHASE53_LEAF_MAP_CALL_LINKED, run.FC_XNU_PHASE53_LEAF_MAP_CALL_WORD), 'leaf-wrapper-entry': (run.FC_XNU_PHASE53_LEAF_WRAPPER_ENTRY, run.FC_XNU_PHASE53_LEAF_WRAPPER_ENTRY_LINKED, run.FC_XNU_PHASE53_LEAF_WRAPPER_ENTRY_WORD), 'leaf-genter': (run.FC_XNU_PHASE53_LEAF_GENTER, run.FC_XNU_PHASE53_LEAF_GENTER_LINKED, run.FC_XNU_PHASE53_LEAF_GENTER_WORD), 'leaf-genter-return': (run.FC_XNU_PHASE53_LEAF_GENTER_RETURN, run.FC_XNU_PHASE53_LEAF_GENTER_RETURN_LINKED, run.FC_XNU_PHASE53_LEAF_GENTER_RETURN_WORD), 'leaf-wrapper-retab': (run.FC_XNU_PHASE53_LEAF_WRAPPER_RETAB, run.FC_XNU_PHASE53_LEAF_WRAPPER_RETAB_LINKED, run.FC_XNU_PHASE53_LEAF_WRAPPER_RETAB_WORD), 'leaf-caller-return': (run.FC_XNU_PHASE53_LEAF_CALLER_RETURN, run.FC_XNU_PHASE53_LEAF_CALLER_RETURN_LINKED, run.FC_XNU_PHASE53_LEAF_CALLER_RETURN_WORD)}
    event_state.expected_pc, event_state.linked_pc, event_state.expected_word = event_state.specs[event_state.stage_name]
    event_state.checks = {'expected_pc': event_state.ctx.elr == event_state.expected_pc}
    event_state.stage_record = dict(stage=event_state.stage_name, pc=hex(event_state.ctx.elr))
    try:
        event_state.roots = event_state.state['roots']

        def read_descriptor_bind_page(table):
            if table & run.PAGE - 1 or not run.base <= table < table + run.PAGE <= run.base + run.guest_size:
                raise ValueError('Phase53 descriptor-bind table outside owned RAM')
            return run.iface.readmem(table, run.PAGE)

        def read_descriptor_bind_u64(va):
            leaf = run.translate(va, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_descriptor_bind_page)
            raw = run.iface.readmem(leaf['pa'], 8)
            if len(raw) != 8:
                raise ValueError('Phase53 descriptor-bind read was truncated')
            return (run.struct.unpack('<Q', raw)[0], leaf, raw)

        def active_descriptor_bind_sp(context):
            mode = int(context.spsr) & 15
            if mode != 4:
                raise ValueError('Phase53 descriptor-bind caller is not EL1t')
            return int(context.sp[0])

        def compute_l2_slot(root, va):
            l1_index = va >> 36 & 2047
            l1_raw = read_descriptor_bind_page(root)
            l1_desc = run.struct.unpack_from('<Q', l1_raw, l1_index * 8)[0]
            l2_table = l1_desc & (1 << 42) - run.PAGE
            return dict(root=hex(root), l1_index=l1_index, l1_descriptor=l1_desc, l1_valid_table=l1_desc & 3 == 3, l2_table_pa=l2_table, l2_index=va >> 25 & 2047, slot_pa=l2_table + (va >> 25 & 2047) * 8)

        def capture_descriptor_bind_fte(physical_address):
            pointer, pointer_leaf, pointer_raw = read_descriptor_bind_u64(run.FC_SPTM_PHASE53_FTE_BASE_POINTER)
            center_va = pointer + (physical_address - run.base >> 10 & 18014398509481968)
            records = []
            for delta in (-16, 0, 16):
                leaf = run.translate(center_va + delta, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_descriptor_bind_page)
                raw = run.iface.readmem(leaf['pa'], 16)
                records.append(dict(delta=delta, va=hex(center_va + delta), pa=hex(leaf['pa']), hex=raw.hex(), sha256=run.hashlib.sha256(raw).hexdigest(), in_flight_ops=run.struct.unpack('<H', raw[:2])[0] if len(raw) == 16 else None, type=raw[2] if len(raw) == 16 else None, complete=len(raw) == 16, level_three=leaf['level'] == 3, access_flag=leaf['access_flag']))
            return dict(base_pointer_va=hex(run.FC_SPTM_PHASE53_FTE_BASE_POINTER), base_pointer_pa=hex(pointer_leaf['pa']), base_pointer_hex=pointer_raw.hex(), pointer_level_three=pointer_leaf['level'] == 3, pointer_access_flag=pointer_leaf['access_flag'], fte_base=hex(pointer), center_va=hex(center_va), records=records)

        def descriptor_bind_fte_checks(now, before, expected_type):
            center = now['records'][1]
            return dict(fte_base_stable=now['fte_base'] == before['fte_base'], fte_center_stable=now['center_va'] == before['center_va'], fte_pointer_level_three=now['pointer_level_three'], fte_pointer_access_flag=now['pointer_access_flag'], fte_records_complete=all((item['complete'] for item in now['records'])), fte_records_level_three=all((item['level_three'] for item in now['records'])), fte_records_access_flag=all((item['access_flag'] for item in now['records'])), fte_center_unlocked=center['in_flight_ops'] == 0, fte_center_type=center['type'] == expected_type, fte_neighbors_unchanged=now['records'][0]['hex'] == before['records'][0]['hex'] and now['records'][2]['hex'] == before['records'][2]['hex'])

        def descriptor_bind_code_checks(prefix, pc, linked, word):
            leaf = run.translate(pc, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_descriptor_bind_page)
            live = run.iface.readmem(leaf['pa'], 4)
            offset = event_state.kernel_segment['fileoff'] + linked - event_state.kernel_segment['va']
            source = run.sources['kernelcache'][offset:offset + 4]
            expected = run.struct.pack('<I', word)
            return ({prefix + '_source': source == expected, prefix + '_live': live == expected and live == source, prefix + '_level_three': leaf['level'] == 3, prefix + '_access_flag': leaf['access_flag']}, dict(pa=hex(leaf['pa']), source_hex=source.hex(), live_hex=live.hex()))

        def descriptor_bind_return_call(prefix, saved_return, call_specs):
            pac_mask = (1 << 40) - 1
            matches = [item for item in call_specs if saved_return & pac_mask in {value & pac_mask for value in item[0]}]
            if len(matches) != 1:
                return ({prefix + '_return': False}, dict(saved_return=hex(saved_return)))
            returns, pc, linked, word = matches[0]
            checks, evidence = descriptor_bind_code_checks(prefix + '_call', pc, linked, word)
            checks[prefix + '_return'] = True
            evidence.update(saved_return=hex(saved_return), allowed_returns=[hex(value) for value in returns])
            return (checks, evidence)
        event_state.fast_status = run.txm_sstep_fast_path.status()
        event_state.code_leaf = run.translate(event_state.ctx.elr, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_descriptor_bind_page)
        event_state.code_live = run.iface.readmem(event_state.code_leaf['pa'], 4)
        event_state.kernel_segment = run.layout['images']['kernelcache']['segments']['__TEXT_EXEC']
        event_state.source_offset = event_state.kernel_segment['fileoff'] + event_state.linked_pc - event_state.kernel_segment['va']
        event_state.source_bytes = run.sources['kernelcache'][event_state.source_offset:event_state.source_offset + 4]
        event_state.expected_code = run.struct.pack('<I', event_state.expected_word)
        event_state.aggregate_steps = event_state.state['aggregate_steps'] + event_state.fast_status['steps']
        event_state.stopped_status = event_state.fast_status['status'] == run.FC_VEL2_STEP_FILTER_TERMINAL
        event_state.checks.update(source_word=event_state.source_bytes == event_state.expected_code, live_word=event_state.code_live == event_state.expected_code and event_state.code_live == event_state.source_bytes, level_three=event_state.code_leaf['level'] == 3, access_flag=event_state.code_leaf['access_flag'], filter_stopped=not event_state.fast_status['active'] and event_state.stopped_status, filter_last_pc=event_state.fast_status['last_pc'] == event_state.expected_pc, filter_bounded=0 < event_state.fast_status['steps'] <= event_state.state['max_steps'], filter_contract=event_state.fast_status['first_pc'] == event_state.state['segment_start'] and event_state.fast_status['expected_first_pc'] == event_state.state['segment_start'] and (event_state.fast_status['range0_hits'] + event_state.fast_status['range1_hits'] == event_state.fast_status['steps']) and (event_state.fast_status['range0_start'] == event_state.state['range0'][0]) and (event_state.fast_status['range0_end'] == event_state.state['range0'][1]) and (event_state.fast_status['range1_start'] == run.FC_SPTM_RUNTIME_TEXT[0]) and (event_state.fast_status['range1_end'] == run.FC_SPTM_RUNTIME_TEXT[1]) and (event_state.fast_status['terminal_pc'] == event_state.expected_pc) and (event_state.fast_status['max_steps'] == event_state.state['max_steps']), aggregate_budget=event_state.aggregate_steps <= event_state.state.get('aggregate_limit', run.FC_XNU_PHASE53_DESCRIPTOR_BIND_TOTAL_STEPS))
        event_state.stage_record.update(source_hex=event_state.source_bytes.hex(), live_hex=event_state.code_live.hex(), pa=hex(event_state.code_leaf['pa']), filter_status=event_state.fast_status, aggregate_steps=event_state.aggregate_steps)
        event_state.next_stage = event_state.next_pc = None
        if event_state.stage_name == 'twig-branch':
            event_state.extra_checks, event_state.evidence = descriptor_bind_code_checks('compare', run.FC_XNU_PHASE53_TWIG_COMPARE, run.FC_XNU_PHASE53_TWIG_COMPARE_LINKED, run.FC_XNU_PHASE53_TWIG_COMPARE_WORD)
            event_state.checks.update(event_state.extra_checks)
            event_state.branch_taken = bool(int(event_state.ctx.spsr) & 1 << 30)
            event_state.checks.update(caller_mode_el1t=int(event_state.ctx.spsr) & 15 == 4, caller_sp=active_descriptor_bind_sp(event_state.ctx) == event_state.state['caller_sp'], filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_TWIG_COMPARE, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.stage_record.update(compare=event_state.evidence, branch_taken=event_state.branch_taken)
            if event_state.branch_taken:
                event_state.next_stage = 'kernel-branch'
                event_state.next_pc = run.FC_XNU_PHASE53_KERNEL_BRANCH
            else:
                event_state.state.update(path='ordinary', expected_fte_type=20, expected_pre_map_fte=event_state.state['target_fte'])
                event_state.next_stage = 'pre-map-call'
                event_state.next_pc = run.FC_XNU_PHASE53_PRE_MAP_CALL
        elif event_state.stage_name == 'kernel-branch':
            event_state.extra_checks, event_state.evidence = descriptor_bind_code_checks('compare', run.FC_XNU_PHASE53_KERNEL_COMPARE, run.FC_XNU_PHASE53_KERNEL_COMPARE_LINKED, run.FC_XNU_PHASE53_KERNEL_COMPARE_WORD)
            event_state.checks.update(event_state.extra_checks)
            event_state.branch_taken = bool(int(event_state.ctx.spsr) & 1 << 30)
            event_state.checks.update(caller_mode_el1t=int(event_state.ctx.spsr) & 15 == 4, caller_sp=active_descriptor_bind_sp(event_state.ctx) == event_state.state['caller_sp'], filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_KERNEL_COMPARE, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.stage_record.update(compare=event_state.evidence, branch_taken=event_state.branch_taken)
            if event_state.branch_taken:
                event_state.next_stage = 'rozone-end-branch'
                event_state.next_pc = run.FC_XNU_PHASE53_ROZONE_END_BRANCH
            else:
                event_state.state.update(path='ordinary', expected_fte_type=20, expected_pre_map_fte=event_state.state['target_fte'])
                event_state.next_stage = 'pre-map-call'
                event_state.next_pc = run.FC_XNU_PHASE53_PRE_MAP_CALL
        elif event_state.stage_name == 'rozone-end-branch':
            event_state.extra_checks, event_state.evidence = descriptor_bind_code_checks('compare', run.FC_XNU_PHASE53_ROZONE_END_COMPARE, run.FC_XNU_PHASE53_ROZONE_END_COMPARE_LINKED, run.FC_XNU_PHASE53_ROZONE_END_COMPARE_WORD)
            event_state.checks.update(event_state.extra_checks)
            event_state.nzcv = int(event_state.ctx.spsr)
            event_state.branch_taken = not bool(event_state.nzcv & 1 << 29) or bool(event_state.nzcv & 1 << 30)
            event_state.checks.update(caller_mode_el1t=int(event_state.ctx.spsr) & 15 == 4, caller_sp=active_descriptor_bind_sp(event_state.ctx) == event_state.state['caller_sp'], filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_ROZONE_END_COMPARE, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.stage_record.update(compare=event_state.evidence, branch_taken=event_state.branch_taken)
            if event_state.branch_taken:
                event_state.state.update(path='ordinary-kernel', expected_fte_type=20, expected_pre_map_fte=event_state.state['target_fte'])
                event_state.next_stage = 'pre-map-call'
                event_state.next_pc = run.FC_XNU_PHASE53_PRE_MAP_CALL
            else:
                event_state.next_stage = 'rozone-start-branch'
                event_state.next_pc = run.FC_XNU_PHASE53_ROZONE_START_BRANCH
        elif event_state.stage_name == 'rozone-start-branch':
            event_state.extra_checks, event_state.evidence = descriptor_bind_code_checks('compare', run.FC_XNU_PHASE53_ROZONE_START_COMPARE, run.FC_XNU_PHASE53_ROZONE_START_COMPARE_LINKED, run.FC_XNU_PHASE53_ROZONE_START_COMPARE_WORD)
            event_state.checks.update(event_state.extra_checks)
            event_state.intermediate_checks, event_state.intermediate_evidence = descriptor_bind_code_checks('intermediate', run.FC_XNU_PHASE53_ROZONE_START_INTERMEDIATE, run.FC_XNU_PHASE53_ROZONE_START_INTERMEDIATE_LINKED, run.FC_XNU_PHASE53_ROZONE_START_INTERMEDIATE_WORD)
            event_state.checks.update(event_state.intermediate_checks)
            event_state.previous_checks, event_state.previous_evidence = descriptor_bind_code_checks('previous', run.FC_XNU_PHASE53_ROZONE_START_PREVIOUS, run.FC_XNU_PHASE53_ROZONE_START_PREVIOUS_LINKED, run.FC_XNU_PHASE53_ROZONE_START_PREVIOUS_WORD)
            event_state.checks.update(event_state.previous_checks)
            event_state.branch_taken = bool(int(event_state.ctx.spsr) & 1 << 29)
            event_state.checks.update(caller_mode_el1t=int(event_state.ctx.spsr) & 15 == 4, caller_sp=active_descriptor_bind_sp(event_state.ctx) == event_state.state['caller_sp'], filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_ROZONE_START_PREVIOUS, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.stage_record.update(compare=event_state.evidence, intermediate=event_state.intermediate_evidence, previous=event_state.previous_evidence, branch_taken=event_state.branch_taken)
            if event_state.branch_taken:
                event_state.state.update(path='ordinary-kernel', expected_fte_type=20, expected_pre_map_fte=event_state.state['target_fte'])
                event_state.next_stage = 'pre-map-call'
                event_state.next_pc = run.FC_XNU_PHASE53_PRE_MAP_CALL
            else:
                event_state.state['path'] = 'rozone'
                event_state.next_stage = 'rozone-retype1-call'
                event_state.next_pc = run.FC_XNU_PHASE53_ROZONE_RETYPE1_CALL
        elif event_state.stage_name == 'rozone-retype1-call':
            event_state.args = tuple((int(event_state.ctx.regs[index]) for index in range(4)))
            event_state.fte_now = capture_descriptor_bind_fte(event_state.state['target_pa'])
            event_state.checks.update(descriptor_bind_fte_checks(event_state.fte_now, event_state.state['target_fte'], 20))
            event_state.checks.update(args=event_state.args == (event_state.state['target_pa'], 20, 11, 0), fte_center_unchanged=event_state.fte_now['records'][1]['hex'] == event_state.state['target_fte']['records'][1]['hex'], filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_ROZONE_RETYPE1_CALL - 4, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.state['rozone_retype1_before'] = event_state.fte_now
            event_state.stage_record.update(args=[hex(value) for value in event_state.args], frame_table=event_state.fte_now)
            event_state.next_stage = 'rozone-retype1-return'
            event_state.next_pc = run.FC_XNU_PHASE53_ROZONE_RETYPE1_RETURN
        elif event_state.stage_name == 'rozone-retype1-return':
            event_state.fte_now = capture_descriptor_bind_fte(event_state.state['target_pa'])
            event_state.checks.update(descriptor_bind_fte_checks(event_state.fte_now, event_state.state['target_fte'], 11))
            event_state.expected_center = bytes((0, 0, 11)) + bytes(13)
            event_state.checks.update(restored_caller=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_ROZONE_RETYPE1_RETURN & (1 << 40) - 1, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB, fte_center_exact=bytes.fromhex(event_state.fte_now['records'][1]['hex']) == event_state.expected_center, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.state['rozone_default_fte'] = event_state.fte_now
            event_state.stage_record['frame_table'] = event_state.fte_now
            event_state.next_stage = 'rozone-retype2-call'
            event_state.next_pc = run.FC_XNU_PHASE53_ROZONE_RETYPE2_CALL
        elif event_state.stage_name == 'rozone-retype2-call':
            event_state.args = tuple((int(event_state.ctx.regs[index]) for index in range(4)))
            event_state.fte_now = capture_descriptor_bind_fte(event_state.state['target_pa'])
            event_state.checks.update(descriptor_bind_fte_checks(event_state.fte_now, event_state.state['rozone_default_fte'], 11))
            event_state.checks.update(args=event_state.args == (event_state.state['target_pa'], 11, 22, 3), fte_center_unchanged=event_state.fte_now['records'][1]['hex'] == event_state.state['rozone_default_fte']['records'][1]['hex'], filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_ROZONE_RETYPE2_CALL - 4, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.stage_record.update(args=[hex(value) for value in event_state.args], frame_table=event_state.fte_now)
            event_state.next_stage = 'rozone-retype2-return'
            event_state.next_pc = run.FC_XNU_PHASE53_ROZONE_RETYPE2_RETURN
        elif event_state.stage_name == 'rozone-retype2-return':
            event_state.fte_now = capture_descriptor_bind_fte(event_state.state['target_pa'])
            event_state.checks.update(descriptor_bind_fte_checks(event_state.fte_now, event_state.state['target_fte'], 22))
            event_state.expected_center = bytes((0, 0, 22, 0)) + run.struct.pack('<H', 3) + bytes(10)
            event_state.checks.update(restored_caller=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_ROZONE_RETYPE2_RETURN & (1 << 40) - 1, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB, fte_center_exact=bytes.fromhex(event_state.fte_now['records'][1]['hex']) == event_state.expected_center, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.state.update(expected_fte_type=22, expected_pre_map_fte=event_state.fte_now)
            event_state.stage_record['frame_table'] = event_state.fte_now
            event_state.next_stage = 'pre-map-call'
            event_state.next_pc = run.FC_XNU_PHASE53_PRE_MAP_CALL
        elif event_state.stage_name == 'pre-map-call':
            event_state.checks['caller_mode_el1t'] = int(event_state.ctx.spsr) & 15 == 4
            event_state.active_sp = active_descriptor_bind_sp(event_state.ctx)
            event_state.ttep_kva, event_state.ttep_stack_leaf, event_state.ttep_stack_raw = read_descriptor_bind_u64(event_state.active_sp + 88)
            event_state.target_va, event_state.va_stack_leaf, event_state.va_stack_raw = read_descriptor_bind_u64(event_state.active_sp + 72)
            event_state.old_descriptor, event_state.slot_leaf, event_state.slot_raw = read_descriptor_bind_u64(event_state.ttep_kva)
            event_state.args = tuple((int(event_state.ctx.regs[index]) for index in range(4)))
            event_state.computed = compute_l2_slot(event_state.args[0], event_state.target_va)
            event_state.expected_descriptor = event_state.state['target_pa'] | 3
            event_state.fte_now = capture_descriptor_bind_fte(event_state.state['target_pa'])
            event_state.fte_center = event_state.fte_now['records'][1]
            event_state.fte_before = event_state.state['expected_pre_map_fte']
            event_state.checks.update(caller_sp=event_state.active_sp == event_state.state['caller_sp'], stack_ttep_level_three=event_state.ttep_stack_leaf['level'] == 3, stack_ttep_access_flag=event_state.ttep_stack_leaf['access_flag'], stack_va_level_three=event_state.va_stack_leaf['level'] == 3, stack_va_access_flag=event_state.va_stack_leaf['access_flag'], slot_level_three=event_state.slot_leaf['level'] == 3, slot_access_flag=event_state.slot_leaf['access_flag'], root=event_state.args[0] == event_state.roots['ttbr1'], mapping_va=event_state.args[1] == event_state.target_va, mapping_va_canonical=event_state.target_va >> 47 == (1 << 17) - 1, mapping_va_page_aligned=event_state.target_va & run.PAGE - 1 == 0, level=event_state.args[2] == 2, new_tte=event_state.args[3] == event_state.expected_descriptor, l1_valid_table=event_state.computed['l1_valid_table'], l1_address_42bit=event_state.computed['l1_descriptor'] & ((1 << 48) - 1 ^ (1 << 42) - 1) == 0, l2_table_owned=run.base <= event_state.computed['l2_table_pa'] < event_state.computed['l2_table_pa'] + run.PAGE <= run.base + run.guest_size, slot_owned=run.base <= event_state.slot_leaf['pa'] < event_state.slot_leaf['pa'] + 8 <= run.base + run.guest_size, computed_slot=event_state.computed['slot_pa'] == event_state.slot_leaf['pa'], old_not_valid_table=event_state.old_descriptor & 3 != 3, fte_base_stable=event_state.fte_now['fte_base'] == event_state.fte_before['fte_base'], fte_center_stable=event_state.fte_now['center_va'] == event_state.fte_before['center_va'], fte_pointer_level_three=event_state.fte_now['pointer_level_three'], fte_pointer_access_flag=event_state.fte_now['pointer_access_flag'], fte_records_complete=all((item['complete'] for item in event_state.fte_now['records'])), fte_records_level_three=all((item['level_three'] for item in event_state.fte_now['records'])), fte_records_access_flag=all((item['access_flag'] for item in event_state.fte_now['records'])), fte_center_unlocked=event_state.fte_center['in_flight_ops'] == 0, fte_center_type=event_state.fte_center['type'] == event_state.state['expected_fte_type'], fte_center_unchanged=event_state.fte_center['hex'] == event_state.fte_before['records'][1]['hex'], rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.state.update(ttep_kva=event_state.ttep_kva, target_va=event_state.target_va, slot_pa=event_state.slot_leaf['pa'], old_descriptor=event_state.old_descriptor, expected_descriptor=event_state.expected_descriptor, pre_map_fte=event_state.fte_now, map_args=event_state.args)
            event_state.stage_record.update(caller_sp=hex(event_state.active_sp), ttep_kva=hex(event_state.ttep_kva), target_va=hex(event_state.target_va), slot_pa=hex(event_state.slot_leaf['pa']), old_descriptor=hex(event_state.old_descriptor), expected_descriptor=hex(event_state.expected_descriptor), stack_ttep_hex=event_state.ttep_stack_raw.hex(), stack_va_hex=event_state.va_stack_raw.hex(), slot_hex=event_state.slot_raw.hex(), l2=event_state.computed, frame_table=event_state.fte_now)
            event_state.next_stage = 'wrapper-entry'
            event_state.next_pc = run.FC_XNU_PHASE53_MAP_WRAPPER_ENTRY
        elif event_state.stage_name == 'wrapper-entry':
            event_state.checks['caller_mode_el1t'] = int(event_state.ctx.spsr) & 15 == 4
            event_state.active_sp = active_descriptor_bind_sp(event_state.ctx)
            event_state.checks.update(caller_sp=event_state.active_sp == event_state.state['caller_sp'], args_unchanged=tuple((int(event_state.ctx.regs[index]) for index in range(4))) == event_state.state['map_args'], restored_caller=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_MAP_CALLER_RETURN & (1 << 40) - 1, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_PRE_MAP_CALL, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.next_stage = 'genter'
            event_state.next_pc = run.FC_XNU_PHASE53_MAP_GENTER
        elif event_state.stage_name == 'genter':
            event_state.selector_leaf = run.translate(run.FC_XNU_PHASE53_MAP_SELECTOR, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_descriptor_bind_page)
            event_state.selector_live = run.iface.readmem(event_state.selector_leaf['pa'], 4)
            event_state.selector_offset = event_state.kernel_segment['fileoff'] + run.FC_XNU_PHASE53_MAP_SELECTOR_LINKED - event_state.kernel_segment['va']
            event_state.selector_source = run.sources['kernelcache'][event_state.selector_offset:event_state.selector_offset + 4]
            event_state.expected_selector = run.struct.pack('<I', run.FC_XNU_PHASE53_MAP_SELECTOR_WORD)
            event_state.checks.update(selector_source=event_state.selector_source == event_state.expected_selector, selector_live=event_state.selector_live == event_state.expected_selector and event_state.selector_live == event_state.selector_source, selector_level_three=event_state.selector_leaf['level'] == 3, selector_access_flag=event_state.selector_leaf['access_flag'], selector=int(event_state.ctx.regs[16]) == 3, args_unchanged=tuple((int(event_state.ctx.regs[index]) for index in range(4))) == event_state.state['map_args'], filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_MAP_SELECTOR, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.stage_record.update(selector_source_hex=event_state.selector_source.hex(), selector_live_hex=event_state.selector_live.hex())
            event_state.next_stage = 'genter-return'
            event_state.next_pc = run.FC_XNU_PHASE53_MAP_GENTER_RETURN
        elif event_state.stage_name == 'genter-return':
            event_state.sptm_segment = run.layout['images']['sptm']['segments']['__TEXT_EXEC']
            event_state.code_specs = (('selector', run.FC_XNU_PHASE53_MAP_SELECTOR, run.FC_XNU_PHASE53_MAP_SELECTOR_LINKED, run.FC_XNU_PHASE53_MAP_SELECTOR_WORD, event_state.kernel_segment, run.sources['kernelcache']), ('genter', run.FC_XNU_PHASE53_MAP_GENTER, run.FC_XNU_PHASE53_MAP_GENTER_LINKED, run.FC_XNU_PHASE53_MAP_GENTER_WORD, event_state.kernel_segment, run.sources['kernelcache']), ('gexit', run.FC_XNU_PHASE53_GEXIT, run.FC_XNU_PHASE53_GEXIT_LINKED, run.FC_XNU_PHASE53_GEXIT_WORD, event_state.sptm_segment, run.sources['sptm']), ('return', run.FC_XNU_PHASE53_MAP_GENTER_RETURN, run.FC_XNU_PHASE53_MAP_GENTER_RETURN_LINKED, run.FC_XNU_PHASE53_MAP_GENTER_RETURN_WORD, event_state.kernel_segment, run.sources['kernelcache']))
            event_state.evidence = {}
            for event_state.name, event_state.pc, event_state.linked, event_state.word, event_state.segment, event_state.source in event_state.code_specs:
                event_state.leaf = run.translate(event_state.pc, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_descriptor_bind_page)
                event_state.live = run.iface.readmem(event_state.leaf['pa'], 4)
                event_state.offset = event_state.segment['fileoff'] + event_state.linked - event_state.segment['va']
                event_state.pinned = event_state.source[event_state.offset:event_state.offset + 4]
                event_state.expected = run.struct.pack('<I', event_state.word)
                event_state.checks[event_state.name + '_source'] = event_state.pinned == event_state.expected
                event_state.checks[event_state.name + '_live'] = event_state.live == event_state.expected and event_state.live == event_state.pinned
                event_state.checks[event_state.name + '_level_three'] = event_state.leaf['level'] == 3
                event_state.checks[event_state.name + '_access_flag'] = event_state.leaf['access_flag']
                event_state.evidence[event_state.name] = dict(pa=hex(event_state.leaf['pa']), source_hex=event_state.pinned.hex(), live_hex=event_state.live.hex())
            event_state.checks.update(exact_spsr=int(event_state.ctx.spsr) == run.FC_XNU_PHASE53_GENTER_RETURN_SPSR, wrapper_link=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_MAP_SELECTOR & (1 << 40) - 1, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_GEXIT, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.stage_record['code'] = event_state.evidence
            event_state.next_stage = 'wrapper-retab'
            event_state.next_pc = run.FC_XNU_PHASE53_MAP_WRAPPER_RETAB
        elif event_state.stage_name == 'wrapper-retab':
            event_state.checks.update(restored_caller=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_MAP_CALLER_RETURN & (1 << 40) - 1, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_MAP_WRAPPER_RETAB_PREVIOUS, rearm_budget=event_state.state['rearms'] < run.FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS)
            event_state.next_stage = 'caller-return'
            event_state.next_pc = run.FC_XNU_PHASE53_MAP_CALLER_RETURN
        elif event_state.stage_name == 'caller-return':
            event_state.checks['caller_mode_el1t'] = int(event_state.ctx.spsr) & 15 == 4
            event_state.active_sp = active_descriptor_bind_sp(event_state.ctx)
            event_state.ttep_kva, event_state.ttep_stack_leaf, event_state.ttep_stack_raw = read_descriptor_bind_u64(event_state.active_sp + 88)
            event_state.target_va, event_state.va_stack_leaf, event_state.va_stack_raw = read_descriptor_bind_u64(event_state.active_sp + 72)
            event_state.descriptor, event_state.slot_leaf, event_state.slot_raw = read_descriptor_bind_u64(event_state.ttep_kva)
            event_state.provenance_checks = {}
            event_state.provenance_record = {}
            event_state.provenance_state = {}
            if run.a.xnu_phase53_leaf_page_bind:
                event_state.saved_leaf_va, event_state.saved_leaf_leaf, event_state.saved_leaf_raw = read_descriptor_bind_u64(event_state.active_sp + 280)
                event_state.saved_pmap, event_state.saved_pmap_leaf, event_state.saved_pmap_raw = read_descriptor_bind_u64(event_state.active_sp + 344)
                event_state.saved_parent_lr, event_state.saved_lr_leaf, event_state.saved_lr_raw = read_descriptor_bind_u64(event_state.active_sp + 360)
                event_state.pmap_root, event_state.pmap_root_leaf, event_state.pmap_root_raw = read_descriptor_bind_u64(event_state.saved_pmap + 8)
                event_state.pac_mask = (1 << 40) - 1
                event_state.parent_call_checks, event_state.parent_call_evidence = descriptor_bind_return_call('parent', event_state.saved_parent_lr, run.FC_XNU_PHASE53_EXPAND_PARENT_CALLS)
                event_state.provenance_checks.update(saved_leaf_va_canonical=event_state.saved_leaf_va >> 47 in (0, 131071), saved_leaf_va_page_aligned=event_state.saved_leaf_va & run.PAGE - 1 == 0, saved_leaf_same_l1=event_state.saved_leaf_va >> 36 & 2047 == event_state.target_va >> 36 & 2047, saved_leaf_same_l2=event_state.saved_leaf_va >> 25 & 2047 == event_state.target_va >> 25 & 2047, saved_parent_lr=event_state.saved_parent_lr & event_state.pac_mask in {value & event_state.pac_mask for value in run.FC_XNU_PHASE53_EXPAND_PARENT_RETURNS}, pmap_root_same=event_state.pmap_root == event_state.state['map_args'][0], saved_leaf_level_three=event_state.saved_leaf_leaf['level'] == 3, saved_leaf_access_flag=event_state.saved_leaf_leaf['access_flag'], saved_pmap_level_three=event_state.saved_pmap_leaf['level'] == 3, saved_pmap_access_flag=event_state.saved_pmap_leaf['access_flag'], saved_lr_level_three=event_state.saved_lr_leaf['level'] == 3, saved_lr_access_flag=event_state.saved_lr_leaf['access_flag'], pmap_root_level_three=event_state.pmap_root_leaf['level'] == 3, pmap_root_access_flag=event_state.pmap_root_leaf['access_flag'])
                event_state.provenance_checks.update(event_state.parent_call_checks)
                event_state.provenance_record.update(saved_leaf_va=hex(event_state.saved_leaf_va), saved_leaf_hex=event_state.saved_leaf_raw.hex(), saved_pmap=hex(event_state.saved_pmap), saved_pmap_hex=event_state.saved_pmap_raw.hex(), saved_parent_lr=hex(event_state.saved_parent_lr), saved_parent_lr_hex=event_state.saved_lr_raw.hex(), pmap_root=hex(event_state.pmap_root), pmap_root_hex=event_state.pmap_root_raw.hex(), parent_call=event_state.parent_call_evidence)
                event_state.provenance_state.update(parent_sp=event_state.active_sp + 368, parent_leaf_va=event_state.saved_leaf_va, parent_pmap=event_state.saved_pmap, parent_lr=event_state.saved_parent_lr)
            event_state.computed = compute_l2_slot(event_state.state['map_args'][0], event_state.target_va)
            event_state.fte_after = capture_descriptor_bind_fte(event_state.state['target_pa'])
            event_state.state['pre_map_fte_after'] = event_state.fte_after
            event_state.center = event_state.fte_after['records'][1]
            event_state.before_fte = event_state.state['pre_map_fte']
            event_state.pre_map_center = bytes.fromhex(event_state.state['pre_map_fte']['records'][1]['hex'])
            event_state.after_center = bytes.fromhex(event_state.center['hex'])
            event_state.checks.update(status_success=int(event_state.ctx.regs[0]) == 0, caller_sp=event_state.active_sp == event_state.state['caller_sp'], same_ttep=event_state.ttep_kva == event_state.state['ttep_kva'], same_target_va=event_state.target_va == event_state.state['target_va'], same_slot=event_state.slot_leaf['pa'] == event_state.state['slot_pa'], descriptor=event_state.descriptor == event_state.state['expected_descriptor'], l1_valid_table=event_state.computed['l1_valid_table'], l1_address_42bit=event_state.computed['l1_descriptor'] & ((1 << 48) - 1 ^ (1 << 42) - 1) == 0, l2_table_owned=run.base <= event_state.computed['l2_table_pa'] < event_state.computed['l2_table_pa'] + run.PAGE <= run.base + run.guest_size, slot_owned=run.base <= event_state.slot_leaf['pa'] < event_state.slot_leaf['pa'] + 8 <= run.base + run.guest_size, computed_slot=event_state.computed['slot_pa'] == event_state.slot_leaf['pa'], stack_ttep_level_three=event_state.ttep_stack_leaf['level'] == 3, stack_ttep_access_flag=event_state.ttep_stack_leaf['access_flag'], stack_va_level_three=event_state.va_stack_leaf['level'] == 3, stack_va_access_flag=event_state.va_stack_leaf['access_flag'], slot_level_three=event_state.slot_leaf['level'] == 3, slot_access_flag=event_state.slot_leaf['access_flag'], fte_base_stable=event_state.fte_after['fte_base'] == event_state.before_fte['fte_base'], fte_center_stable=event_state.fte_after['center_va'] == event_state.before_fte['center_va'], fte_pointer_level_three=event_state.fte_after['pointer_level_three'], fte_pointer_access_flag=event_state.fte_after['pointer_access_flag'], fte_records_complete=all((item['complete'] for item in event_state.fte_after['records'])), fte_records_level_three=all((item['level_three'] for item in event_state.fte_after['records'])), fte_records_access_flag=all((item['access_flag'] for item in event_state.fte_after['records'])), fte_center_unlocked=event_state.center['in_flight_ops'] == 0, fte_center_type=event_state.center['type'] == event_state.state['expected_fte_type'], fte_generic_fields_stable=event_state.after_center[:3] == event_state.pre_map_center[:3], fte_neighbors_unchanged=event_state.fte_after['records'][0]['hex'] == event_state.before_fte['records'][0]['hex'] and event_state.fte_after['records'][2]['hex'] == event_state.before_fte['records'][2]['hex'], restored_caller=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_MAP_CALLER_RETURN & (1 << 40) - 1, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_MAP_WRAPPER_RETAB)
            event_state.checks.update(event_state.provenance_checks)
            event_state.stage_record.update(caller_sp=hex(event_state.active_sp), ttep_kva=hex(event_state.ttep_kva), target_va=hex(event_state.target_va), slot_pa=hex(event_state.slot_leaf['pa']), descriptor=hex(event_state.descriptor), slot_hex=event_state.slot_raw.hex(), stack_ttep_hex=event_state.ttep_stack_raw.hex(), stack_va_hex=event_state.va_stack_raw.hex(), l2=event_state.computed, frame_table_after=event_state.fte_after, fte_center_changed_offsets=[index for index, (old, new) in enumerate(zip(event_state.pre_map_center, event_state.after_center)) if old != new])
            event_state.stage_record.update(event_state.provenance_record)
            event_state.state.update(event_state.provenance_state)
        elif event_state.stage_name == 'leaf-map-call':
            event_state.args = tuple((int(event_state.ctx.regs[index]) for index in range(4)))
            event_state.root, event_state.mapping_va, event_state.leaf_descriptor, event_state.flags = event_state.args
            event_state.active_sp = active_descriptor_bind_sp(event_state.ctx)
            event_state.leaf_parent_lr, event_state.leaf_lr_leaf, event_state.leaf_lr_raw = read_descriptor_bind_u64(event_state.active_sp + 136)
            event_state.pac_mask = (1 << 40) - 1
            event_state.leaf_parent_call_checks, event_state.leaf_parent_call_evidence = descriptor_bind_return_call('leaf_parent', event_state.leaf_parent_lr, run.FC_XNU_PHASE53_LEAF_PARENT_CALLS)
            event_state.prior_l2_raw = run.iface.readmem(event_state.state['slot_pa'], 8)
            event_state.prior_l2 = run.struct.unpack('<Q', event_state.prior_l2_raw)[0]
            event_state.computed_l2 = compute_l2_slot(event_state.root, event_state.mapping_va)
            event_state.l3_index = event_state.mapping_va >> 14 & 2047
            event_state.l3_slot_pa = event_state.state['target_pa'] + event_state.l3_index * 8
            event_state.l3_before = run.iface.readmem(event_state.state['target_pa'], run.PAGE)
            if len(event_state.l3_before) != run.PAGE:
                raise ValueError('Phase53 L3 table snapshot was truncated')
            event_state.l3_offset = event_state.l3_index * 8
            event_state.l3_old = run.struct.unpack_from('<Q', event_state.l3_before, event_state.l3_offset)[0]
            event_state.output_pa = event_state.leaf_descriptor & (1 << 42) - run.PAGE
            event_state.output_address_checks = dict(leaf_descriptor_valid=event_state.leaf_descriptor & 3 == 3, leaf_output_address_42bit=event_state.leaf_descriptor & ((1 << 48) - 1 ^ (1 << 42) - 1) == 0, leaf_output_nonzero=event_state.output_pa != 0, leaf_output_owned=run.base <= event_state.output_pa < event_state.output_pa + run.PAGE <= run.base + run.guest_size)
            event_state.checks.update(event_state.output_address_checks)
            if not all(event_state.output_address_checks.values()):
                raise ValueError('Phase53 leaf output descriptor is unsafe')
            event_state.fte_now = capture_descriptor_bind_fte(event_state.state['target_pa'])
            event_state.output_fte = capture_descriptor_bind_fte(event_state.output_pa)
            event_state.source_type_arg, event_state.source_type_arg_leaf, event_state.source_type_arg_raw = read_descriptor_bind_u64(event_state.state['parent_sp'] + 128)
            event_state.source_type_checks, event_state.source_type_evidence = descriptor_bind_code_checks('source_type_load', run.FC_XNU_PHASE53_LEAF_SOURCE_TYPE_LOAD, run.FC_XNU_PHASE53_LEAF_SOURCE_TYPE_LOAD_LINKED, run.FC_XNU_PHASE53_LEAF_SOURCE_TYPE_LOAD_WORD)
            event_state.before_fte = event_state.state['pre_map_fte_after']
            event_state.pre_map_center = bytes.fromhex(event_state.state['pre_map_fte']['records'][1]['hex'])
            event_state.fte_center = bytes.fromhex(event_state.fte_now['records'][1]['hex'])
            event_state.output_center_va = int(event_state.output_fte['center_va'], 16)
            event_state.output_neighbor_indexes = [index for index, record in enumerate(event_state.fte_now['records']) if int(record['va'], 16) == event_state.output_center_va]
            event_state.output_neighbor_index = event_state.output_neighbor_indexes[0] if len(event_state.output_neighbor_indexes) == 1 else None
            event_state.before_output = bytes.fromhex(event_state.before_fte['records'][event_state.output_neighbor_index]['hex']) if event_state.output_neighbor_index is not None else b''
            event_state.after_output = bytes.fromhex(event_state.output_fte['records'][1]['hex'])
            event_state.unrelated_records_unchanged = event_state.output_neighbor_index is not None and all((event_state.fte_now['records'][index]['hex'] == event_state.before_fte['records'][index]['hex'] for index in range(3) if index != event_state.output_neighbor_index))
            event_state.output_changed_offsets = [index for index, (old, new) in enumerate(zip(event_state.before_output, event_state.after_output)) if old != new]
            event_state.checks.update(caller_mode_el1t=int(event_state.ctx.spsr) & 15 == 4, frame_parent_sp=event_state.active_sp + 144 == event_state.state['parent_sp'], saved_parent_lr=event_state.leaf_parent_lr & event_state.pac_mask in {value & event_state.pac_mask for value in run.FC_XNU_PHASE53_LEAF_PARENT_RETURNS}, saved_parent_lr_level_three=event_state.leaf_lr_leaf['level'] == 3, saved_parent_lr_access_flag=event_state.leaf_lr_leaf['access_flag'], root_same=event_state.root == event_state.state['map_args'][0], flags_zero=event_state.flags == 0, mapping_va_canonical=event_state.mapping_va >> 47 in (0, 131071), mapping_va_page_aligned=event_state.mapping_va & run.PAGE - 1 == 0, same_l1_index=event_state.mapping_va >> 36 & 2047 == event_state.state['target_va'] >> 36 & 2047, same_l2_index=event_state.mapping_va >> 25 & 2047 == event_state.state['target_va'] >> 25 & 2047, mapping_va_from_parent=event_state.mapping_va == event_state.state['parent_leaf_va'], computed_l1_valid_table=event_state.computed_l2['l1_valid_table'], computed_l2_slot_exact=event_state.computed_l2['slot_pa'] == event_state.state['slot_pa'], l2_descriptor_unchanged=event_state.prior_l2 == event_state.state['expected_descriptor'], l3_table_owned=run.base <= event_state.state['target_pa'] < event_state.state['target_pa'] + run.PAGE <= run.base + run.guest_size, l3_slot_owned=run.base <= event_state.l3_slot_pa < event_state.l3_slot_pa + 8 <= run.base + run.guest_size, l3_slot_empty=event_state.l3_old == 0, l3_slot_not_valid=event_state.l3_old & 3 != 3, l3_table_all_zero=not any(event_state.l3_before), leaf_descriptor_valid=event_state.leaf_descriptor & 3 == 3, leaf_output_address_42bit=event_state.leaf_descriptor & ((1 << 48) - 1 ^ (1 << 42) - 1) == 0, leaf_output_nonzero=event_state.output_pa != 0, leaf_output_owned=run.base <= event_state.output_pa < event_state.output_pa + run.PAGE <= run.base + run.guest_size, fte_center_unlocked=event_state.fte_now['records'][1]['in_flight_ops'] == 0, fte_center_type=event_state.fte_now['records'][1]['type'] == event_state.state['expected_fte_type'], fte_generic_fields_stable=event_state.fte_center[:3] == event_state.pre_map_center[:3], output_fte_positive_neighbor=event_state.output_neighbor_index == 2, output_fte_center_matches_neighbor=event_state.output_neighbor_index is not None and event_state.output_fte['records'][1]['hex'] == event_state.fte_now['records'][event_state.output_neighbor_index]['hex'], output_fte_base_same=event_state.output_fte['fte_base'] == event_state.fte_now['fte_base'], output_fte_base_stable=event_state.output_fte['fte_base'] == event_state.before_fte['fte_base'], output_fte_pointer_level_three=event_state.output_fte['pointer_level_three'], output_fte_pointer_access_flag=event_state.output_fte['pointer_access_flag'], output_fte_records_complete=all((item['complete'] for item in event_state.output_fte['records'])), output_fte_records_level_three=all((item['level_three'] for item in event_state.output_fte['records'])), output_fte_records_access_flag=all((item['access_flag'] for item in event_state.output_fte['records'])), output_fte_unlocked=event_state.output_fte['records'][1]['in_flight_ops'] == 0, output_fte_retype_0b_to_19=len(event_state.before_output) == 16 and run.struct.unpack('<H', event_state.before_output[:2])[0] == 0 and (event_state.before_output[2] == 11) and (event_state.output_fte['records'][1]['type'] == 25), output_fte_only_type_changed=event_state.output_changed_offsets == [2], fte_unrelated_records_unchanged=event_state.unrelated_records_unchanged, source_type_arg_level_three=event_state.source_type_arg_leaf['level'] == 3, source_type_arg_access_flag=event_state.source_type_arg_leaf['access_flag'], filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_LEAF_MAP_PREP[-1][0], rearm_budget=event_state.state['rearms'] < event_state.state['rearm_limit'])
            event_state.checks.update(event_state.leaf_parent_call_checks)
            event_state.checks.update(event_state.source_type_checks)
            event_state.prep_evidence = []
            for event_state.index, (event_state.pc, event_state.linked, event_state.word) in enumerate(run.FC_XNU_PHASE53_LEAF_MAP_PREP):
                event_state.extra, event_state.evidence = descriptor_bind_code_checks('prep' + str(event_state.index), event_state.pc, event_state.linked, event_state.word)
                event_state.checks.update(event_state.extra)
                event_state.prep_evidence.append(event_state.evidence)
            event_state.state.update(leaf_args=event_state.args, leaf_va=event_state.mapping_va, leaf_descriptor=event_state.leaf_descriptor, leaf_output_pa=event_state.output_pa, leaf_slot_pa=event_state.l3_slot_pa, leaf_table_before=event_state.l3_before.hex(), leaf_pre_fte=event_state.fte_now)
            event_state.stage_record.update(args=[hex(value) for value in event_state.args], caller_sp=hex(event_state.active_sp), parent_sp=hex(event_state.state['parent_sp']), saved_parent_lr=hex(event_state.leaf_parent_lr), saved_parent_lr_hex=event_state.leaf_lr_raw.hex(), parent_call=event_state.leaf_parent_call_evidence, output_pa=hex(event_state.output_pa), l3_index=event_state.l3_index, slot_pa=hex(event_state.l3_slot_pa), table_before_sha256=run.hashlib.sha256(event_state.l3_before).hexdigest(), prior_l2_hex=event_state.prior_l2_raw.hex(), l2=event_state.computed_l2, prep=event_state.prep_evidence, frame_table=event_state.fte_now, output_frame_table=event_state.output_fte, output_fte_transition=dict(neighbor_index=event_state.output_neighbor_index, before_hex=event_state.before_output.hex(), after_hex=event_state.after_output.hex(), changed_offsets=event_state.output_changed_offsets), source_type_arg=hex(event_state.source_type_arg & 255), source_type_arg_raw=event_state.source_type_arg_raw.hex(), source_type_load=event_state.source_type_evidence)
            event_state.next_stage = 'leaf-wrapper-entry'
            event_state.next_pc = run.FC_XNU_PHASE53_LEAF_WRAPPER_ENTRY
        elif event_state.stage_name == 'leaf-wrapper-entry':
            event_state.checks.update(caller_mode_el1t=int(event_state.ctx.spsr) & 15 == 4, args_unchanged=tuple((int(event_state.ctx.regs[index]) for index in range(4))) == event_state.state['leaf_args'], restored_caller=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_LEAF_CALLER_RETURN & (1 << 40) - 1, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_LEAF_MAP_CALL, rearm_budget=event_state.state['rearms'] < event_state.state['rearm_limit'])
            event_state.next_stage = 'leaf-genter'
            event_state.next_pc = run.FC_XNU_PHASE53_LEAF_GENTER
        elif event_state.stage_name == 'leaf-genter':
            event_state.extra, event_state.evidence = descriptor_bind_code_checks('selector', run.FC_XNU_PHASE53_LEAF_SELECTOR, run.FC_XNU_PHASE53_LEAF_SELECTOR_LINKED, run.FC_XNU_PHASE53_LEAF_SELECTOR_WORD)
            event_state.checks.update(event_state.extra)
            event_state.checks.update(selector=int(event_state.ctx.regs[16]) == 2, args_unchanged=tuple((int(event_state.ctx.regs[index]) for index in range(4))) == event_state.state['leaf_args'], filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_LEAF_SELECTOR, rearm_budget=event_state.state['rearms'] < event_state.state['rearm_limit'])
            event_state.stage_record['selector_code'] = event_state.evidence
            event_state.next_stage = 'leaf-genter-return'
            event_state.next_pc = run.FC_XNU_PHASE53_LEAF_GENTER_RETURN
        elif event_state.stage_name == 'leaf-genter-return':
            event_state.sptm_segment = run.layout['images']['sptm']['segments']['__TEXT_EXEC']
            event_state.code_specs = (('selector', run.FC_XNU_PHASE53_LEAF_SELECTOR, run.FC_XNU_PHASE53_LEAF_SELECTOR_LINKED, run.FC_XNU_PHASE53_LEAF_SELECTOR_WORD, event_state.kernel_segment, run.sources['kernelcache']), ('genter', run.FC_XNU_PHASE53_LEAF_GENTER, run.FC_XNU_PHASE53_LEAF_GENTER_LINKED, run.FC_XNU_PHASE53_LEAF_GENTER_WORD, event_state.kernel_segment, run.sources['kernelcache']), ('gexit', run.FC_XNU_PHASE53_GEXIT, run.FC_XNU_PHASE53_GEXIT_LINKED, run.FC_XNU_PHASE53_GEXIT_WORD, event_state.sptm_segment, run.sources['sptm']), ('return', run.FC_XNU_PHASE53_LEAF_GENTER_RETURN, run.FC_XNU_PHASE53_LEAF_GENTER_RETURN_LINKED, run.FC_XNU_PHASE53_LEAF_GENTER_RETURN_WORD, event_state.kernel_segment, run.sources['kernelcache']))
            event_state.evidence = {}
            for event_state.name, event_state.pc, event_state.linked, event_state.word, event_state.segment, event_state.source in event_state.code_specs:
                event_state.leaf = run.translate(event_state.pc, event_state.roots['ttbr0'], event_state.roots['ttbr1'], read_descriptor_bind_page)
                event_state.live = run.iface.readmem(event_state.leaf['pa'], 4)
                event_state.offset = event_state.segment['fileoff'] + event_state.linked - event_state.segment['va']
                event_state.pinned = event_state.source[event_state.offset:event_state.offset + 4]
                event_state.expected = run.struct.pack('<I', event_state.word)
                event_state.checks[event_state.name + '_source'] = event_state.pinned == event_state.expected
                event_state.checks[event_state.name + '_live'] = event_state.live == event_state.expected and event_state.live == event_state.pinned
                event_state.checks[event_state.name + '_level_three'] = event_state.leaf['level'] == 3
                event_state.checks[event_state.name + '_access_flag'] = event_state.leaf['access_flag']
                event_state.evidence[event_state.name] = dict(pa=hex(event_state.leaf['pa']), source_hex=event_state.pinned.hex(), live_hex=event_state.live.hex())
            event_state.checks.update(exact_spsr=int(event_state.ctx.spsr) == run.FC_XNU_PHASE53_GENTER_RETURN_SPSR, wrapper_link=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_LEAF_SELECTOR & (1 << 40) - 1, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_GEXIT, rearm_budget=event_state.state['rearms'] < event_state.state['rearm_limit'])
            event_state.stage_record['code'] = event_state.evidence
            event_state.next_stage = 'leaf-wrapper-retab'
            event_state.next_pc = run.FC_XNU_PHASE53_LEAF_WRAPPER_RETAB
        elif event_state.stage_name == 'leaf-wrapper-retab':
            event_state.checks.update(restored_caller=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_LEAF_CALLER_RETURN & (1 << 40) - 1, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_LEAF_WRAPPER_RETAB_PREVIOUS, rearm_budget=event_state.state['rearms'] < event_state.state['rearm_limit'])
            event_state.next_stage = 'leaf-caller-return'
            event_state.next_pc = run.FC_XNU_PHASE53_LEAF_CALLER_RETURN
        elif event_state.stage_name == 'leaf-caller-return':
            event_state.l2_raw = run.iface.readmem(event_state.state['slot_pa'], 8)
            event_state.l2_descriptor = run.struct.unpack('<Q', event_state.l2_raw)[0]
            event_state.l3_after = run.iface.readmem(event_state.state['target_pa'], run.PAGE)
            event_state.l3_before = bytes.fromhex(event_state.state['leaf_table_before'])
            event_state.l3_offset = (event_state.state['leaf_va'] >> 14 & 2047) * 8
            event_state.expected_l3 = bytearray(event_state.l3_before)
            run.struct.pack_into('<Q', event_state.expected_l3, event_state.l3_offset, event_state.state['leaf_descriptor'])
            event_state.fte_after = capture_descriptor_bind_fte(event_state.state['target_pa'])
            event_state.before_fte = event_state.state['leaf_pre_fte']
            event_state.before_center = bytes.fromhex(event_state.before_fte['records'][1]['hex'])
            event_state.after_center = bytes.fromhex(event_state.fte_after['records'][1]['hex'])
            event_state.before_output = bytes.fromhex(event_state.before_fte['records'][2]['hex'])
            event_state.after_output = bytes.fromhex(event_state.fte_after['records'][2]['hex'])
            event_state.center_changed_offsets = [index for index, (old, new) in enumerate(zip(event_state.before_center, event_state.after_center)) if old != new]
            event_state.output_changed_offsets = [index for index, (old, new) in enumerate(zip(event_state.before_output, event_state.after_output)) if old != new]
            event_state.checks.update(caller_mode_el1t=int(event_state.ctx.spsr) & 15 == 4, status_success=int(event_state.ctx.regs[0]) == 0, l2_descriptor_unchanged=event_state.l2_descriptor == event_state.state['expected_descriptor'], l3_slot_written=run.struct.unpack_from('<Q', event_state.l3_after, event_state.l3_offset)[0] == event_state.state['leaf_descriptor'], l3_only_target_slot_changed=event_state.l3_after == bytes(event_state.expected_l3), fte_base_stable=event_state.fte_after['fte_base'] == event_state.before_fte['fte_base'], fte_center_stable=event_state.fte_after['center_va'] == event_state.before_fte['center_va'], fte_pointer_level_three=event_state.fte_after['pointer_level_three'], fte_pointer_access_flag=event_state.fte_after['pointer_access_flag'], fte_records_complete=all((item['complete'] for item in event_state.fte_after['records'])), fte_records_level_three=all((item['level_three'] for item in event_state.fte_after['records'])), fte_records_access_flag=all((item['access_flag'] for item in event_state.fte_after['records'])), fte_center_unlocked=event_state.fte_after['records'][1]['in_flight_ops'] == 0, fte_center_type=event_state.fte_after['records'][1]['type'] == event_state.state['expected_fte_type'], fte_generic_fields_stable=event_state.after_center[:3] == event_state.before_center[:3], fte_unrelated_neighbor_unchanged=event_state.fte_after['records'][0]['hex'] == event_state.before_fte['records'][0]['hex'], fte_output_unlocked=event_state.fte_after['records'][2]['in_flight_ops'] == 0, fte_output_type=event_state.fte_after['records'][2]['type'] == event_state.before_fte['records'][2]['type'] == 25, fte_table_metadata_transition=event_state.center_changed_offsets == [8] and event_state.before_center[8] == 0 and (event_state.after_center[8] == 1), fte_output_metadata_transition=event_state.output_changed_offsets == [8] and event_state.before_output[8] == 0 and (event_state.after_output[8] == 1), restored_caller=int(event_state.ctx.regs[30]) & (1 << 40) - 1 == run.FC_XNU_PHASE53_LEAF_CALLER_RETURN & (1 << 40) - 1, filter_previous_pc=event_state.fast_status['previous_pc'] == run.FC_XNU_PHASE53_LEAF_WRAPPER_RETAB)
            event_state.stage_record.update(l2_descriptor=hex(event_state.l2_descriptor), l3_after_sha256=run.hashlib.sha256(event_state.l3_after).hexdigest(), frame_table_after=event_state.fte_after, fte_center_changed_offsets=event_state.center_changed_offsets, fte_output_changed_offsets=event_state.output_changed_offsets)
        event_state.stage_record['checks'] = event_state.checks
        event_state.stage_record['complete'] = all(event_state.checks.values())
        event_state.state['stages'].append(event_state.stage_record)
        event_state.current_report_key = event_state.state.get('report_key', 'xnu_phase53_descriptor_bind')
        run.report[event_state.current_report_key]['stages'] = list(event_state.state['stages'])
        if event_state.stage_record['complete'] and event_state.next_stage is not None:
            event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, event_state.next_pc, event_state.state['max_steps'], event_state.ctx.elr)
            event_state.state.update(stage=event_state.next_stage, range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.ctx.elr, terminal_pc=event_state.next_pc, aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'] + 1)
            event_state.stage_record['next_enable_status'] = event_state.enabled_status
            run.report[event_state.current_report_key].update(current_stage=event_state.next_stage, terminal_pc=hex(event_state.next_pc), expected_first_pc=hex(event_state.ctx.elr), aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'])
            event_state.event.update(kind=('phase53-leaf-page-bind-' if event_state.current_report_key == 'xnu_phase53_leaf_page_bind' else 'phase53-descriptor-bind-') + event_state.stage_name, pc=event_state.ctx.elr, checks=event_state.checks)
            event_state.ctx.spsr.SS = 1
            run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
            run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
            event_state.ret = run.EXC_RET.HANDLED
        elif event_state.stage_record['complete'] and event_state.stage_name == 'caller-return':
            run.report['xnu_phase53_descriptor_bind'].update(complete=True, current_stage='complete', aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'], slot_pa=hex(event_state.state['slot_pa']), descriptor_before=hex(event_state.state['old_descriptor']), descriptor_after=hex(event_state.state['expected_descriptor']), path=event_state.state['path'], expected_fte_type=hex(event_state.state['expected_fte_type']), target_va=hex(event_state.state['target_va']), ttep_kva=hex(event_state.state['ttep_kva']))
            if run.a.xnu_phase53_leaf_page_bind:
                event_state.enabled_status = run.txm_sstep_fast_path.enable(run.FC_XNU_RUNTIME_TEXT, run.FC_SPTM_RUNTIME_TEXT, run.FC_XNU_PHASE53_LEAF_MAP_CALL, run.FC_XNU_PHASE53_LEAF_BIND_FAST_STEPS, event_state.ctx.elr)
                event_state.state.update(active=True, stage='leaf-map-call', range0=run.FC_XNU_RUNTIME_TEXT, segment_start=event_state.ctx.elr, terminal_pc=run.FC_XNU_PHASE53_LEAF_MAP_CALL, aggregate_steps=0, rearms=1, stages=[], world_transitions=[], report_key='xnu_phase53_leaf_page_bind', max_steps=run.FC_XNU_PHASE53_LEAF_BIND_FAST_STEPS, aggregate_limit=run.FC_XNU_PHASE53_LEAF_BIND_TOTAL_STEPS, rearm_limit=run.FC_XNU_PHASE53_LEAF_BIND_MAX_REARMS)
                run.report['xnu_phase53_leaf_page_bind'].update(activated=True, current_stage='leaf-map-call', terminal_pc=hex(run.FC_XNU_PHASE53_LEAF_MAP_CALL), expected_first_pc=hex(event_state.ctx.elr), aggregate_steps=0, rearms=1, stages=[], world_transitions=[], table_pa=hex(event_state.state['target_pa']), l2_slot_pa=hex(event_state.state['slot_pa']), activation_enable_status=event_state.enabled_status)
                event_state.stage_record['next_enable_status'] = event_state.enabled_status
                event_state.event.update(kind='phase53-leaf-page-bind-start', pc=event_state.ctx.elr, checks=event_state.checks)
                event_state.ctx.spsr.SS = 1
                run.u.msr(run.MDSCR_EL1, run.u.mrs(run.MDSCR_EL1) | 1)
                run.iface.writemem(event_state.info, run.ExcInfo.build(event_state.ctx))
                run.report.pop('stop_reason', None)
                event_state.ret = run.EXC_RET.HANDLED
            else:
                event_state.state.update(active=False, aggregate_steps=event_state.aggregate_steps)
                run.report['stop_reason'] = 'phase53-descriptor-bind-reached'
        elif event_state.stage_record['complete']:
            event_state.state.update(active=False, aggregate_steps=event_state.aggregate_steps)
            run.report['xnu_phase53_leaf_page_bind'].update(complete=True, current_stage='complete', aggregate_steps=event_state.aggregate_steps, rearms=event_state.state['rearms'], table_pa=hex(event_state.state['target_pa']), l2_slot_pa=hex(event_state.state['slot_pa']), leaf_va=hex(event_state.state['leaf_va']), leaf_slot_pa=hex(event_state.state['leaf_slot_pa']), leaf_descriptor=hex(event_state.state['leaf_descriptor']), leaf_output_pa=hex(event_state.state['leaf_output_pa']))
            run.report['stop_reason'] = 'phase53-leaf-page-bind-reached'
        else:
            event_state.state['active'] = False
            run.report[event_state.current_report_key]['rejection'] = event_state.stage_record
            run.report['stop_reason'] = ('phase53-leaf-page-bind-' if event_state.current_report_key == 'xnu_phase53_leaf_page_bind' else 'phase53-descriptor-bind-') + event_state.stage_name + '-gate-rejected'
    except Exception as descriptor_bind_error:
        event_state.checks['gate_readback'] = False
        event_state.stage_record.update(checks=event_state.checks, complete=False, error=str(descriptor_bind_error))
        event_state.state['active'] = False
        event_state.state.setdefault('stages', []).append(event_state.stage_record)
        event_state.current_report_key = event_state.state.get('report_key', 'xnu_phase53_descriptor_bind')
        run.report[event_state.current_report_key]['stages'] = list(event_state.state['stages'])
        run.report[event_state.current_report_key]['rejection'] = event_state.stage_record
        run.report['stop_reason'] = ('phase53-leaf-page-bind-' if event_state.current_report_key == 'xnu_phase53_leaf_page_bind' else 'phase53-descriptor-bind-') + event_state.stage_name + '-gate-rejected'
