"""Shared synthetic fixtures for the probe control test modules; no test cases."""
import os
from pathlib import Path
import struct
import sys
import unittest
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from probe_fixtures import Tables, ENABLED_SCTLR, VHE_HCR
from sptm_entry_probe import FC_XNU_AGT_ESR, FC_XNU_AGT_HVC, FC_XNU_AGT_LINKED, FC_XNU_AGT_WORD, patch_xnu_agtcnt_rdir, restore_xnu_agtcnt_rdir, FC_XNU_AHCR_NOP_SITES, FC_XNU_CNTP_CTL_ESR, FC_XNU_CNTP_CTL_LINKED, FC_XNU_CNTP_CTL_WORD, restore_xnu_cntp_ctl, FC_XNU_APPLE_PHYS_TIMER_ESR, FC_XNU_APPLE_PHYS_TIMER_LINKED, FC_XNU_APPLE_PHYS_TIMER_WORD, FC_XNU_APPLE_PHYS_TIMER_EL02, restore_xnu_apple_physical_timer, FC_XNU_M3_COMPAT_CHIPS, patch_xnu_m3_ahcr_nops, FC_XNU_PMCR1_EL12_LINKED, FC_XNU_PMCR1_EL1_WORD, FC_XNU_PMCR1_EL12_WORD, patch_xnu_pmcr1_bank_collapse, ABSENT_REGION, emit_memory_map_regions, FC_XNU_DOCKCHANNEL_UART_IPA, FC_XNU_DOCKCHANNEL_UART_FAR, FC_XNU_DOCKCHANNEL_CONFIG_IPA, FC_XNU_DOCKCHANNEL_RX8_IPA, xnu_dockchannel_uart_mapping, xnu_dockchannel_uart_catalog, match_xnu_dockchannel_uart, FC_XNU_PANIC_CARVEOUT_IPA, FC_XNU_PANIC_CARVEOUT_SIZE, xnu_panic_carveout_contract, FC_XNU_SOCD_IPA, FC_XNU_SOCD_SIZE, FC_XNU_SOCD_FAR, FC_XNU_SOCD_ESR, xnu_socd_trace_contract
from sptm_entry_probe import FC_XNU_PPERM_SITES, patch_xnu_pperm_guest_window
from sptm_entry_probe import restore_xnu_pperm_guest_window
from sptm_entry_probe import TpidrGl2FastShadow, audit_and_disable_tpidr_gl2_fast_shadow, Vel2StepFilter

class FastShadowProxy:

    def __init__(self):
        self.state = dict(enabled=False, tag_base=0, shadow=0, reads=0, writes=0, forwarded=0)
        self.calls = []

    def hv_vel2_tpidr_gl2_shadow_enable(self, tag_base, initial_value):
        self.calls.append(('enable', tag_base, initial_value))
        self.state.update(enabled=True, tag_base=tag_base, shadow=initial_value, reads=0, writes=0, forwarded=0)

    def hv_vel2_tpidr_gl2_shadow_status(self):
        self.calls.append(('status',))
        return dict(self.state)

    def hv_vel2_tpidr_gl2_shadow_disable(self):
        self.calls.append(('disable',))
        self.state['enabled'] = False

class StepFilterProxy:

    def __init__(self):
        self.calls = []
        self.state = dict(active=False, status=0, steps=0, first_pc=0, last_pc=0, previous_pc=0, range0_hits=0, range1_hits=0, range_switches=0, terminal_pc=0, max_steps=0, range0_start=0, range0_end=0, range1_start=0, range1_end=0, expected_first_pc=0)

    def hv_vel2_step_filter_enable(self, range0_start, range0_end, range1_start, range1_end, terminal_pc, max_steps, expected_first_pc):
        self.calls.append(('enable', range0_start, range0_end, range1_start, range1_end, terminal_pc, max_steps, expected_first_pc))
        self.state.update(active=True, status=1, steps=0, first_pc=0, last_pc=0, previous_pc=0, range0_hits=0, range1_hits=0, range_switches=0, terminal_pc=terminal_pc, max_steps=max_steps, range0_start=range0_start, range0_end=range0_end, range1_start=range1_start, range1_end=range1_end, expected_first_pc=expected_first_pc)

    def hv_vel2_step_filter_status(self):
        self.calls.append(('status',))
        return dict(self.state)

    def hv_vel2_step_filter_disable(self):
        self.calls.append(('disable',))
        self.state.update(active=False, status=0)

class MemoryMapFixture:

    def __init__(self, names=()):
        object.__setattr__(self, '_types', {})
        object.__setattr__(self, '_properties', {name: (99, 99) for name in names})

    def __setattr__(self, name, value):
        if name.startswith('_'):
            object.__setattr__(self, name, value)
        else:
            self._properties[name] = value

class ProbeControlFixture:

    def setUp(self):
        self.tables = Tables()
        self.endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True)
        self.s = self.endpoint.sysreg

    def access(self, register, **kwargs):
        return self.tables.access(self.endpoint, register, **kwargs)

    def assert_handled(self):
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertNotIn('error', self.endpoint.report)
        self.assertEqual(self.endpoint.hardware.attempts, [])

    def assert_stopped_unchanged(self, before, after, reason):
        self.assertEqual(self.endpoint.codec.build(before), self.endpoint.codec.build(after))
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], reason)
        self.assertFalse(any((c[0] in ('msr', 'barrier') for c in self.endpoint.hardware.calls)))
        self.assertEqual(self.endpoint.hardware.attempts, [])

    def _txm_context_entry_gate(self, prefix=False, claim=False, metadata=False, x18_branch=False, outbound=False, handler=None, **changes):
        ns = self.endpoint.namespace
        ns['a'].free_run = ns['a'].real_guarded = ns['a'].native_handoff = True
        ns['a'].xnu_run = True
        ns['a'].xnu_txm_context_entry_one_step = not (prefix or claim or metadata or x18_branch or outbound or handler)
        ns['a'].xnu_txm_context_entry_register_prefix = prefix
        ns['a'].xnu_txm_context_stack_claim_one_step = claim
        ns['a'].xnu_txm_context_stack_metadata_init = metadata
        ns['a'].xnu_txm_context_x18_branch_one_step = x18_branch
        ns['a'].xnu_txm_context_outbound_branch_one_step = outbound
        ns['a'].xnu_txm_handler_boundary = handler
        ns['handoff_state'].update(active=False, native=True)
        ns['report']['handoff'] = dict(image='kernelcache', target_pc='0xfffffe002bfb0000', instructions_executed=True)
        target = ns['FC_XNU_TXM_CONTEXT_TARGET']
        stack = ns['FC_XNU_TXM_CONTEXT_STACK']
        source_offset = ns['FC_XNU_TXM_CONTEXT_ERET_PC'] - 4 - ns['FC_IMAGE_BASE']
        sptm_source = bytearray(source_offset + 4)
        struct.pack_into('<I', sptm_source, source_offset, 3600745440)
        txm_fileoff = 128
        post_claim_source = changes.get('post_claim_source', ns['FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES'])
        x18_tail_source = changes.get('x18_tail_source', ns['FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES'][4:])
        context_source = b'\x1f\x00\x00\x91' + ns['FC_XNU_TXM_CONTEXT_REGISTER_PREFIX_BYTES'] + struct.pack('<I', ns['FC_XNU_TXM_CONTEXT_CASB_WORD']) + post_claim_source + x18_tail_source
        txm_segment_va = ns['FC_XNU_TXM_CONTEXT_OUTBOUND_LINKED']
        context_source_offset = txm_fileoff + int(ns['FC_XNU_TXM_CONTEXT_LINKED'], 16) - txm_segment_va
        handler_source = ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES'] + bytes.fromhex('e80f00f93a0200d0')
        validator_source = handler_source + bytes.fromhex('5a431a9148034039c8000035e963009128c572f2c100005400088052020000140014805201008052a4faff973f1140b16300005440088052fbffff17f30300aae80300f908008852000d084ee083803ce0030091a105805236070094')
        helper_source_offset = txm_fileoff + ns['FC_XNU_TXM_HANDLER_HELPER_LINKED'] - txm_segment_va
        txm_source = bytearray(max(context_source_offset + len(context_source), helper_source_offset + len(ns['FC_XNU_TXM_HANDLER_HELPER_BYTES'])))
        supplied_handler_source = changes.get('outbound_target_source', validator_source if handler in ('validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace') else handler_source if handler == 'local-setup' else ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES'])
        txm_source[txm_fileoff:txm_fileoff + len(supplied_handler_source)] = supplied_handler_source
        txm_source[helper_source_offset:helper_source_offset + len(ns['FC_XNU_TXM_HANDLER_HELPER_BYTES'])] = changes.get('handler_helper_source', ns['FC_XNU_TXM_HANDLER_HELPER_BYTES'])
        txm_source[context_source_offset:context_source_offset + len(context_source)] = context_source
        txm_source = bytes(txm_source)
        ns['sources'] = {'sptm': bytes(sptm_source), 'txm': txm_source}
        ns['layout'] = {'images': {'sptm': {'segments': {'__TEXT_EXEC': {'fileoff': 16384, 'filesize': len(sptm_source) - 16384}}}, 'txm': {'segments': {'__TEXT_EXEC': {'fileoff': txm_fileoff, 'va': txm_segment_va, 'filesize': len(txm_source) - txm_fileoff}}}}}
        target_descriptor = 536871040 | 3
        stack_descriptor = 536887296 | 64 | 3
        outbound_page_pa = 570425344
        helper_page_pa = 570441728
        global_page_pa = 570458112
        response_page_pa = 570474496
        for page_pa in (outbound_page_pa, helper_page_pa, global_page_pa, response_page_pa):
            if page_pa not in self.tables.memory.pages:
                self.tables.memory.add_page(page_pa)
        outbound_pa = outbound_page_pa + (ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET'] & ns['PAGE'] - 1)
        self.tables.memory.write(outbound_pa, changes.get('outbound_live_source', validator_source if handler in ('validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace') else handler_source if handler == 'local-setup' else ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES']))
        helper_pa = helper_page_pa + (ns['FC_XNU_TXM_HANDLER_HELPER'] & ns['PAGE'] - 1)
        self.tables.memory.write(helper_pa, changes.get('handler_helper_live_source', ns['FC_XNU_TXM_HANDLER_HELPER_BYTES']))
        global_pa = global_page_pa + (ns['FC_XNU_TXM_HANDLER_GLOBAL'] & ns['PAGE'] - 1)
        self.tables.memory.write(global_pa, changes.get('handler_global_source', b'\x00'))
        response_pa = response_page_pa + (ns['FC_XNU_TXM_HANDLER_RESPONSE_POINTER'] & ns['PAGE'] - 1)
        self.tables.memory.write(response_pa, struct.pack('<Q', 1311768467463790320))
        ns['classify_entry'] = lambda *args: dict(image='txm', segment='__TEXT_EXEC', target_pc=hex(target), pa=hex(536870912), linked_pc=ns['FC_XNU_TXM_CONTEXT_LINKED'], entry_matches=False, bytes_match=True, bytes_hex=ns['FC_XNU_TXM_CONTEXT_BYTES'].hex(), instructions_executed=False)
        stack_pa = changes.get('stack_pa', 536887296)

        def fake_translate(va, *_):
            if va == target:
                return dict(pa=536870912, level=3, descriptor=target_descriptor, access_flag=True, read_only=True, user_access=False, pxn=False, uxn=False)
            if va == ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET']:
                return dict(pa=outbound_pa, level=3, descriptor=target_descriptor, access_flag=True, read_only=True, user_access=False, pxn=False, uxn=False)
            if va == ns['FC_XNU_TXM_HANDLER_HELPER']:
                return dict(pa=helper_pa, level=3, descriptor=target_descriptor, access_flag=True, read_only=True, user_access=False, pxn=False, uxn=False)
            if va == ns['FC_XNU_TXM_HANDLER_GLOBAL']:
                return dict(pa=global_pa, level=3, descriptor=stack_descriptor, access_flag=True, read_only=False, user_access=True, pxn=True, uxn=True)
            if va == ns['FC_XNU_TXM_HANDLER_RESPONSE_POINTER']:
                return dict(pa=response_pa, level=3, descriptor=stack_descriptor, access_flag=True, read_only=False, user_access=True, pxn=True, uxn=True)
            return dict(pa=stack_pa + va - stack, level=3, descriptor=stack_descriptor, access_flag=True, read_only=False, user_access=True, pxn=False, uxn=False)
        ns['translate'] = fake_translate
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1: self.s.ELR_EL12, self.s.SPSR_GL1: self.s.SPSR_EL12, self.s.SPRR_PPERM_EL1: self.s.SPRR_PPERM_EL12, self.s.SPRR_UPERM_EL0: self.s.SPRR_UPERM_EL02})
        self.endpoint.hardware.values[self.s.ELR_EL12] = changes.get('target', target)
        self.endpoint.hardware.values[self.s.SPSR_EL12] = changes.get('target_spsr', 5056)
        self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12] = 2315031809083751142
        self.endpoint.hardware.values[self.s.SPRR_UPERM_EL02] = 140754669043840
        self.endpoint.hardware.values[self.s.MAIR_EL12] = 255
        self.endpoint.hardware.values[self.s.TTBR0_EL12] = self.tables.low
        self.endpoint.hardware.values[self.s.TTBR1_EL12] = self.tables.high
        event = self.tables.event(1509967872)
        event['pc'] = changes.get('pc', ns['FC_XNU_TXM_CONTEXT_ERET_PC'])
        event['spsr'] = changes.get('caller_spsr', 2147488709)
        event['regs'][0] = changes.get('x0', stack)
        event['regs'][3] = changes.get('x3', 0)
        event['regs'][16] = changes.get('x16', ns['FC_XNU_TXM_CONTEXT_SELECTOR'])
        event['regs'][18] = changes.get('x18', ns['FC_XNU_TXM_CONTEXT_X18'])
        return self.endpoint.feed(event)

    def _complete_txm_handler_boundary(self, boundary):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(handler=boundary)
        states = ns['txm_context_step_state']['expected_states']
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        entry_regs = [4096 + register for register in range(32)]
        entry_regs[0] = entry_regs[8] = entry_regs[10] = 1
        entry_regs[9] = 0
        entry_regs[16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
        entry_regs[18] = ns['FC_XNU_TXM_CONTEXT_X18']
        signed_x30 = 11936128518282651045
        for index, expected in enumerate(states):
            step = self.tables.event(3405774882)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][:] = entry_regs
            if index >= 23:
                step['regs'][30] = signed_x30
            for register, source in expected.get('captured_reg_values', {}).items():
                step['regs'][register] = entry_regs[source]
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            memory = expected.get('memory', {})
            offsets = ns['txm_context_step_state']['metadata_offsets']
            for name, value_hex in memory.items():
                offset, _ = offsets[name]
                self.tables.memory.write(frame_pa + offset, bytes.fromhex(value_hex))
            save_pairs = ((26, 25), (24, 23), (22, 21), (20, 19), (29, 30))
            for pair_index, registers in enumerate(save_pairs[:expected.get('saved_pairs', 0)]):
                values = [signed_x30 if register == 30 else entry_regs[register] for register in registers]
                self.tables.memory.write(frame_pa - 112 + 32 + pair_index * 16, struct.pack('<QQ', *values))
            self.endpoint.feed(step)
        return (states, self.endpoint.report['xnu_txm_handler_boundary'])

    def _run_phase53_retype_survey_call(self, target_type=20, limit=4, after_type=None, lock_before=False, stop_before_return=False, descriptor_bind=False, descriptor_wrong_caller=False, descriptor_call_index=4):
        ns = self.endpoint.namespace
        ns['a'].xnu_phase53_retype_survey = True
        ns['a'].xnu_phase53_retype_survey_limit = limit
        ns['a'].xnu_phase53_descriptor_bind = descriptor_bind
        ns['handoff_state'].update(native=True)
        self.endpoint.report['handoff'] = dict(image='txm', target_pc=hex(ns['FC_XNU_TXM_CONTEXT_TARGET']))
        fast_proxy = StepFilterProxy()
        ns['txm_sstep_fast_path'] = Vel2StepFilter(fast_proxy)
        caller_pc = ns['FC_XNU_PHASE53_PRIMARY_RETYPE_CALL'] if descriptor_bind and (not descriptor_wrong_caller) else ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'] - 48
        caller_linked = ns['FC_XNU_PHASE53_PRIMARY_RETYPE_CALL_LINKED'] if descriptor_bind and (not descriptor_wrong_caller) else ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED'] - 48
        caller_return = caller_pc + 4
        caller_word = ns['FC_XNU_PHASE53_PRIMARY_RETYPE_CALL_WORD'] if descriptor_bind and (not descriptor_wrong_caller) else 2483027980
        kernel_start = caller_linked
        kernel_end = ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED'] + 4
        kernel_source = bytearray(kernel_end - kernel_start)
        code = ((caller_pc, caller_linked, caller_word), (ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'], ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_LINKED'], ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY_WORD']), (ns['FC_XNU_PHASE53_GENTER_PREVIOUS'], ns['FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED'], ns['FC_XNU_PHASE53_GENTER_PREVIOUS_WORD']), (ns['FC_XNU_PHASE53_GENTER'], ns['FC_XNU_PHASE53_GENTER_LINKED'], ns['FC_XNU_PHASE53_GENTER_WORD']), (ns['FC_XNU_PHASE53_GENTER_RETURN'], ns['FC_XNU_PHASE53_GENTER_RETURN_LINKED'], ns['FC_XNU_PHASE53_GENTER_RETURN_WORD']), (ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'], ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_LINKED'], ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_WORD']))
        kernel_page = 572522496
        sptm_page = 572538880
        pointer_page = 572555264
        fte_page = 572571648
        for page in (kernel_page, sptm_page, pointer_page, fte_page):
            self.tables.memory.add_page(page)
        translations = {}
        for runtime, linked, word in code:
            struct.pack_into('<I', kernel_source, linked - kernel_start, word)
            pa = kernel_page + (runtime & ns['PAGE'] - 1)
            self.tables.memory.write(pa, struct.pack('<I', word))
            translations[runtime] = pa
        gexit_pc = ns['FC_XNU_PHASE53_GEXIT']
        gexit_pa = sptm_page + (gexit_pc & ns['PAGE'] - 1)
        self.tables.memory.write(gexit_pa, struct.pack('<I', ns['FC_XNU_PHASE53_GEXIT_WORD']))
        translations[gexit_pc] = gexit_pa
        ns['layout'] = {'images': {'kernelcache': {'segments': {'__TEXT_EXEC': {'va': kernel_start, 'fileoff': 0, 'filesize': len(kernel_source)}}}, 'sptm': {'segments': {'__TEXT_EXEC': {'va': ns['FC_XNU_PHASE53_GEXIT_LINKED'], 'fileoff': 0, 'filesize': 4}}}}}
        ns['sources'] = {'kernelcache': bytes(kernel_source), 'sptm': struct.pack('<I', ns['FC_XNU_PHASE53_GEXIT_WORD'])}
        allocated_pa = 570425344
        fte_base = 18446741875341656064
        fte_va = fte_base + (allocated_pa - ns['base'] >> 10 & 18014398509481968)
        self.tables.memory.write(pointer_page, struct.pack('<Q', fte_base))
        for delta, record_type in ((-16, 18), (0, 11), (16, 21)):
            pa = fte_page + 256 + delta
            self.tables.memory.write(pa, bytes([0, 0, record_type]) + bytes(range(3, 16)))
            translations[fte_va + delta] = pa
        translations[ns['FC_SPTM_PHASE53_FTE_BASE_POINTER']] = pointer_page
        prior_translate = ns['translate']
        ns['translate'] = lambda va, *args: dict(pa=translations[va], level=3, descriptor=1027, access_flag=True, read_only=True, user_access=False, pxn=False, uxn=False) if va in translations else prior_translate(va, *args)
        state = ns['phase53_retype_survey_state']
        state.update(active=True, roots={'ttbr0': 0, 'ttbr1': 0}, range0=ns['FC_XNU_RUNTIME_TEXT'], segment_start=ns['FC_XNU_PHASE53_RETYPE_RETURN'], terminal_pc=ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'], stage='seek-entry', completed_calls=descriptor_call_index if descriptor_bind else 0, aggregate_steps=0, rearms=1, calls=[], limit=limit, world_transitions=[], max_steps=ns['FC_XNU_PHASE53_RETYPE_SURVEY_FAST_STEPS'])
        self.endpoint.report['xnu_phase53_retype_survey'] = dict(requested=True, activated=True, calls=[])

        def feed(pc, regs, previous_pc, status=Vel2StepFilter.TERMINAL, spsr=0, steps=19):
            segment_start = state['segment_start']
            fast_proxy.state.update(active=False, status=status, steps=steps, first_pc=segment_start, previous_pc=previous_pc, last_pc=pc, range0_hits=steps, range1_hits=0, range_switches=0, terminal_pc=state['terminal_pc'], max_steps=state['max_steps'], range0_start=state['range0'][0], range0_end=state['range0'][1], range1_start=ns['FC_SPTM_RUNTIME_TEXT'][0], range1_end=ns['FC_SPTM_RUNTIME_TEXT'][1], expected_first_pc=segment_start)
            callback = self.tables.event(3388997666, mode=4)
            callback['pc'] = pc
            callback['spsr'] = spsr
            for register, value in regs.items():
                callback['regs'][register] = value
            self.endpoint.feed(callback)
        args = {0: allocated_pa, 1: 11, 2: target_type, 3: 3 if descriptor_bind else 0}
        center_pa = translations[fte_va]
        if lock_before:
            before = self.tables.memory.read(center_pa, 16)
            self.tables.memory.write(center_pa, b'\x01\x00' + before[2:])
        feed(ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'], {**args, 30: caller_return}, caller_pc - 4)
        if lock_before:
            return (ns, state, fast_proxy, feed, caller_return, center_pa)
        self.assertEqual(state['stage'], 'seek-genter')
        self.assertEqual(fast_proxy.state['expected_first_pc'], ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'])
        feed(ns['FC_XNU_PHASE53_GENTER'], {**args, 16: 1, 30: caller_return}, ns['FC_XNU_PHASE53_GENTER_PREVIOUS'])
        self.assertEqual(state['stage'], 'seek-genter-return')
        if stop_before_return:
            return (ns, state, fast_proxy, feed, caller_return, center_pa)
        feed(ns['FC_XNU_PHASE53_GENTER_RETURN'], {30: ns['FC_XNU_PHASE53_GENTER_PREVIOUS']}, ns['FC_XNU_PHASE53_GEXIT'], spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        self.assertEqual(state['stage'], 'seek-wrapper-retab')
        before = self.tables.memory.read(center_pa, 16)
        self.tables.memory.write(center_pa, before[:2] + bytes([target_type if after_type is None else after_type]) + before[3:])
        feed(ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'], {30: caller_return}, ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB_PREVIOUS'], spsr=4 if descriptor_bind else 0)
        return (ns, state, fast_proxy, feed, caller_return, center_pa)

    def _prepare_phase53_unrelated_gexit_return(self):
        ns, state, fast_proxy, feed, caller_return, _ = self._run_phase53_retype_survey_call(target_type=41, limit=2)
        state.update(range0=ns['FC_TXM_RUNTIME_TEXT'], segment_start=ns['FC_XNU_TXM_CONTEXT_TARGET'])
        return (ns, state, fast_proxy, feed, caller_return - 4)

    def _run_phase53_descriptor_bind(self, mismatch=None, branch_path='ordinary', alternate_return=False, stop_after=None, return_status=None, leaf_page_bind=False, leaf_mismatch=None, omit_parent_translations=False):
        ns = self.endpoint.namespace
        ns['a'].xnu_phase53_leaf_page_bind = leaf_page_bind
        ns['handoff_state'].update(native=True)
        self.endpoint.report['handoff'] = dict(image='txm', target_pc=hex(ns['FC_XNU_TXM_CONTEXT_TARGET']))
        fast_proxy = StepFilterProxy()
        ns['txm_sstep_fast_path'] = Vel2StepFilter(fast_proxy)
        code = ((ns['FC_XNU_PHASE53_TWIG_COMPARE'], ns['FC_XNU_PHASE53_TWIG_COMPARE_LINKED'], ns['FC_XNU_PHASE53_TWIG_COMPARE_WORD']), (ns['FC_XNU_PHASE53_TWIG_BRANCH'], ns['FC_XNU_PHASE53_TWIG_BRANCH_LINKED'], ns['FC_XNU_PHASE53_TWIG_BRANCH_WORD']), (ns['FC_XNU_PHASE53_KERNEL_COMPARE'], ns['FC_XNU_PHASE53_KERNEL_COMPARE_LINKED'], ns['FC_XNU_PHASE53_KERNEL_COMPARE_WORD']), (ns['FC_XNU_PHASE53_KERNEL_BRANCH'], ns['FC_XNU_PHASE53_KERNEL_BRANCH_LINKED'], ns['FC_XNU_PHASE53_KERNEL_BRANCH_WORD']), (ns['FC_XNU_PHASE53_ROZONE_END_COMPARE'], ns['FC_XNU_PHASE53_ROZONE_END_COMPARE_LINKED'], ns['FC_XNU_PHASE53_ROZONE_END_COMPARE_WORD']), (ns['FC_XNU_PHASE53_ROZONE_END_BRANCH'], ns['FC_XNU_PHASE53_ROZONE_END_BRANCH_LINKED'], ns['FC_XNU_PHASE53_ROZONE_END_BRANCH_WORD']), (ns['FC_XNU_PHASE53_ROZONE_START_COMPARE'], ns['FC_XNU_PHASE53_ROZONE_START_COMPARE_LINKED'], ns['FC_XNU_PHASE53_ROZONE_START_COMPARE_WORD']), (ns['FC_XNU_PHASE53_ROZONE_START_INTERMEDIATE'], ns['FC_XNU_PHASE53_ROZONE_START_INTERMEDIATE_LINKED'], ns['FC_XNU_PHASE53_ROZONE_START_INTERMEDIATE_WORD']), (ns['FC_XNU_PHASE53_ROZONE_START_PREVIOUS'], ns['FC_XNU_PHASE53_ROZONE_START_PREVIOUS_LINKED'], ns['FC_XNU_PHASE53_ROZONE_START_PREVIOUS_WORD']), (ns['FC_XNU_PHASE53_ROZONE_START_BRANCH'], ns['FC_XNU_PHASE53_ROZONE_START_BRANCH_LINKED'], ns['FC_XNU_PHASE53_ROZONE_START_BRANCH_WORD']), (ns['FC_XNU_PHASE53_ROZONE_RETYPE1_CALL'], ns['FC_XNU_PHASE53_ROZONE_RETYPE1_CALL_LINKED'], ns['FC_XNU_PHASE53_ROZONE_RETYPE1_CALL_WORD']), (ns['FC_XNU_PHASE53_ROZONE_RETYPE1_RETURN'], ns['FC_XNU_PHASE53_ROZONE_RETYPE1_RETURN_LINKED'], ns['FC_XNU_PHASE53_ROZONE_RETYPE1_RETURN_WORD']), (ns['FC_XNU_PHASE53_ROZONE_RETYPE2_CALL'], ns['FC_XNU_PHASE53_ROZONE_RETYPE2_CALL_LINKED'], ns['FC_XNU_PHASE53_ROZONE_RETYPE2_CALL_WORD']), (ns['FC_XNU_PHASE53_ROZONE_RETYPE2_RETURN'], ns['FC_XNU_PHASE53_ROZONE_RETYPE2_RETURN_LINKED'], ns['FC_XNU_PHASE53_ROZONE_RETYPE2_RETURN_WORD']), (ns['FC_XNU_PHASE53_PRE_MAP_CALL'], ns['FC_XNU_PHASE53_PRE_MAP_CALL_LINKED'], ns['FC_XNU_PHASE53_PRE_MAP_CALL_WORD']), (ns['FC_XNU_PHASE53_MAP_WRAPPER_ENTRY'], ns['FC_XNU_PHASE53_MAP_WRAPPER_ENTRY_LINKED'], ns['FC_XNU_PHASE53_MAP_WRAPPER_ENTRY_WORD']), (ns['FC_XNU_PHASE53_MAP_SELECTOR'], ns['FC_XNU_PHASE53_MAP_SELECTOR_LINKED'], ns['FC_XNU_PHASE53_MAP_SELECTOR_WORD']), (ns['FC_XNU_PHASE53_MAP_GENTER'], ns['FC_XNU_PHASE53_MAP_GENTER_LINKED'], ns['FC_XNU_PHASE53_MAP_GENTER_WORD']), (ns['FC_XNU_PHASE53_MAP_GENTER_RETURN'], ns['FC_XNU_PHASE53_MAP_GENTER_RETURN_LINKED'], ns['FC_XNU_PHASE53_MAP_GENTER_RETURN_WORD']), (ns['FC_XNU_PHASE53_MAP_WRAPPER_RETAB'], ns['FC_XNU_PHASE53_MAP_WRAPPER_RETAB_LINKED'], ns['FC_XNU_PHASE53_MAP_WRAPPER_RETAB_WORD']), (ns['FC_XNU_PHASE53_MAP_CALLER_RETURN'], ns['FC_XNU_PHASE53_MAP_CALLER_RETURN_LINKED'], ns['FC_XNU_PHASE53_MAP_CALLER_RETURN_WORD']), *((runtime, linked, word) for runtime, linked, word in ns['FC_XNU_PHASE53_LEAF_MAP_PREP']), *((runtime, linked, word) for calls in (ns['FC_XNU_PHASE53_EXPAND_PARENT_CALLS'], ns['FC_XNU_PHASE53_LEAF_PARENT_CALLS']) for _, runtime, linked, word in calls), (ns['FC_XNU_PHASE53_LEAF_SOURCE_TYPE_LOAD'], ns['FC_XNU_PHASE53_LEAF_SOURCE_TYPE_LOAD_LINKED'], ns['FC_XNU_PHASE53_LEAF_SOURCE_TYPE_LOAD_WORD']), (ns['FC_XNU_PHASE53_LEAF_MAP_CALL'], ns['FC_XNU_PHASE53_LEAF_MAP_CALL_LINKED'], ns['FC_XNU_PHASE53_LEAF_MAP_CALL_WORD']), (ns['FC_XNU_PHASE53_LEAF_WRAPPER_ENTRY'], ns['FC_XNU_PHASE53_LEAF_WRAPPER_ENTRY_LINKED'], ns['FC_XNU_PHASE53_LEAF_WRAPPER_ENTRY_WORD']), (ns['FC_XNU_PHASE53_LEAF_SELECTOR'], ns['FC_XNU_PHASE53_LEAF_SELECTOR_LINKED'], ns['FC_XNU_PHASE53_LEAF_SELECTOR_WORD']), (ns['FC_XNU_PHASE53_LEAF_GENTER'], ns['FC_XNU_PHASE53_LEAF_GENTER_LINKED'], ns['FC_XNU_PHASE53_LEAF_GENTER_WORD']), (ns['FC_XNU_PHASE53_LEAF_GENTER_RETURN'], ns['FC_XNU_PHASE53_LEAF_GENTER_RETURN_LINKED'], ns['FC_XNU_PHASE53_LEAF_GENTER_RETURN_WORD']), (ns['FC_XNU_PHASE53_LEAF_WRAPPER_RETAB'], ns['FC_XNU_PHASE53_LEAF_WRAPPER_RETAB_LINKED'], ns['FC_XNU_PHASE53_LEAF_WRAPPER_RETAB_WORD']), (ns['FC_XNU_PHASE53_LEAF_CALLER_RETURN'], ns['FC_XNU_PHASE53_LEAF_CALLER_RETURN_LINKED'], ns['FC_XNU_PHASE53_LEAF_CALLER_RETURN_WORD']), (ns['FC_XNU_TXM_HANDLER_CMD1_RETAB'], ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_LINKED'], ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD']))
        kernel_start = min((item[1] for item in code))
        kernel_end = max((item[1] for item in code)) + 4
        kernel_source = bytearray(kernel_end - kernel_start)
        code_page = 573571072
        sptm_page = 573587456
        stack_page = 573603840
        root_page = 573620224
        l2_page = 573636608
        pointer_page = 573652992
        fte_page = 573669376
        for page in (code_page, sptm_page, stack_page, root_page, l2_page, pointer_page, fte_page, 570425344):
            self.tables.memory.add_page(page)
        translations = {}
        for runtime, linked, word in code:
            struct.pack_into('<I', kernel_source, linked - kernel_start, word)
            pa = code_page + (runtime & ns['PAGE'] - 1)
            self.tables.memory.write(pa, struct.pack('<I', word))
            translations[runtime] = pa
        gexit = ns['FC_XNU_PHASE53_GEXIT']
        gexit_pa = sptm_page + (gexit & ns['PAGE'] - 1)
        self.tables.memory.write(gexit_pa, struct.pack('<I', ns['FC_XNU_PHASE53_GEXIT_WORD']))
        translations[gexit] = gexit_pa
        ns['layout'] = {'images': {'kernelcache': {'segments': {'__TEXT_EXEC': {'va': kernel_start, 'fileoff': 0, 'filesize': len(kernel_source)}}}, 'sptm': {'segments': {'__TEXT_EXEC': {'va': ns['FC_XNU_PHASE53_GEXIT_LINKED'], 'fileoff': 0, 'filesize': 4}}}}}
        ns['sources'] = {'kernelcache': bytes(kernel_source), 'sptm': struct.pack('<I', ns['FC_XNU_PHASE53_GEXIT_WORD'])}
        if mismatch == 'rozone-start-intermediate-code':
            intermediate = ns['FC_XNU_PHASE53_ROZONE_START_INTERMEDIATE']
            self.tables.memory.write(translations[intermediate], struct.pack('<I', 3573751839))
        elif mismatch == 'parent-call-code':
            call_pc = ns['FC_XNU_PHASE53_EXPAND_PARENT_CALLS'][0][1]
            self.tables.memory.write(translations[call_pc], struct.pack('<I', 3573751839))
        target_pa = 570425344
        target_va = 18446741875760267264 + (8 if mismatch == 'va-alignment' else 0)
        caller_sp = 18446741875340611584
        ttep_kva = 18446741875341664256
        l1_index = target_va >> 36 & 2047
        l2_index = target_va >> 25 & 2047
        computed_slot = l2_page + l2_index * 8
        slot_pa = computed_slot + (8 if mismatch == 'slot' else 0)
        self.tables.memory.write(root_page + l1_index * 8, struct.pack('<Q', l2_page | 3))
        self.tables.memory.write(stack_page + 256, struct.pack('<Q', ttep_kva))
        self.tables.memory.write(stack_page + 264, struct.pack('<Q', target_va))
        parent_leaf_va = target_va + ns['PAGE']
        pmap_kva = 18446741875343753216
        self.tables.memory.write(stack_page + 280, struct.pack('<Q', parent_leaf_va + (ns['PAGE'] if mismatch == 'parent-leaf-va' else 0)))
        self.tables.memory.write(stack_page + 344, struct.pack('<Q', pmap_kva))
        self.tables.memory.write(stack_page + 360, struct.pack('<Q', 4660 if mismatch == 'parent-lr' else ns['FC_XNU_PHASE53_EXPAND_PARENT_RETURNS'][1]))
        self.tables.memory.write(stack_page + 520, struct.pack('<Q', root_page + (ns['PAGE'] if mismatch == 'parent-pmap-root' else 0)))
        self.tables.memory.write(slot_pa, struct.pack('<Q', 3 if mismatch == 'old-table' else 0))
        translations[caller_sp + 88] = stack_page + 256
        translations[caller_sp + 72] = stack_page + 264
        if not omit_parent_translations:
            translations[caller_sp + 280] = stack_page + 280
            translations[caller_sp + 344] = stack_page + 344
        translations[caller_sp + 360] = stack_page + 360
        self.tables.memory.write(stack_page + 496, struct.pack('<Q', 11))
        translations[caller_sp + 496] = stack_page + 496
        translations[pmap_kva + 8] = stack_page + 520
        translations[ttep_kva] = slot_pa
        fte_base = 18446741875342704640
        fte_va = fte_base + (target_pa - ns['base'] >> 10 & 18014398509481968)
        self.tables.memory.write(pointer_page, struct.pack('<Q', fte_base))
        translations[ns['FC_SPTM_PHASE53_FTE_BASE_POINTER']] = pointer_page
        fte_records = []
        for delta, record_type in ((-16, 18), (0, 20), (16, 11)):
            record_pa = fte_page + 256 + delta
            record_raw = bytes((0, 0, 20, 0, 3, 0)) + bytes(10) if delta == 0 else bytes([0, 0, record_type]) + bytes(13) if delta == 16 else bytes([0, 0, record_type]) + bytes(range(3, 16))
            self.tables.memory.write(record_pa, record_raw)
            translations[fte_va + delta] = record_pa
            fte_records.append(dict(hex=record_raw.hex()))
        for delta in (32, 48):
            record_pa = fte_page + 256 + delta
            record_raw = bytes([0, 0, 11]) + bytes(range(3, 16))
            self.tables.memory.write(record_pa, record_raw)
            translations[fte_va + delta] = record_pa
        prior_translate = ns['translate']
        ns['translate'] = lambda va, *args: dict(pa=translations[va], level=3, descriptor=1027, access_flag=True, read_only=True, user_access=False, pxn=False, uxn=False) if va in translations else prior_translate(va, *args)
        state = ns['phase53_descriptor_bind_state']
        state.update(active=True, roots={'ttbr0': root_page, 'ttbr1': root_page}, range0=ns['FC_XNU_RUNTIME_TEXT'], segment_start=ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'], terminal_pc=ns['FC_XNU_PHASE53_TWIG_BRANCH'], stage='twig-branch', aggregate_steps=ns['FC_XNU_PHASE53_DESCRIPTOR_BIND_TOTAL_STEPS'] if mismatch == 'aggregate-budget' else 0, rearms=ns['FC_XNU_PHASE53_DESCRIPTOR_BIND_MAX_REARMS'] if mismatch == 'rearm-budget' else 1, world_transitions=[], stages=[], target_pa=target_pa, target_fte={'fte_base': hex(fte_base), 'center_va': hex(fte_va), 'records': fte_records}, caller_sp=caller_sp, max_steps=ns['FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS'])
        self.endpoint.report['xnu_phase53_descriptor_bind'] = dict(requested=True, activated=True, stages=[], world_transitions=[])
        self.endpoint.report['xnu_phase53_leaf_page_bind'] = dict(requested=leaf_page_bind, activated=False, stages=[], world_transitions=[])

        def feed(pc, regs, previous_pc, status=Vel2StepFilter.TERMINAL, spsr=None, sp=None):
            segment_start = state['segment_start']
            fast_proxy.state.update(active=False, status=status, steps=13, first_pc=segment_start, previous_pc=previous_pc, last_pc=pc, range0_hits=10, range1_hits=3, range_switches=1, terminal_pc=state['terminal_pc'], max_steps=state['max_steps'], range0_start=state['range0'][0], range0_end=state['range0'][1], range1_start=ns['FC_SPTM_RUNTIME_TEXT'][0], range1_end=ns['FC_SPTM_RUNTIME_TEXT'][1], expected_first_pc=segment_start)
            callback = self.tables.event(3388997666, mode=4)
            callback['pc'] = pc
            callback['spsr'] = 4 if spsr is None else spsr
            callback['sp'][0] = sp if sp is not None else caller_sp + 224 if state.get('stage', '').startswith('leaf-') else caller_sp
            for register, value in regs.items():
                callback['regs'][register] = value
            self.endpoint.feed(callback)
        args = {0: root_page, 1: target_va + 16384 if mismatch == 'target-va' else target_va, 2: 2, 3: target_pa | (7 if mismatch == 'new-tte' else 3)}
        feed(ns['FC_XNU_PHASE53_TWIG_BRANCH'], {}, ns['FC_XNU_PHASE53_TWIG_COMPARE'], spsr=4 | 1 << 30 if branch_path != 'ordinary' else 4)
        if not state['active']:
            return (ns, state, fast_proxy)
        if branch_path != 'ordinary':
            feed(ns['FC_XNU_PHASE53_KERNEL_BRANCH'], {}, ns['FC_XNU_PHASE53_KERNEL_COMPARE'], spsr=4 | 1 << 30)
            if not state['active']:
                return (ns, state, fast_proxy)
            if branch_path == 'kernel-ordinary-end':
                feed(ns['FC_XNU_PHASE53_ROZONE_END_BRANCH'], {}, ns['FC_XNU_PHASE53_ROZONE_END_COMPARE'], spsr=4)
            else:
                feed(ns['FC_XNU_PHASE53_ROZONE_END_BRANCH'], {}, ns['FC_XNU_PHASE53_ROZONE_END_COMPARE'], spsr=4 | 1 << 29)
                if not state['active']:
                    return (ns, state, fast_proxy)
                feed(ns['FC_XNU_PHASE53_ROZONE_START_BRANCH'], {}, ns['FC_XNU_PHASE53_ROZONE_START_PREVIOUS'], spsr=4 | 1 << 29 if branch_path == 'kernel-ordinary-start' else 4)
            if not state['active']:
                return (ns, state, fast_proxy)
        if branch_path == 'rozone':
            feed(ns['FC_XNU_PHASE53_ROZONE_RETYPE1_CALL'], {0: target_pa, 1: 20, 2: 12 if mismatch == 'rozone-call1-args' else 11, 3: 0}, ns['FC_XNU_PHASE53_ROZONE_RETYPE1_CALL'] - 4)
            if not state['active']:
                return (ns, state, fast_proxy)
            center_pa = translations[fte_va]
            self.tables.memory.write(center_pa, bytes((0, 0, 20 if mismatch == 'rozone-default-type' else 11)) + bytes(13))
            feed(ns['FC_XNU_PHASE53_ROZONE_RETYPE1_RETURN'], {30: ns['FC_XNU_PHASE53_ROZONE_RETYPE1_RETURN']}, ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'])
            if not state['active']:
                return (ns, state, fast_proxy)
            feed(ns['FC_XNU_PHASE53_ROZONE_RETYPE2_CALL'], {0: target_pa, 1: 11, 2: 22, 3: 2 if mismatch == 'rozone-call2-args' else 3}, ns['FC_XNU_PHASE53_ROZONE_RETYPE2_CALL'] - 4)
            if not state['active']:
                return (ns, state, fast_proxy)
            self.tables.memory.write(center_pa, bytes((0, 0, 20 if mismatch == 'rozone-final-type' else 22, 0, 3, 0)) + bytes(10))
            feed(ns['FC_XNU_PHASE53_ROZONE_RETYPE2_RETURN'], {30: ns['FC_XNU_PHASE53_ROZONE_RETYPE2_RETURN']}, ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'])
            if not state['active']:
                return (ns, state, fast_proxy)
        if mismatch == 'fte-pre':
            center_pa = translations[fte_va]
            raw = self.tables.memory.read(center_pa, 16)
            self.tables.memory.write(center_pa, b'\x01\x00' + raw[2:])
        feed(ns['FC_XNU_PHASE53_PRE_MAP_CALL'], args, ns['FC_XNU_PHASE53_PRE_MAP_CALL'] - 4, spsr=5 if mismatch == 'caller-mode' else None)
        if not state['active']:
            return (ns, state, fast_proxy)
        if stop_after == 'pre-map-call':
            return (ns, state, fast_proxy)
        feed(ns['FC_XNU_PHASE53_MAP_WRAPPER_ENTRY'], {**args, 30: ns['FC_XNU_PHASE53_MAP_CALLER_RETURN']}, ns['FC_XNU_PHASE53_PRE_MAP_CALL'])
        feed(ns['FC_XNU_PHASE53_MAP_GENTER'], {**args, 16: 3, 30: ns['FC_XNU_PHASE53_MAP_CALLER_RETURN']}, ns['FC_XNU_PHASE53_MAP_SELECTOR'])
        if stop_after == 'genter':
            return (ns, state, fast_proxy)
        if alternate_return:
            state['range0'] = ns['FC_TXM_RUNTIME_TEXT']
        feed(ns['FC_XNU_PHASE53_MAP_GENTER_RETURN'], {30: ns['FC_XNU_PHASE53_MAP_SELECTOR']}, ns['FC_XNU_PHASE53_GEXIT'], status=Vel2StepFilter.TERMINAL if return_status is None else return_status, spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        if not state['active']:
            return (ns, state, fast_proxy)
        feed(ns['FC_XNU_PHASE53_MAP_WRAPPER_RETAB'], {30: ns['FC_XNU_PHASE53_MAP_CALLER_RETURN']}, ns['FC_XNU_PHASE53_MAP_WRAPPER_RETAB_PREVIOUS'])
        self.tables.memory.write(slot_pa, struct.pack('<Q', 0 if mismatch == 'descriptor' else target_pa | 3))
        if mismatch == 'fte':
            center_pa = translations[fte_va]
            raw = self.tables.memory.read(center_pa, 16)
            self.tables.memory.write(center_pa, b'\x01\x00' + raw[2:])
        elif mismatch == 'fte-metadata':
            center_pa = translations[fte_va]
            raw = bytearray(self.tables.memory.read(center_pa, 16))
            raw[6] = 1
            self.tables.memory.write(center_pa, bytes(raw))
        elif mismatch == 'fte-neighbor':
            neighbor_pa = translations[fte_va - 16]
            raw = bytearray(self.tables.memory.read(neighbor_pa, 16))
            raw[6] ^= 1
            self.tables.memory.write(neighbor_pa, bytes(raw))
        feed(ns['FC_XNU_PHASE53_MAP_CALLER_RETURN'], {0: 1 if mismatch == 'status' else 0, 30: ns['FC_XNU_PHASE53_MAP_CALLER_RETURN']}, ns['FC_XNU_PHASE53_MAP_WRAPPER_RETAB'])
        if not leaf_page_bind or not state['active']:
            return (ns, state, fast_proxy)
        leaf_va = parent_leaf_va
        self.tables.memory.write(stack_page + 360, struct.pack('<Q', 4660 if leaf_mismatch == 'parent-lr' else ns['FC_XNU_PHASE53_LEAF_PARENT_RETURNS'][1]))
        leaf_descriptor = target_pa + ns['PAGE'] | 1027
        leaf_args = {0: root_page + ns['PAGE'] if leaf_mismatch == 'root' else root_page, 1: leaf_va + 8 if leaf_mismatch == 'va-alignment' else target_va + (1 << 25) if leaf_mismatch == 'l2-index' else leaf_va + ns['PAGE'] if leaf_mismatch == 'parent-va' else leaf_va, 2: leaf_descriptor & ~3 if leaf_mismatch == 'leaf-invalid' else leaf_descriptor | 1 << 42 if leaf_mismatch == 'leaf-address' else 1027 if leaf_mismatch == 'output-zero' else 4294968323 if leaf_mismatch == 'output-outside' else leaf_descriptor, 3: 1 if leaf_mismatch == 'flags' else 0}
        if leaf_mismatch == 'prep-code':
            prep_pc = ns['FC_XNU_PHASE53_LEAF_MAP_PREP'][0][0]
            self.tables.memory.write(translations[prep_pc], struct.pack('<I', 3573751839))
        elif leaf_mismatch == 'parent-call-code':
            call_pc = ns['FC_XNU_PHASE53_LEAF_PARENT_CALLS'][0][1]
            self.tables.memory.write(translations[call_pc], struct.pack('<I', 3573751839))
        elif leaf_mismatch == 'source-type-load-code':
            self.tables.memory.write(translations[ns['FC_XNU_PHASE53_LEAF_SOURCE_TYPE_LOAD']], struct.pack('<I', 3573751839))
        elif leaf_mismatch == 'table-nonzero':
            self.tables.memory.write(target_pa, struct.pack('<Q', 1024))
        elif leaf_mismatch == 'aggregate-budget':
            state['aggregate_steps'] = ns['FC_XNU_PHASE53_LEAF_BIND_TOTAL_STEPS']
        elif leaf_mismatch == 'rearm-budget':
            state['rearms'] = ns['FC_XNU_PHASE53_LEAF_BIND_MAX_REARMS']
        if leaf_mismatch == 'unrelated-budget':
            state['rearms'] = ns['FC_XNU_PHASE53_LEAF_BIND_MAX_REARMS']
        if leaf_mismatch in ('unrelated-once', 'unrelated-budget'):
            feed(ns['FC_XNU_PHASE53_LEAF_MAP_CALL'], leaf_args, ns['FC_XNU_PHASE53_LEAF_MAP_PREP'][-1][0], sp=caller_sp + 736)
            if not state['active']:
                return (ns, state, fast_proxy)
        output_fte_pa = translations[fte_va + 16]
        output_fte_raw = bytearray(self.tables.memory.read(output_fte_pa, 16))
        output_fte_raw[2] = 24 if leaf_mismatch == 'output-fte-type' else 25
        if leaf_mismatch == 'output-fte-metadata':
            output_fte_raw[6] ^= 1
        self.tables.memory.write(output_fte_pa, bytes(output_fte_raw))
        if leaf_mismatch == 'unrelated-fte-neighbor':
            unrelated_pa = translations[fte_va - 16]
            unrelated_raw = bytearray(self.tables.memory.read(unrelated_pa, 16))
            unrelated_raw[6] ^= 1
            self.tables.memory.write(unrelated_pa, bytes(unrelated_raw))
        feed(ns['FC_XNU_PHASE53_LEAF_MAP_CALL'], leaf_args, ns['FC_XNU_PHASE53_LEAF_MAP_PREP'][-1][0])
        if not state['active']:
            return (ns, state, fast_proxy)
        feed(ns['FC_XNU_PHASE53_LEAF_WRAPPER_ENTRY'], {**leaf_args, 30: ns['FC_XNU_PHASE53_LEAF_CALLER_RETURN']}, ns['FC_XNU_PHASE53_LEAF_MAP_CALL'])
        feed(ns['FC_XNU_PHASE53_LEAF_GENTER'], {**leaf_args, 16: 3 if leaf_mismatch == 'selector' else 2, 30: ns['FC_XNU_PHASE53_LEAF_CALLER_RETURN']}, ns['FC_XNU_PHASE53_LEAF_SELECTOR'])
        if not state['active']:
            return (ns, state, fast_proxy)
        feed(ns['FC_XNU_PHASE53_LEAF_GENTER_RETURN'], {30: ns['FC_XNU_PHASE53_LEAF_SELECTOR']}, ns['FC_XNU_PHASE53_GEXIT'], spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        if not state['active']:
            return (ns, state, fast_proxy)
        feed(ns['FC_XNU_PHASE53_LEAF_WRAPPER_RETAB'], {30: ns['FC_XNU_PHASE53_LEAF_CALLER_RETURN']}, ns['FC_XNU_PHASE53_LEAF_WRAPPER_RETAB_PREVIOUS'])
        if not state['active']:
            return (ns, state, fast_proxy)
        leaf_slot_pa = target_pa + (leaf_args[1] >> 14 & 2047) * 8
        self.tables.memory.write(leaf_slot_pa + (8 if leaf_mismatch == 'wrong-slot' else 0), struct.pack('<Q', leaf_args[2]))
        table_fte_pa = translations[fte_va]
        table_fte_raw = bytearray(self.tables.memory.read(table_fte_pa, 16))
        table_fte_raw[8] = 2 if leaf_mismatch == 'fte-table-metadata' else 1
        self.tables.memory.write(table_fte_pa, bytes(table_fte_raw))
        output_fte_raw = bytearray(self.tables.memory.read(output_fte_pa, 16))
        output_fte_raw[8] = 2 if leaf_mismatch == 'fte-output-metadata' else 1
        self.tables.memory.write(output_fte_pa, bytes(output_fte_raw))
        if leaf_mismatch == 'fte-unrelated-after':
            unrelated_pa = translations[fte_va - 16]
            unrelated_raw = bytearray(self.tables.memory.read(unrelated_pa, 16))
            unrelated_raw[8] ^= 1
            self.tables.memory.write(unrelated_pa, bytes(unrelated_raw))
        if leaf_mismatch == 'l2-changed':
            self.tables.memory.write(slot_pa, struct.pack('<Q', target_pa | 7))
        elif leaf_mismatch == 'fte':
            center_pa = translations[fte_va]
            raw = bytearray(self.tables.memory.read(center_pa, 16))
            raw[0] = 1
            self.tables.memory.write(center_pa, bytes(raw))
        feed(ns['FC_XNU_PHASE53_LEAF_CALLER_RETURN'], {0: 1 if leaf_mismatch == 'status' else 0, 30: ns['FC_XNU_PHASE53_LEAF_CALLER_RETURN']}, ns['FC_XNU_PHASE53_LEAF_WRAPPER_RETAB'])
        return (ns, state, fast_proxy)

    def feed_xnu_launch(self, steps=2, pperm=6148914691236517205, broken_walk=False, state=5065):
        ns = self.endpoint.namespace
        target = 18446741875424165888
        ns['a'].xnu_steps = steps
        self.endpoint.hardware.values[self.s.ASPSR_GL12] = 4660
        ns['a'].free_run = ns['a'].real_guarded = ns['a'].native_handoff = True
        ns['classify_entry'] = lambda *args: dict(image='kernelcache', target_pc=hex(target), entry_matches=True, bytes_match=True, instructions_executed=False)
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1: self.s.ELR_EL12, self.s.SPSR_GL1: self.s.SPSR_EL12, self.s.ASPSR_GL1: self.s.ASPSR_GL12})
        self.endpoint.hardware.values[self.s.ELR_EL12] = target
        self.endpoint.hardware.values[self.s.SPSR_EL12] = state
        ns['HV'].MSR_REDIRECTS.update({self.s.SPRR_PPERM_EL1: self.s.SPRR_PPERM_EL12, self.s.SPRR_UPERM_EL0: self.s.SPRR_UPERM_EL02})
        live_pperm, live_uperm = (pperm, 1229782938247303441)
        self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12] = live_pperm
        self.endpoint.hardware.values[self.s.SPRR_UPERM_EL02] = live_uperm
        ns['permission_shadow'][self.s.SPRR_PPERM_EL1] = 0
        ns['permission_shadow'][self.s.SPRR_UPERM_EL0] = 0
        self.endpoint.hardware.values[self.s.TTBR0_EL12] = self.tables.low
        self.endpoint.hardware.values[self.s.TTBR1_EL12] = self.tables.high
        original_translate = ns['translate']
        ns['translate'] = lambda va, ttbr0, ttbr1, read: original_translate(self.tables.pc, ttbr0, ttbr1, read)
        if broken_walk:

            def fail_walk(*args):
                raise ValueError('synthetic table capture failed')
            ns['translate'] = fail_walk
        rt = 4
        reg = self.s.ASPSR_GL1
        op0, op1, crn, crm, op2 = reg
        word = 3573547008 | op0 << 19 | op1 << 16 | crn << 12 | crm << 8 | op2 << 5 | rt
        patched, = struct.unpack('<I', ns['patch_probe_code'](struct.pack('<I', word)))
        imm = patched >> 5 & 65535
        before, after = self.endpoint.feed(dict(self.tables.event(1509949440 | imm, 0, rt), pc=ns['FC_XNU_GEXIT']))
        return (before, after)

    def _prepare_pperm_window_replay(self):
        ns = self.endpoint.namespace
        ns['handoff_state'].update(active=False, native=True)
        ns['a'].xnu_pperm_guest_window = True
        ns['a'].xnu_pperm_guest_window_limit = 1
        runtime_entry = 18446741875424165888
        ns['report']['handoff'] = {'target_pc': hex(runtime_entry)}
        lo = min((site[0] for site in FC_XNU_PPERM_SITES))
        hi = max((site[0] for site in FC_XNU_PPERM_SITES)) + 4
        source = bytearray(hi - lo)
        for pc, word, _, _ in FC_XNU_PPERM_SITES:
            struct.pack_into('<I', source, pc - lo, word)
        ns['layout'] = {'images': {'kernelcache': {'segments': {'__TEXT_EXEC': {'va': lo, 'fileoff': 0, 'filesize': len(source)}}}}}
        ns['sources'] = {'kernelcache': bytes(source)}
        ns['report']['xnu_pperm_guest_window'] = {'enabled': True, 'sequence': [], 'memcpy_crossed': False, 'physical_pperm_el1_touched': False, 'started_windows': 0, 'completed_windows': 0, 'memcpy_crossed_windows': 0}
        ns['HV'].MSR_REDIRECTS[ns['SPRR_PPERM_EL1']] = self.s.SPRR_PPERM_EL12
        original = 2315031809083751142
        writable = original & ~(15 << 8) | 11 << 8
        self.endpoint.hardware.values[self.s.SPRR_PPERM_EL12] = original
        return (ns, runtime_entry, original, writable)

    def _feed_pperm_hvc(self, ns, runtime_entry, site_index, x8=0):
        pc, _, tag, _ = FC_XNU_PPERM_SITES[site_index]
        event = self.tables.event(22 << 26 | 1 << 25 | tag)
        event.update(pc=runtime_entry + pc - ns['FC_XNU_ENTRY_LINKED'] + 4)
        event['regs'][8] = x8
        return self.endpoint.feed(event)
