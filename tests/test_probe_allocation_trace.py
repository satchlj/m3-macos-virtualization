"""Allocation trace regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from probe_control_support import ProbeControlFixture, StepFilterProxy
import os
import struct
import unittest
from sptm_entry_probe import Vel2StepFilter


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class ProbeAllocationTraceTests(ProbeControlFixture, unittest.TestCase):

    def test_txm_handler_cmd1_firmware_fast_path_gates_svc_and_terminal(self):
        _, probe = self._complete_txm_handler_boundary('cmd1-completion-trace')
        ns = self.endpoint.namespace
        state = ns['txm_validator_trace_state']
        ns['a'].xnu_txm_sstep_fast_path = True
        fast_proxy = StepFilterProxy()
        ns['txm_sstep_fast_path'] = Vel2StepFilter(fast_proxy)
        self.endpoint.report['xnu_txm_sstep_fast_path'] = dict(
            requested=True, activated=False)

        returned = self.tables.event(0xcb000022)
        returned['pc'] = ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET'] + 0xa4
        returned['sp'][0] = state['expected_sp']
        returned['regs'][0] = 0x2d
        self.endpoint.feed(returned)
        frame_pa = state['metadata_frame_pa']
        self.tables.memory.write(frame_pa + 8, b'\x00' * 8)
        self.tables.memory.write(frame_pa + 0x18, struct.pack('<Q', 3))
        self.tables.memory.write(frame_pa + 0x20,
            struct.pack('<Q', state['response_pointer']))
        self.tables.memory.write(frame_pa + 0x28,
            struct.pack('<Q', ns['FC_XNU_TXM_HANDLER_GLOBAL'] + 4))
        self.tables.memory.write(frame_pa + 0x30,
            struct.pack('<Q', ns['FC_XNU_TXM_HANDLER_GLOBAL'] + 8))
        self.tables.memory.write(state['protected_pa'] + 0x18, b'\x00' * 8)
        response = self.tables.event(0xcb000022)
        response['pc'] = ns['FC_XNU_TXM_HANDLER_RESPONSE_STOP']
        response['sp'][0] = state['expected_sp']
        self.endpoint.feed(response)

        svc_pc = ns['FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC']
        svc_word = struct.pack(
            '<I', ns['FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC_WORD'])
        segment = ns['layout']['images']['txm']['segments']['__TEXT_EXEC']
        linked = (ns['FC_XNU_TXM_HANDLER_HELPER_LINKED'] + svc_pc -
                  ns['FC_XNU_TXM_HANDLER_HELPER'])
        source_offset = segment['fileoff'] + linked - segment['va']
        source = bytearray(ns['sources']['txm'])
        source.extend(b'\x00' * max(0, source_offset + 4 - len(source)))
        source[source_offset:source_offset + 4] = svc_word
        ns['sources']['txm'] = bytes(source)
        segment['filesize'] = len(source) - segment['fileoff']
        svc_page = 0x22010000
        self.tables.memory.add_page(svc_page)
        svc_pa = svc_page + (svc_pc & (ns['PAGE'] - 1))
        self.tables.memory.write(svc_pa, svc_word)
        previous_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=svc_pa, level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va == svc_pc else previous_translate(va, *args))

        svc = self.tables.event(0xcb000022)
        svc['pc'] = svc_pc
        svc['sp'][0] = state['expected_sp']
        self.endpoint.feed(svc)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['fast_path_armed'])
        self.assertTrue(fast_proxy.state['active'])
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR'])

        fast_proxy.state.update(
            steps=23, first_pc=ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR'],
            previous_pc=ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET'] - 16,
            last_pc=ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET'] - 8,
            range0_hits=0, range1_hits=23, range_switches=0)
        completion_return = ns['FC_XNU_TXM_HANDLER_CMD1_COMPLETION_SVC'] + 4
        previous_classify = ns['classify_entry']
        ns['classify_entry'] = lambda target, *args: (
            dict(image='txm', segment='__TEXT_EXEC', target_pc=hex(target),
                 pa=hex(svc_pa + 4),
                 linked_pc=hex(ns['FC_XNU_TXM_HANDLER_CMD1_RETURN_LINKED']),
                 entry_matches=False, bytes_match=True,
                 bytes_hex=(ns['FC_XNU_TXM_HANDLER_CMD1_RETURN_BYTES'] +
                            b'\x00' * 16).hex(), instructions_executed=False)
            if target == completion_return else previous_classify(target, *args))
        ns['HV'].MSR_REDIRECTS.update({
            self.s.ELR_GL1: self.s.ELR_GL12,
            self.s.SPSR_GL1: self.s.SPSR_GL12,
            self.s.ESR_GL1: self.s.ESR_GL12,
            self.s.ASPSR_GL1: self.s.ASPSR_GL12,
        })
        self.endpoint.hardware.values.update({
            self.s.ELR_GL12: completion_return,
            self.s.SPSR_GL12: 0x800013c0,
            self.s.ESR_GL12: ns['FC_XNU_TXM_HANDLER_CMD1_GUARDED_ESR'],
            self.s.ASPSR_GL12: ns['FC_XNU_TXM_HANDLER_CMD1_GUARDED_ASPSR'],
        })
        eret_source_offset = (ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET'] - 4 -
                              ns['FC_IMAGE_BASE'])
        sptm_source = bytearray(ns['sources']['sptm'])
        sptm_source.extend(b'\x00' * max(
            0, eret_source_offset + 4 - len(sptm_source)))
        struct.pack_into('<I', sptm_source, eret_source_offset, 0xd69f03e0)
        mdscr_pc = ns['FC_XNU_TXM_HANDLER_CMD1_MDSCR_PC']
        mdscr_source_offset = mdscr_pc - ns['FC_IMAGE_BASE']
        sptm_source.extend(b'\x00' * max(
            0, mdscr_source_offset + 4 - len(sptm_source)))
        struct.pack_into('<I', sptm_source, mdscr_source_offset,
                         ns['FC_XNU_TXM_HANDLER_CMD1_MDSCR_WORD'])
        ns['sources']['sptm'] = bytes(sptm_source)
        ns['layout']['images']['sptm']['segments']['__TEXT_EXEC'][
            'filesize'] = len(sptm_source) - 0x4000
        eret = self.tables.event(0x5a004800)
        eret['pc'] = ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_ERET']
        _, after_eret = self.endpoint.feed(eret)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(after_eret.elr, completion_return)
        self.assertEqual(after_eret.spsr.SS, 1)
        self.assertEqual(self.endpoint.report['eret_classifications'][-1]
                         ['decision'], 'cmd1-completion-eret')

        # Attempt 89 reached an unpatched MDSCR_EL1 write while the firmware
        # filter was still armed.  It must bypass the TXM SSTEP validator,
        # remain guest-only, and resume stepping after the trapped instruction.
        mdscr_page = 0x22014000
        self.tables.memory.add_page(mdscr_page)
        mdscr_pa = mdscr_page + (mdscr_pc & (ns['PAGE'] - 1))
        self.tables.memory.write(mdscr_pa, struct.pack(
            '<I', ns['FC_XNU_TXM_HANDLER_CMD1_MDSCR_WORD']))
        prior_gate_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=mdscr_pa, level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va == mdscr_pc else prior_gate_translate(va, *args))
        fast_proxy.state.update(
            steps=71, last_pc=mdscr_pc, previous_pc=mdscr_pc - 8,
            range0_hits=8, range1_hits=63, range_switches=2)
        mdscr = self.tables.event(
            ns['FC_XNU_TXM_HANDLER_CMD1_MDSCR_ESR'],
            value=ns['FC_XNU_TXM_HANDLER_CMD1_MDSCR_VALUE'], rt=9, mode=5)
        mdscr['pc'] = mdscr_pc
        _, after_mdscr = self.endpoint.feed(mdscr)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(after_mdscr.elr, mdscr['pc'] + 4)
        self.assertEqual(after_mdscr.spsr.SS, 1)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'],
                         'emulated-guest-mdscr')
        self.assertTrue(self.endpoint.report['trace'][-1]
                        ['firmware_step_filter_rearmed'])
        self.assertTrue(state['active'])

        retab_pc = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB']
        ns['layout']['images']['kernelcache'] = {
            'segments': {'__TEXT_EXEC': {
                'va': ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_LINKED'],
                'fileoff': 0, 'filesize': 4}}}
        ns['sources']['kernelcache'] = struct.pack(
            '<I', ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD'])
        kernel_segment = ns['layout']['images']['kernelcache'][
            'segments']['__TEXT_EXEC']
        retab_source_offset = (kernel_segment['fileoff'] +
            ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_LINKED'] -
            kernel_segment['va'])
        kernel_source = bytearray(ns['sources']['kernelcache'])
        kernel_source.extend(b'\x00' * max(
            0, retab_source_offset + 4 - len(kernel_source)))
        struct.pack_into('<I', kernel_source, retab_source_offset,
                         ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD'])
        ns['sources']['kernelcache'] = bytes(kernel_source)
        retab_page = 0x22018000
        self.tables.memory.add_page(retab_page)
        retab_pa = retab_page + (retab_pc & (ns['PAGE'] - 1))
        self.tables.memory.write(retab_pa, struct.pack(
            '<I', ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_WORD']))
        prior_retab_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=retab_pa, level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va == retab_pc else prior_retab_translate(va, *args))
        fast_proxy.state.update(
            active=False, status=Vel2StepFilter.TERMINAL, steps=1000,
            first_pc=ns['FC_XNU_TXM_HANDLER_CMD1_SPTM_VECTOR'],
            previous_pc=ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS'],
            last_pc=retab_pc,
            range0_hits=400, range1_hits=600, range_switches=3)
        retab = self.tables.event(0xca000022, mode=4)
        retab['pc'] = retab_pc
        retab['spsr'] = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_SPSR']
        retab['regs'][30] = 0x5bc17e002bc5fb88
        self.endpoint.feed(retab)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['retab_crossed'])
        self.assertTrue(fast_proxy.state['active'])
        self.assertEqual(fast_proxy.state['terminal_pc'],
                         ns['FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN'])

        fast_proxy.state.update(
            active=False, status=Vel2StepFilter.TERMINAL, steps=0,
            first_pc=0, previous_pc=0,
            last_pc=ns['FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN'],
            range0_hits=0, range1_hits=0, range_switches=0)
        ns['a'].xnu_phase53_allocation_trace = True
        self.tables.memory.write(frame_pa + 0x58, b'\x00')
        completion = self.tables.event(0xca000022)
        completion['pc'] = ns['FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN']
        completion['sp'][0] = state['expected_sp']
        self.endpoint.feed(completion)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertNotIn('stop_reason', self.endpoint.report)
        self.assertTrue(probe['complete'])
        self.assertTrue(probe['result']['checks']['fast_path_contract'])
        self.assertTrue(probe['result']['checks']['fast_path_crossed_both_worlds'])
        self.assertEqual(probe['result']['extension_instructions'], 1044)
        allocation_state = ns['phase53_allocation_trace_state']
        self.assertTrue(allocation_state['active'])
        self.assertEqual(fast_proxy.state['terminal_pc'],
                         ns['FC_XNU_PHASE53_ALLOC_CALL'])
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         ns['FC_XNU_PHASE53_AFTER_CMD1_FIRST'])

        phase53_eret_pc = ns['FC_XNU_TXM_CONTEXT_ERET_PC']
        txm_target = ns['FC_XNU_TXM_CONTEXT_TARGET']
        ns['classify_entry'] = lambda target, *args: (
            dict(image='txm', segment='__TEXT_EXEC', target_pc=hex(target),
                 linked_pc=ns['FC_XNU_TXM_CONTEXT_LINKED'],
                 entry_matches=False, bytes_match=True, bytes_hex='00' * 32,
                 instructions_executed=False)
            if target == txm_target else
            dict(image='kernelcache', segment='__TEXT_EXEC',
                 target_pc=hex(target), linked_pc=hex(target - 0x20000000),
                 entry_matches=False, bytes_match=True, bytes_hex='00' * 32,
                 instructions_executed=False))
        self.endpoint.hardware.values.update({
            self.s.ELR_GL12: txm_target,
            self.s.SPSR_GL12: 0x13c0,
        })
        fast_proxy.state.update(
            active=True, status=Vel2StepFilter.RUNNING, steps=11,
            first_pc=ns['FC_XNU_PHASE53_AFTER_CMD1_FIRST'],
            previous_pc=phase53_eret_pc - 8, last_pc=phase53_eret_pc - 4,
            range0_hits=9, range1_hits=2, range_switches=1)
        to_txm = self.tables.event(0x5a004800, mode=5)
        to_txm['pc'] = phase53_eret_pc
        self.endpoint.feed(to_txm)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(fast_proxy.state['range0_start'],
                         ns['FC_TXM_RUNTIME_TEXT'][0])
        self.assertEqual(fast_proxy.state['expected_first_pc'], txm_target)

        xnu_target = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB']
        fast_proxy.state.update(
            active=False, status=4, steps=159,
            first_pc=txm_target, previous_pc=phase53_eret_pc - 8,
            last_pc=ns['FC_XNU_TXM_HANDLER_CMD1_RETAB'],
            range0_hits=9, range1_hits=150, range_switches=1)
        fast_proxy.state['previous_pc'] = (
            ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS'])
        to_xnu = self.tables.event(0xcb000022, mode=4)
        to_xnu['pc'] = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB']
        to_xnu['spsr'] = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_SPSR']
        to_xnu['regs'][30] = 0x5bc17e002bc5fb88
        self.endpoint.feed(to_xnu)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(fast_proxy.state['range0_start'],
                         ns['FC_XNU_RUNTIME_TEXT'][0])
        self.assertEqual(fast_proxy.state['expected_first_pc'], xnu_target)
        self.assertEqual(len(self.endpoint.report[
            'xnu_phase53_allocation_trace']['world_transitions']), 2)

        fast_proxy.state.update(
            active=True, status=Vel2StepFilter.RUNNING, steps=77,
            first_pc=xnu_target, previous_pc=phase53_eret_pc - 8,
            last_pc=phase53_eret_pc - 4, range0_hits=70, range1_hits=7,
            range_switches=1)
        guarded_to_txm = self.tables.event(0x5a004800, mode=5)
        guarded_to_txm['pc'] = phase53_eret_pc
        self.endpoint.feed(guarded_to_txm)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(fast_proxy.state['range0_start'],
                         ns['FC_TXM_RUNTIME_TEXT'][0])
        self.assertEqual(fast_proxy.state['expected_first_pc'], txm_target)

        gexit_pc = ns['FC_XNU_PHASE53_GEXIT']
        guarded_return_pc = ns['FC_XNU_PHASE53_GENTER_RETURN']
        ns['layout']['images']['sptm']['segments']['__TEXT_EXEC'] = {
            'va': ns['FC_XNU_PHASE53_GEXIT_LINKED'],
            'fileoff': 0, 'filesize': 4}
        ns['sources']['sptm'] = struct.pack(
            '<I', ns['FC_XNU_PHASE53_GEXIT_WORD'])
        ns['layout']['images']['kernelcache']['segments']['__TEXT_EXEC'] = {
            'va': ns['FC_XNU_PHASE53_GENTER_PREVIOUS_LINKED'],
            'fileoff': 0, 'filesize': 12}
        ns['sources']['kernelcache'] = struct.pack(
            '<III', ns['FC_XNU_PHASE53_GENTER_PREVIOUS_WORD'],
            ns['FC_XNU_PHASE53_GENTER_WORD'],
            ns['FC_XNU_PHASE53_GENTER_RETURN_WORD'])
        gexit_page = 0x22014000
        guarded_return_page = 0x22018000
        self.tables.memory.add_page(gexit_page)
        self.tables.memory.add_page(guarded_return_page)
        gexit_pa = gexit_page + (gexit_pc & (ns['PAGE'] - 1))
        selector_pa = (guarded_return_page +
                       (ns['FC_XNU_PHASE53_GENTER_PREVIOUS'] &
                        (ns['PAGE'] - 1)))
        genter_pa = (guarded_return_page +
                     (ns['FC_XNU_PHASE53_GENTER'] & (ns['PAGE'] - 1)))
        guarded_return_pa = (guarded_return_page +
                             (guarded_return_pc & (ns['PAGE'] - 1)))
        self.tables.memory.write(gexit_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_GEXIT_WORD']))
        self.tables.memory.write(selector_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_GENTER_PREVIOUS_WORD']))
        self.tables.memory.write(genter_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_GENTER_WORD']))
        self.tables.memory.write(guarded_return_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_GENTER_RETURN_WORD']))
        prior_guarded_return_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=gexit_pa, level=3, descriptor=0x403, access_flag=True,
                 read_only=True, user_access=False, pxn=False, uxn=False)
            if va == gexit_pc else
            (dict(pa=selector_pa, level=3, descriptor=0x403,
                  access_flag=True, read_only=True, user_access=False,
                  pxn=False, uxn=False)
             if va == ns['FC_XNU_PHASE53_GENTER_PREVIOUS'] else
             (dict(pa=genter_pa, level=3, descriptor=0x403,
                   access_flag=True, read_only=True, user_access=False,
                   pxn=False, uxn=False)
              if va == ns['FC_XNU_PHASE53_GENTER'] else
              (dict(pa=guarded_return_pa, level=3, descriptor=0x403,
                  access_flag=True, read_only=True, user_access=False,
                  pxn=False, uxn=False)
               if va == guarded_return_pc else
               prior_guarded_return_translate(va, *args)))))
        fast_proxy.state.update(
            active=False, status=4, steps=2396,
            first_pc=txm_target,
            previous_pc=ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS'],
            last_pc=guarded_return_pc, range0_hits=123, range1_hits=2273,
            range_switches=1)
        guarded_return = self.tables.event(0xcb000022, mode=4)
        guarded_return['pc'] = guarded_return_pc
        guarded_return['spsr'] = ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR']
        guarded_return['regs'][30] = 0xcfbbfe002bf7a4c0
        self.endpoint.feed(guarded_return)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertNotIn('stop_reason', self.endpoint.report)
        self.assertEqual(allocation_state['stage'], 'allocation-call')
        self.assertEqual(fast_proxy.state['range0_start'],
                         ns['FC_XNU_RUNTIME_TEXT'][0])
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         guarded_return_pc)
        self.assertEqual(len(self.endpoint.report[
            'xnu_phase53_allocation_trace']['world_transitions']), 4)

        allocation_pc = ns['FC_XNU_PHASE53_ALLOC_CALL']
        ns['layout']['images']['kernelcache']['segments']['__TEXT_EXEC'] = {
            'va': ns['FC_XNU_PHASE53_ALLOC_CALL_LINKED'],
            'fileoff': 0, 'filesize': 4}
        ns['sources']['kernelcache'] = struct.pack(
            '<I', ns['FC_XNU_PHASE53_ALLOC_CALL_WORD'])
        allocation_page = 0x2201c000
        self.tables.memory.add_page(allocation_page)
        allocation_pa = allocation_page + (allocation_pc & (ns['PAGE'] - 1))
        self.tables.memory.write(allocation_pa, struct.pack(
            '<I', ns['FC_XNU_PHASE53_ALLOC_CALL_WORD']))
        prior_allocation_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=allocation_pa, level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va == allocation_pc else prior_allocation_translate(va, *args))
        fast_proxy.state.update(
            active=False, status=Vel2StepFilter.TERMINAL, steps=123,
            first_pc=guarded_return_pc,
            previous_pc=allocation_pc - 4, last_pc=allocation_pc,
            range0_hits=123, range1_hits=0, range_switches=0)
        allocation = self.tables.event(0xca000022, mode=4)
        allocation['pc'] = allocation_pc
        self.endpoint.feed(allocation)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertNotIn('stop_reason', self.endpoint.report)

        stage_page = 0x22020000
        def feed_stage(pc_name, linked_name, word_name, regs=None,
                       previous_pc=None):
            nonlocal stage_page
            pc = ns[pc_name]
            linked = ns[linked_name]
            word = ns[word_name]
            ns['layout']['images']['kernelcache']['segments']['__TEXT_EXEC'] = {
                'va': linked, 'fileoff': 0, 'filesize': 4}
            ns['sources']['kernelcache'] = struct.pack('<I', word)
            self.tables.memory.add_page(stage_page)
            pa = stage_page + (pc & (ns['PAGE'] - 1))
            self.tables.memory.write(pa, struct.pack('<I', word))
            prior_translate = ns['translate']
            ns['translate'] = lambda va, *args, _pc=pc, _pa=pa, _prior=prior_translate: (
                dict(pa=_pa, level=3, descriptor=0x403, access_flag=True,
                     read_only=True, user_access=False, pxn=False, uxn=False)
                if va == _pc else _prior(va, *args))
            segment_start = fast_proxy.state['expected_first_pc']
            fast_proxy.state.update(
                active=False, status=Vel2StepFilter.TERMINAL, steps=23,
                first_pc=segment_start,
                previous_pc=(pc - 4 if previous_pc is None else previous_pc),
                last_pc=pc, range0_hits=23, range1_hits=0,
                range_switches=0)
            callback = self.tables.event(0xca000022, mode=4)
            callback['pc'] = pc
            for register, value in (regs or {}).items():
                callback['regs'][register] = value
            self.endpoint.feed(callback)
            stage_page += ns['PAGE']

        feed_stage('FC_XNU_PHASE53_ALLOC_INTERNAL_CALL',
                   'FC_XNU_PHASE53_ALLOC_INTERNAL_CALL_LINKED',
                   'FC_XNU_PHASE53_ALLOC_INTERNAL_CALL_WORD')
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        allocated_pa = 0x22000000
        feed_stage('FC_XNU_PHASE53_ALLOC_RETURN',
                   'FC_XNU_PHASE53_ALLOC_RETURN_LINKED',
                   'FC_XNU_PHASE53_ALLOC_RETURN_WORD', {0: allocated_pa})
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))

        fte_pointer_pa = 0x22100000
        fte_record_pa = 0x22104000
        self.tables.memory.add_page(fte_pointer_pa)
        self.tables.memory.add_page(fte_record_pa)
        fte_base = 0xfffffe0027100000
        fte_va = fte_base + (
            ((allocated_pa - ns['base']) >> 10) & 0x3ffffffffffff0)
        fte_before = bytes([0, 0, 0xb, *range(3, 16)])
        self.tables.memory.write(fte_pointer_pa, struct.pack('<Q', fte_base))
        self.tables.memory.write(fte_record_pa, fte_before)
        prior_fte_translate = ns['translate']
        ns['translate'] = lambda va, *args: (
            dict(pa=fte_pointer_pa, level=3, descriptor=0x403,
                 access_flag=True, read_only=True, user_access=False,
                 pxn=False, uxn=False)
            if va == ns['FC_SPTM_PHASE53_FTE_BASE_POINTER'] else
            (dict(pa=fte_record_pa, level=3, descriptor=0x403,
                  access_flag=True, read_only=True, user_access=False,
                  pxn=False, uxn=False)
             if va == fte_va else prior_fte_translate(va, *args)))
        feed_stage('FC_XNU_PHASE53_POST_UBFIZ',
                   'FC_XNU_PHASE53_POST_UBFIZ_LINKED',
                   'FC_XNU_PHASE53_POST_UBFIZ_WORD', {21: allocated_pa},
                   ns['FC_XNU_PHASE53_UBFIZ_PC'])
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        feed_stage('FC_XNU_PHASE53_RETYPE_CALL',
                   'FC_XNU_PHASE53_RETYPE_CALL_LINKED',
                   'FC_XNU_PHASE53_RETYPE_CALL_WORD',
                   {0: allocated_pa, 1: 0xb, 2: 0x29, 3: 0})
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        feed_stage('FC_XNU_PHASE53_GENTER',
                   'FC_XNU_PHASE53_GENTER_LINKED',
                   'FC_XNU_PHASE53_GENTER_WORD', {16: 1},
                   ns['FC_XNU_PHASE53_GENTER_PREVIOUS'])
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        fte_after = fte_before[:2] + bytes([0x29]) + fte_before[3:]
        self.tables.memory.write(fte_record_pa, fte_after)
        feed_stage('FC_XNU_PHASE53_RETYPE_RETURN',
                   'FC_XNU_PHASE53_RETYPE_RETURN_LINKED',
                   'FC_XNU_PHASE53_RETYPE_RETURN_WORD',
                   {0: fte_va, 21: allocated_pa})
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-return-reached')
        self.assertTrue(self.endpoint.report['xnu_phase53_allocation_trace']
                        ['complete'])
        stages = self.endpoint.report['xnu_phase53_allocation_trace']['stages']
        self.assertEqual(len(stages), 7)
        self.assertEqual(stages[-1]['frame_table_after']['changed_bytes'][0],
                         {'offset': 2, 'before': 11, 'after': 41, 'xor': 34})
