"""Txm entry regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from probe_control_support import ProbeControlFixture
import os
import struct
import unittest
from phase53_retype_hvc import (GENTER_SITE, POST_SITE, PRE_SITE,
                                RETYPE_HVC_SITES, RetypeHvcStateMachine)


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class ProbeTxmEntryTests(ProbeControlFixture, unittest.TestCase):

    def _activate_phase53_retype_hvc_for_unrelated_eret(self,
                                                        continuations=None):
        ns = self.endpoint.namespace
        ns['RETYPE_HVC_SITES'] = RETYPE_HVC_SITES
        runtime_slide = (RETYPE_HVC_SITES[0].runtime_pc -
                         RETYPE_HVC_SITES[0].linked_pc)
        source_words = {site.linked_pc: struct.pack('<I', site.source_word)
                        for site in RETYPE_HVC_SITES}
        ns['phase53_kernel_runtime'] = lambda linked: linked + runtime_slide
        ns['phase53_kernel_source'] = lambda linked, size: (
            source_words[linked] if size == 4 else b'')
        ns['a'].xnu_phase53_retype_hvc_fast_path = True
        self.endpoint.hardware.values.update({
            self.s.TTBR0_EL12: self.tables.low,
            self.s.TTBR1_EL12: self.tables.high,
        })
        machine = RetypeHvcStateMachine(max_calls=64)
        machine.observe(PRE_SITE.post_hvc_pc, PRE_SITE.hvc_word)
        machine.observe(GENTER_SITE.post_hvc_pc, GENTER_SITE.hvc_word)
        records = list(continuations or [])
        ns['phase53_retype_hvc_state'].update(
            active=True, mode='three-site-hvc', patches_live=True,
            roots={'ttbr0': self.tables.low, 'ttbr1': self.tables.high},
            stage='hvc-post', filter_disabled=True,
            gl1_activation_verified=True, machine=machine,
            native_continuations=records, continuation_limit=128,
            repeated_continuation_limit=64)
        self.endpoint.report['xnu_phase53_retype_hvc_fast_path'] = dict(
            requested=True, activated=True, enabled=True,
            current_stage='POST', expected_phase='POST',
            native_continuation_limit=128,
            native_continuations=list(records))
        return ns

    def _phase53_patched_wrapper_return_classification(self, ns, drift=False):
        linked_pc = POST_SITE.linked_pc - 4
        source = (struct.pack('<' + 'I' * 4,
                              *ns['FC_XNU_PHASE53_RETYPE_WRAPPER_WORDS'][6:])
                  + bytes.fromhex('112233445566778899aabbccddeeff00'))
        live = bytearray(source)
        struct.pack_into('<I', live, POST_SITE.linked_pc - linked_pc,
                         POST_SITE.hvc_word)
        if drift:
            live[0] ^= 1
        ns['phase53_kernel_source'] = lambda linked, size: (
            source[:size] if linked == linked_pc and size <= len(source)
            else b'')
        return dict(
            image='kernelcache', segment='__TEXT_EXEC',
            target_pc=hex(POST_SITE.runtime_pc - 4), pa=hex(0x20000000),
            linked_pc=hex(linked_pc), entry_matches=False, bytes_match=False,
            bytes_hex=bytes(live).hex(), instructions_executed=False)

    def test_phase53_retype_hvc_relays_exact_unrelated_eret_natively(self):
        ns = self._activate_phase53_retype_hvc_for_unrelated_eret()
        _, after = self._txm_context_entry_gate(
            handler='cmd1-completion-trace', x16=0)

        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED),
                         self.endpoint.report)
        self.assertEqual(after.elr, ns['FC_XNU_TXM_CONTEXT_TARGET'])
        self.assertFalse(after.spsr.SS)
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)
        self.assertNotIn('stop_reason', self.endpoint.report)
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertNotIn('xnu_txm_context_entry_one_step',
                         self.endpoint.report)
        self.assertEqual(self.endpoint.report['eret_classifications'][-1][
            'decision'], 'phase53-retype-hvc-native-continuation')
        continuations = self.endpoint.report[
            'xnu_phase53_retype_hvc_fast_path']['native_continuations']
        self.assertEqual(len(continuations), 1)
        self.assertTrue(continuations[0]['complete'])
        self.assertEqual(continuations[0]['target_pc'],
                         hex(ns['FC_XNU_TXM_CONTEXT_TARGET']))
        self.assertEqual(continuations[0]['source_hex'], struct.pack(
            '<I', ns['FC_XNU_TXM_CONTEXT_ERET_WORD']).hex())
        self.assertEqual(continuations[0]['resume_mode'],
                         'native-ss-clear-filter-off')
        self.assertFalse(any(call[0] == 'msr' and
                             call[1] == self.s.MDSCR_EL1 and call[2] & 1
                             for call in self.endpoint.hardware.calls))

    def test_phase53_retype_hvc_accepts_patched_kernel_wrapper_return(self):
        ns = self._activate_phase53_retype_hvc_for_unrelated_eret()
        classification = self._phase53_patched_wrapper_return_classification(ns)
        _, after = self._txm_context_entry_gate(
            handler='cmd1-completion-trace', target=POST_SITE.runtime_pc - 4,
            classification=classification)

        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED),
                         self.endpoint.report)
        self.assertEqual(after.elr, POST_SITE.runtime_pc - 4)
        self.assertFalse(after.spsr.SS)
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)
        self.assertNotIn('stop_reason', self.endpoint.report)
        continuation = self.endpoint.report[
            'xnu_phase53_retype_hvc_fast_path']['native_continuations'][-1]
        self.assertTrue(continuation['checks']['target_source_match'])
        self.assertEqual(continuation['target_pc'],
                         hex(POST_SITE.runtime_pc - 4))
        self.assertEqual(self.endpoint.report['eret_classifications'][-1][
            'decision'], 'phase53-retype-hvc-native-continuation')
        self.assertNotIn('xnu_txm_context_entry_one_step', self.endpoint.report)

    def test_phase53_retype_hvc_certifies_exact_eret_for_aic_replay(self):
        ns = self._activate_phase53_retype_hvc_for_unrelated_eret()
        ns['a'].xnu_aic_observe = True
        self.endpoint.report['xnu_aic_observe'] = dict(active=True)

        self._txm_context_entry_gate(
            handler='cmd1-completion-trace', x16=0,
            target_spsr=0x600013c0)

        certificates = ns['aic_observation_state']['certified_erets']
        self.assertEqual(len(certificates), 1)
        self.assertEqual(certificates[0]['target_spsr'], hex(0x600013c0))
        self.assertEqual(self.endpoint.report['xnu_aic_observe'][
            'certified_erets'], certificates)
        self.assertEqual(self.endpoint.report['eret_classifications'][-1][
            'decision'], 'phase53-retype-hvc-native-continuation')

        ns['phase53_retype_hvc_state'].update(
            active=False, patches_live=False)
        ns['aic_observation_state']['active'] = True
        self._txm_context_entry_gate(
            handler='cmd1-completion-trace', x16=0,
            target_spsr=0x400013c0)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'eret-unclassified-target')
        self.assertEqual(ns['aic_observation_state']['replayed_erets'], 0)

        self._txm_context_entry_gate(
            handler='cmd1-completion-trace', x16=0,
            target_spsr=0x600013c0)

        self.assertNotIn('stop_reason', self.endpoint.report)
        self.assertEqual(self.endpoint.report['eret_classifications'][-1][
            'decision'], 'aic-certified-world-transition')
        self.assertEqual(ns['aic_observation_state']['replayed_erets'], 1)

    def test_phase53_retype_hvc_rejects_wrapper_return_byte_drift(self):
        ns = self._activate_phase53_retype_hvc_for_unrelated_eret()
        classification = self._phase53_patched_wrapper_return_classification(
            ns, drift=True)
        before, after = self._txm_context_entry_gate(
            handler='cmd1-completion-trace', target=POST_SITE.runtime_pc - 4,
            classification=classification)

        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.codec.build(after),
                         self.endpoint.codec.build(before))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-hvc-world-transition-gate-rejected')
        rejection = self.endpoint.report[
            'xnu_phase53_retype_hvc_fast_path'][
                'native_continuation_rejection']
        self.assertFalse(rejection['checks']['target_source_match'])
        self.assertFalse(ns['phase53_retype_hvc_state']['active'])
        self.assertTrue(ns['phase53_retype_hvc_state']['failed'])
        self.assertNotIn('xnu_txm_context_entry_one_step', self.endpoint.report)

    def test_phase53_retype_hvc_unrelated_eret_limit_fails_closed(self):
        ns = self._activate_phase53_retype_hvc_for_unrelated_eret(
            [dict(complete=True)] * 128)
        before, after = self._txm_context_entry_gate(
            handler='cmd1-completion-trace', x16=0)

        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.codec.build(after),
                         self.endpoint.codec.build(before))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-hvc-native-continuation-limit-reached')
        self.assertTrue(ns['phase53_retype_hvc_state']['active'])
        self.assertFalse(ns['phase53_retype_hvc_state'].get('failed', False))
        self.assertEqual(len(self.endpoint.report[
            'xnu_phase53_retype_hvc_fast_path']['native_continuations']), 128)
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertNotIn('xnu_txm_context_entry_one_step', self.endpoint.report)

    def test_txm_context_entry_gate_executes_exactly_one_mov_sp(self):
        ns = self.endpoint.namespace
        _, armed = self._txm_context_entry_gate()
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(armed.elr, ns['FC_XNU_TXM_CONTEXT_TARGET'])
        self.assertEqual(armed.spsr.SS, 1)
        self.assertTrue(ns['txm_context_step_state']['active'])
        self.assertTrue(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)
        self.assertNotIn('stop_reason', self.endpoint.report)
        self.assertTrue(all(self.endpoint.report['xnu_txm_context_entry_one_step']
                            ['checks'].values()))
        step = self.tables.event(0xcb000022)
        step['pc'] = ns['FC_XNU_TXM_CONTEXT_TARGET'] + 4
        step['spsr'] = 0x13c0
        step['regs'][0] = ns['FC_XNU_TXM_CONTEXT_STACK']
        step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
        step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
        step['sp'][0] = ns['FC_XNU_TXM_CONTEXT_STACK']
        self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-one-step-complete')
        result = self.endpoint.report['xnu_txm_context_entry_one_step']['result']
        self.assertTrue(result['exactly_one_instruction'])
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)

    def test_txm_context_entry_gate_rejects_caller_mismatch_without_mutation(self):
        before, after = self._txm_context_entry_gate(x16=0)
        self.assertEqual(self.endpoint.codec.build(after), self.endpoint.codec.build(before))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        self.assertFalse(self.endpoint.namespace['txm_context_step_state']['active'])
        self.assertFalse(any(call[0] == 'msr' and call[1] == self.s.MDSCR_EL1
                             for call in self.endpoint.hardware.calls))
        self.assertFalse(self.endpoint.report['xnu_txm_context_entry_one_step']
                         ['checks']['caller_selector_x16'])

    def test_txm_context_entry_one_step_mismatch_stops_without_second_resume(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate()
        step = self.tables.event(0xcb000022)
        step['pc'] = ns['FC_XNU_TXM_CONTEXT_TARGET'] + 8
        step['spsr'] = 0x13c0
        step['regs'][0] = ns['FC_XNU_TXM_CONTEXT_STACK']
        step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
        step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
        step['sp'][0] = ns['FC_XNU_TXM_CONTEXT_STACK']
        self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-one-step-mismatch')
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_txm_context_entry_register_prefix_stops_before_casb(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(prefix=True)
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 15)
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            self.endpoint.feed(step)
            expected_reply = (self.endpoint.EXC_RET.EXIT_GUEST if index == len(states) - 1
                              else self.endpoint.EXC_RET.HANDLED)
            self.assertEqual(self.endpoint.replies[-1], int(expected_reply))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-register-prefix-complete')
        prefix = self.endpoint.report['xnu_txm_context_entry_register_prefix']
        self.assertTrue(prefix['complete'])
        self.assertEqual(len(prefix['steps']), 15)
        self.assertEqual(prefix['result']['observed_pc'], '0xfffffe0017031084')

    def test_txm_context_stack_claim_verifies_single_zero_to_one_casb(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(claim=True)
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 16)
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == len(states) - 1:
                self.tables.memory.write(ns['txm_context_step_state']['first_touch_pa'], b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-stack-claim-one-step-complete')
        claim = self.endpoint.report['xnu_txm_context_stack_claim_one_step']
        self.assertEqual(claim['claim_before_hex'], '00')
        self.assertEqual(claim['result']['claim_after_hex'], '01')
        self.assertTrue(claim['result']['checks']['stack_claimed_zero_to_one'])

    def test_txm_context_stack_metadata_init_stops_before_x18_branch(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(metadata=True)
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 21)
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-stack-metadata-init-complete')
        metadata = self.endpoint.report['xnu_txm_context_stack_metadata_init']
        self.assertTrue(metadata['complete'])
        self.assertEqual(metadata['metadata_before_hex'], {
            'state': '00', 'zero_word': '00000000',
            'claim': '00', 'zero_byte': '00'})
        self.assertEqual(metadata['result']['observed_pc'], '0xfffffe00170310a8')
        self.assertEqual(metadata['result']['claim_after_hex'], '01')
        self.assertEqual(metadata['result']['metadata_page_diff_offsets'],
                         ['0x3c00', '0x3c58'])
        self.assertTrue(metadata['result']['checks']['metadata_final_values'])
        self.assertTrue(metadata['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_context_stack_metadata_init_rejects_unexpected_page_write(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(metadata=True)
        states = ns['txm_context_step_state']['expected_states']
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
                self.tables.memory.write(frame_pa + 0x20, b'\xff')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-stack-metadata-init-mismatch')
        self.assertFalse(self.endpoint.report['xnu_txm_context_stack_metadata_init']
                         ['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_context_stack_metadata_init_never_reads_unowned_stack_leaf(self):
        ns = self.endpoint.namespace
        outside = self.tables.memory.base + self.tables.memory.size
        self._txm_context_entry_gate(metadata=True, stack_pa=outside)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        gate = self.endpoint.report['xnu_txm_context_stack_metadata_init']
        self.assertFalse(gate['checks']['stack_mapping'])
        self.assertIsNone(gate['metadata_page_before_sha256'])
        self.assertFalse(any(address == outside and size == ns['PAGE']
                             for address, size in self.tables.memory.reads))

    def test_txm_context_stack_metadata_init_rejects_changed_source_before_resume(self):
        ns = self.endpoint.namespace
        changed = bytearray(ns['FC_XNU_TXM_CONTEXT_POST_CLAIM_BYTES'])
        changed[-1] ^= 1
        self._txm_context_entry_gate(metadata=True,
                                     post_claim_source=bytes(changed))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        gate = self.endpoint.report['xnu_txm_context_stack_metadata_init']
        self.assertFalse(gate['checks']['post_claim_source'])
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)

    def test_txm_context_stack_metadata_init_rejects_wrong_cbz_path(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(metadata=True)
        states = ns['txm_context_step_state']['expected_states']
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states[:17]):
            step = self.tables.event(0xcb000022)
            step['pc'] = (ns['FC_XNU_TXM_CONTEXT_TARGET'] + 0x50
                          if index == 16 else expected['pc'])
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-stack-metadata-init-mismatch')
        self.assertFalse(self.endpoint.report['xnu_txm_context_stack_metadata_init']
                         ['result']['checks']['expected_pc'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_txm_context_stack_metadata_init_stops_if_claim_did_not_store(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(metadata=True)
        states = ns['txm_context_step_state']['expected_states']
        for expected in states[:16]:
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-stack-metadata-init-mismatch')
        result = self.endpoint.report['xnu_txm_context_stack_metadata_init']['result']
        self.assertFalse(result['checks']['memory_claim'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_txm_context_x18_branch_one_step_stops_before_target_branch(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(x18_branch=True)
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 22)
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-x18-branch-one-step-complete')
        branch = self.endpoint.report['xnu_txm_context_x18_branch_one_step']
        self.assertTrue(branch['complete'])
        self.assertTrue(branch['checks']['x18_branch_source'])
        self.assertEqual(branch['result']['observed_pc'], '0xfffffe00170310b8')
        self.assertEqual(branch['result']['extension_instructions'], 1)
        self.assertTrue(branch['result']['branch_taken'])
        self.assertTrue(branch['result']['fallthrough_svc_not_executed'])
        self.assertFalse(branch['result']['outbound_branch_executed'])
        self.assertEqual(branch['result']['metadata_page_diff_offsets'],
                         ['0x3c00', '0x3c58'])
        self.assertTrue(branch['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_context_x18_branch_rejects_changed_landing_word_before_resume(self):
        ns = self.endpoint.namespace
        changed = bytearray(ns['FC_XNU_TXM_CONTEXT_X18_WINDOW_BYTES'][4:])
        changed[-1] ^= 1
        self._txm_context_entry_gate(x18_branch=True,
                                     x18_tail_source=bytes(changed))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        branch = self.endpoint.report['xnu_txm_context_x18_branch_one_step']
        self.assertFalse(branch['checks']['x18_branch_source'])
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)

    def test_txm_context_x18_branch_rejects_svc_fallthrough(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(x18_branch=True)
        states = ns['txm_context_step_state']['expected_states']
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = (ns['FC_XNU_TXM_CONTEXT_TARGET'] + 0x70
                          if index == len(states) - 1 else expected['pc'])
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = (0 if index == len(states) - 1
                                else ns['FC_XNU_TXM_CONTEXT_X18'])
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-x18-branch-one-step-mismatch')
        result = self.endpoint.report['xnu_txm_context_x18_branch_one_step']['result']
        self.assertFalse(result['checks']['expected_pc'])
        self.assertFalse(result['checks']['x18_unchanged'])
        self.assertFalse(result['branch_taken'])
        self.assertIsNone(result['extension_instructions'])
        self.assertIsNone(result['outbound_branch_executed'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))

    def test_txm_context_outbound_branch_stops_before_pacibsp(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(outbound=True)
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 23)
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-outbound-branch-one-step-complete')
        outbound = self.endpoint.report['xnu_txm_context_outbound_branch_one_step']
        self.assertTrue(outbound['complete'])
        self.assertTrue(outbound['checks']['outbound_target_source'])
        self.assertTrue(outbound['checks']['outbound_target_guarded_gl0_rx'])
        self.assertEqual(outbound['result']['observed_pc'], '0xfffffe001702edec')
        self.assertEqual(outbound['result']['extension_instructions'], 1)
        self.assertTrue(outbound['result']['outbound_branch_taken'])
        self.assertFalse(outbound['result']['pacibsp_executed'])
        self.assertTrue(outbound['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_context_outbound_branch_rejects_changed_target_source(self):
        ns = self.endpoint.namespace
        changed = bytearray(ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES'])
        changed[0] ^= 1
        self._txm_context_entry_gate(outbound=True,
                                     outbound_target_source=bytes(changed))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        outbound = self.endpoint.report['xnu_txm_context_outbound_branch_one_step']
        self.assertFalse(outbound['checks']['outbound_target_source'])
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)

    def test_txm_context_outbound_branch_rejects_changed_live_target(self):
        ns = self.endpoint.namespace
        changed = bytearray(ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET_BYTES'])
        changed[4] ^= 1
        self._txm_context_entry_gate(outbound=True,
                                     outbound_live_source=bytes(changed))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-context-entry-gate-rejected')
        outbound = self.endpoint.report['xnu_txm_context_outbound_branch_one_step']
        self.assertFalse(outbound['checks']['outbound_target_live_bytes'])
        self.assertFalse(ns['txm_context_step_state']['active'])
        self.assertFalse(self.endpoint.hardware.values[self.s.MDSCR_EL1] & 1)

    def test_txm_handler_prologue_stops_before_first_stp(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(handler='prologue')
        states = ns['txm_context_step_state']['expected_states']
        self.assertEqual(len(states), 25)
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        signed_x30 = 0xa5a5a5a5a5a5a5a5
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index >= 23:
                step['regs'][30] = signed_x30
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-prologue-complete')
        prologue = self.endpoint.report['xnu_txm_handler_boundary']
        self.assertTrue(prologue['complete'])
        self.assertEqual(prologue['steps'][23]['captured_regs'],
                         {'x30': hex(signed_x30)})
        self.assertTrue(prologue['result']['checks']['captured_x30_unchanged'])
        self.assertEqual(prologue['result']['observed_pc'], '0xfffffe001702edf4')
        self.assertEqual(prologue['result']['observed_sp_el0'],
                         '0xfffffdf00018bb90')
        self.assertEqual(prologue['result']['extension_instructions'], 2)
        self.assertTrue(prologue['result']['pacibsp_executed'])
        self.assertEqual(prologue['result']['stack_allocation_bytes'], 0x70)
        self.assertFalse(prologue['result']['first_stp_executed'])
        self.assertTrue(prologue['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_handler_prologue_rejects_post_pac_x30_drift(self):
        ns = self.endpoint.namespace
        self._txm_context_entry_gate(handler='prologue')
        states = ns['txm_context_step_state']['expected_states']
        frame_pa = ns['txm_context_step_state']['metadata_frame_pa']
        for index, expected in enumerate(states):
            step = self.tables.event(0xcb000022)
            step['pc'] = expected['pc']
            step['spsr'] = expected['spsr']
            step['sp'][0] = expected['sp']
            step['regs'][16] = ns['FC_XNU_TXM_CONTEXT_SELECTOR']
            step['regs'][18] = ns['FC_XNU_TXM_CONTEXT_X18']
            for register, value in expected['regs'].items():
                step['regs'][register] = value
            if index >= 23:
                step['regs'][30] = 0x1111 + index
            if index == 15:
                self.tables.memory.write(frame_pa + 0x58, b'\x01')
            elif index == 20:
                self.tables.memory.write(frame_pa, b'\x01')
            self.endpoint.feed(step)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-prologue-mismatch')
        result = self.endpoint.report['xnu_txm_handler_boundary']['result']
        self.assertFalse(result['checks']['captured_x30_unchanged'])
        self.assertIsNone(result['extension_instructions'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
