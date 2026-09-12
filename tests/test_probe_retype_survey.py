"""Retype survey regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from probe_control_support import ProbeControlFixture
import os
import struct
import unittest
from types import SimpleNamespace
from sptm_entry_probe import Vel2StepFilter

@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class ProbeRetypeSurveyTests(ProbeControlFixture, unittest.TestCase):

    def test_phase53_retype_survey_stops_on_page_table_target(self):
        self._run_phase53_retype_survey_call()
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-retype-survey-target-reached')
        survey = self.endpoint.report['xnu_phase53_retype_survey']
        self.assertTrue(survey['complete'])
        self.assertTrue(survey['target_found'])
        self.assertTrue(survey['primary_target_found'])
        self.assertEqual(survey['completed_calls'], 1)
        self.assertEqual(survey['calls'][0]['frame_table_before']['records'][1]['type'], 11)
        self.assertEqual(survey['calls'][0]['frame_table_after']['records'][1]['type'], 20)

    def test_phase53_retype_survey_non_target_rearms_with_callback_echo(self):
        ns, state, fast_proxy, _, _, _ = self._run_phase53_retype_survey_call(target_type=41, limit=2)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['active'])
        self.assertEqual(state['stage'], 'seek-entry')
        self.assertEqual(state['completed_calls'], 1)
        self.assertEqual(fast_proxy.state['terminal_pc'], ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'])

    def test_phase53_retype_survey_classifies_bounded_step_limit(self):
        ns, state, _, feed, _, _ = self._run_phase53_retype_survey_call(target_type=41, limit=2)
        limit_pc = ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'] + 4
        feed(limit_pc, {}, limit_pc + 4, status=ns['FC_VEL2_STEP_FILTER_LIMIT'], steps=state['max_steps'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-retype-survey-step-limit-reached')
        survey = self.endpoint.report['xnu_phase53_retype_survey']
        self.assertTrue(survey['complete'])
        self.assertTrue(survey['bounded_no_target'])
        self.assertEqual(survey['completed_calls'], 1)
        self.assertTrue(survey['bounded_exhaustion']['complete'])

    def test_phase53_retype_survey_relays_verified_unrelated_gexit_return(self):
        ns, state, fast_proxy, feed, return_pc = self._prepare_phase53_unrelated_gexit_return()
        prior_aggregate = state['aggregate_steps']
        prior_rearms = state['rearms']
        feed(return_pc, {}, ns['FC_XNU_PHASE53_GEXIT'], status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'], spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['active'])
        self.assertEqual(state['stage'], 'seek-entry')
        self.assertEqual(state['range0'], ns['FC_XNU_RUNTIME_TEXT'])
        self.assertEqual(state['aggregate_steps'], prior_aggregate + 19)
        self.assertEqual(state['rearms'], prior_rearms + 1)
        self.assertEqual(fast_proxy.state['terminal_pc'], ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], return_pc)
        transition = self.endpoint.report['xnu_phase53_retype_survey']['world_transitions'][-1]
        self.assertEqual(transition['kind'], 'survey-unrelated-gexit-return')
        self.assertTrue(transition['complete'])

    def test_phase53_retype_survey_rejects_unrelated_return_flow_or_budget(self):
        ns, state, _, feed, return_pc = self._prepare_phase53_unrelated_gexit_return()
        feed(return_pc, {}, ns['FC_XNU_PHASE53_GEXIT'] + 4, status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'], spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        rejection = self.endpoint.report['xnu_phase53_retype_survey']['unrelated_return_rejection']
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-retype-survey-unrelated-return-gate-rejected')
        self.assertFalse(rejection['checks']['filter_previous_pc'])
        self.setUp()
        ns, state, _, feed, return_pc = self._prepare_phase53_unrelated_gexit_return()
        state['aggregate_steps'] = ns['FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS']
        feed(return_pc, {}, ns['FC_XNU_PHASE53_GEXIT'], status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'], spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        rejection = self.endpoint.report['xnu_phase53_retype_survey']['unrelated_return_rejection']
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-retype-survey-unrelated-return-gate-rejected')
        self.assertFalse(rejection['checks']['aggregate_budget'])

    def test_phase53_retype_survey_eret_switch_and_gexit_return_relay(self):
        ns, state, fast_proxy, feed, _, _ = self._run_phase53_retype_survey_call(stop_before_return=True)
        ns['a'].free_run = ns['a'].real_guarded = True
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1: self.s.ELR_GL12, self.s.SPSR_GL1: self.s.SPSR_GL12, self.s.ESR_GL1: self.s.ESR_EL12, self.s.ASPSR_GL1: self.s.AFSR1_EL12})
        txm_target = ns['FC_XNU_TXM_CONTEXT_TARGET']
        ns['classify_entry'] = lambda target, *args: dict(image='txm', segment='__TEXT_EXEC', target_pc=hex(target), linked_pc=ns['FC_XNU_TXM_CONTEXT_LINKED'], entry_matches=False, bytes_match=True, bytes_hex='00' * 32, instructions_executed=False)
        self.endpoint.hardware.values.update({self.s.ELR_GL12: txm_target, self.s.SPSR_GL12: 5056})
        eret_pc = ns['FC_XNU_TXM_CONTEXT_ERET_PC']
        eret_offset = eret_pc - 4 - ns['FC_IMAGE_BASE']
        sptm_source = bytearray(ns['sources']['sptm'])
        sptm_source.extend(b'\x00' * max(0, eret_offset + 4 - len(sptm_source)))
        struct.pack_into('<I', sptm_source, eret_offset, ns['FC_XNU_TXM_CONTEXT_ERET_WORD'])
        ns['sources']['sptm'] = bytes(sptm_source)
        sptm_segment = ns['layout']['images']['sptm']['segments']['__TEXT_EXEC']
        sptm_segment.update(fileoff=eret_offset, filesize=4)
        fast_proxy.state.update(active=True, status=Vel2StepFilter.RUNNING, steps=11, first_pc=ns['FC_XNU_PHASE53_GENTER'], previous_pc=eret_pc - 8, last_pc=eret_pc - 4, range0_hits=9, range1_hits=2, range_switches=1)
        eret = self.tables.event(1509967872, mode=5)
        eret['pc'] = eret_pc
        self.endpoint.feed(eret)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED), self.endpoint.report)
        self.assertEqual(state['range0'], ns['FC_TXM_RUNTIME_TEXT'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], txm_target)
        self.assertEqual(state['stage'], 'seek-genter-return')
        sptm_segment.update(fileoff=0, filesize=4)
        feed(ns['FC_XNU_PHASE53_GENTER_RETURN'], {30: ns['FC_XNU_PHASE53_GENTER_PREVIOUS']}, ns['FC_XNU_PHASE53_GEXIT'], status=ns['FC_VEL2_STEP_FILTER_TERMINAL'], spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(state['stage'], 'seek-wrapper-retab')
        self.assertEqual(state['range0'], ns['FC_XNU_RUNTIME_TEXT'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], ns['FC_XNU_PHASE53_GENTER_RETURN'])
        self.assertEqual(len(self.endpoint.report['xnu_phase53_retype_survey']['world_transitions']), 1)

    def test_phase53_retype_survey_rejects_outside_at_exact_terminal(self):
        ns, state, _, feed, _, _ = self._run_phase53_retype_survey_call(stop_before_return=True)
        state['range0'] = ns['FC_TXM_RUNTIME_TEXT']
        feed(ns['FC_XNU_PHASE53_GENTER_RETURN'], {30: ns['FC_XNU_PHASE53_GENTER_PREVIOUS']}, ns['FC_XNU_PHASE53_GEXIT'], status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'], spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        rejection = self.endpoint.report['xnu_phase53_retype_survey']['rejection']
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-retype-survey-genter-return-gate-rejected')
        self.assertFalse(rejection['checks']['filter_stopped'])

    def test_phase53_retype_survey_stops_at_call_limit(self):
        self._run_phase53_retype_survey_call(target_type=41, limit=1)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-retype-survey-call-limit-reached')
        self.assertTrue(self.endpoint.report['xnu_phase53_retype_survey']['limit_reached'])

    def test_phase53_retype_survey_rejects_locked_or_mismatched_fte(self):
        self._run_phase53_retype_survey_call(lock_before=True)
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-retype-survey-seek-entry-gate-rejected')
        self.assertFalse(self.endpoint.report['xnu_phase53_retype_survey']['rejection']['checks']['fte_center_unlocked'])
        self.setUp()
        self._run_phase53_retype_survey_call(target_type=41, limit=2, after_type=40)
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-retype-survey-seek-wrapper-retab-gate-rejected')
        self.assertFalse(self.endpoint.report['xnu_phase53_retype_survey']['rejection']['checks']['fte_center_type'])

    def test_phase53_descriptor_bind_activates_only_on_attempt104_path(self):
        ns, _, fast_proxy, _, _, _ = self._run_phase53_retype_survey_call(limit=8, descriptor_bind=True)
        state = ns['phase53_descriptor_bind_state']
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['active'])
        self.assertEqual(state['stage'], 'twig-branch')
        self.assertEqual(fast_proxy.state['terminal_pc'], ns['FC_XNU_PHASE53_TWIG_BRANCH'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'])
        self.assertTrue(self.endpoint.report['xnu_phase53_retype_survey']['complete'])
        self.setUp()
        ns, _, _, _, _, _ = self._run_phase53_retype_survey_call(limit=8, descriptor_bind=True, descriptor_wrong_caller=True)
        self.assertFalse(ns['phase53_descriptor_bind_state']['active'])
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-retype-survey-target-reached')
        self.setUp()
        ns, _, _, _, _, _ = self._run_phase53_retype_survey_call(limit=8, descriptor_bind=True, descriptor_call_index=2)
        self.assertTrue(ns['phase53_descriptor_bind_state']['active'])
        self.assertEqual(self.endpoint.report['xnu_phase53_descriptor_bind']['survey_call_index'], 2)

    def test_phase53_descriptor_bind_success_and_alternate_return(self):
        for alternate in (False, True):
            with self.subTest(alternate_return=alternate):
                if alternate:
                    self.setUp()
                ns, state, fast_proxy = self._run_phase53_descriptor_bind(alternate_return=alternate)
                self.assertFalse(state['active'])
                self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-descriptor-bind-reached')
                result = self.endpoint.report['xnu_phase53_descriptor_bind']
                self.assertTrue(result['complete'])
                self.assertEqual(result['descriptor_after'], hex(570425347))
                self.assertEqual(result['path'], 'ordinary')
                self.assertEqual(len(result['stages']), 7)
                self.assertEqual(fast_proxy.calls[-1][0], 'status')

    def test_phase53_descriptor_bind_does_not_require_leaf_provenance(self):
        _, state, _ = self._run_phase53_descriptor_bind(omit_parent_translations=True)
        self.assertFalse(state['active'])
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-descriptor-bind-reached')
        result = self.endpoint.report['xnu_phase53_descriptor_bind']
        self.assertTrue(result['complete'])
        self.assertNotIn('saved_leaf_va', result['stages'][-1])
        self.setUp()
        _, state, _ = self._run_phase53_descriptor_bind(leaf_page_bind=True, omit_parent_translations=True)
        self.assertFalse(state['active'])
        result = self.endpoint.report['xnu_phase53_descriptor_bind']
        self.assertFalse(result['rejection']['checks']['gate_readback'])
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-descriptor-bind-caller-return-gate-rejected')

    def test_phase53_descriptor_bind_rozone_retypes_then_maps(self):
        ns, state, _ = self._run_phase53_descriptor_bind(branch_path='rozone')
        self.assertFalse(state['active'])
        result = self.endpoint.report['xnu_phase53_descriptor_bind']
        self.assertTrue(result['complete'])
        self.assertEqual(result['path'], 'rozone')
        self.assertEqual(result['expected_fte_type'], '0x16')
        self.assertEqual(len(result['stages']), 14)
        self.assertEqual([stage['stage'] for stage in result['stages'][:8]], ['twig-branch', 'kernel-branch', 'rozone-end-branch', 'rozone-start-branch', 'rozone-retype1-call', 'rozone-retype1-return', 'rozone-retype2-call', 'rozone-retype2-return'])

    def test_phase53_descriptor_bind_kernel_non_rozone_routes_ordinary(self):
        for branch_path, expected_stages in (('kernel-ordinary-end', 9), ('kernel-ordinary-start', 10)):
            with self.subTest(branch_path=branch_path):
                if branch_path.endswith('start'):
                    self.setUp()
                _, state, _ = self._run_phase53_descriptor_bind(branch_path=branch_path)
                self.assertFalse(state['active'])
                result = self.endpoint.report['xnu_phase53_descriptor_bind']
                self.assertTrue(result['complete'])
                self.assertEqual(result['path'], 'ordinary-kernel')
                self.assertEqual(result['expected_fte_type'], '0x14')
                self.assertEqual(len(result['stages']), expected_stages)

    def test_phase53_descriptor_bind_rejects_rozone_retype_mismatches(self):
        cases = {'rozone-call1-args': 'args', 'rozone-default-type': 'fte_center_type', 'rozone-call2-args': 'args', 'rozone-final-type': 'fte_center_type'}
        for mismatch, check in cases.items():
            with self.subTest(mismatch=mismatch):
                self.setUp()
                _, state, _ = self._run_phase53_descriptor_bind(mismatch=mismatch, branch_path='rozone')
                self.assertFalse(state['active'])
                result = self.endpoint.report['xnu_phase53_descriptor_bind']
                self.assertFalse(result['rejection']['checks'][check])
                self.assertIn('gate-rejected', self.endpoint.report['stop_reason'])

    def test_phase53_descriptor_bind_rejects_rozone_intermediate_code(self):
        _, state, _ = self._run_phase53_descriptor_bind(mismatch='rozone-start-intermediate-code', branch_path='rozone')
        self.assertFalse(state['active'])
        rejection = self.endpoint.report['xnu_phase53_descriptor_bind']['rejection']
        self.assertTrue(rejection['checks']['intermediate_source'])
        self.assertFalse(rejection['checks']['intermediate_live'])
        self.assertIn('gate-rejected', self.endpoint.report['stop_reason'])

    def test_phase53_descriptor_bind_rejects_outside_at_exact_terminal(self):
        ns, state, _ = self._run_phase53_descriptor_bind(alternate_return=True, return_status=self.endpoint.namespace['FC_VEL2_STEP_FILTER_OUTSIDE'])
        rejection = self.endpoint.report['xnu_phase53_descriptor_bind']['rejection']
        self.assertFalse(state['active'])
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-descriptor-bind-genter-return-gate-rejected')
        self.assertFalse(rejection['checks']['filter_stopped'])

    def test_phase53_descriptor_bind_rejects_key_mismatches_and_budgets(self):
        cases = {'new-tte': 'new_tte', 'caller-mode': 'caller_mode_el1t', 'target-va': 'mapping_va', 'va-alignment': 'mapping_va_page_aligned', 'slot': 'computed_slot', 'old-table': 'old_not_valid_table', 'fte-pre': 'fte_center_unlocked', 'descriptor': 'descriptor', 'fte': 'fte_center_unlocked', 'fte-neighbor': 'fte_neighbors_unchanged', 'status': 'status_success', 'aggregate-budget': 'aggregate_budget', 'rearm-budget': 'rearm_budget'}
        for mismatch, check in cases.items():
            with self.subTest(mismatch=mismatch):
                self.setUp()
                self._run_phase53_descriptor_bind(mismatch=mismatch)
                result = self.endpoint.report['xnu_phase53_descriptor_bind']
                self.assertIn('rejection', result)
                self.assertFalse(result['rejection']['checks'][check])
                self.assertIn('gate-rejected', self.endpoint.report['stop_reason'])

    def test_phase53_descriptor_bind_allows_type_specific_fte_metadata(self):
        _, state, _ = self._run_phase53_descriptor_bind(mismatch='fte-metadata')
        self.assertFalse(state['active'])
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-descriptor-bind-reached')
        result = self.endpoint.report['xnu_phase53_descriptor_bind']
        self.assertTrue(result['complete'])
        self.assertEqual(result['stages'][-1]['fte_center_changed_offsets'], [6])
        self.setUp()
        _, state, _ = self._run_phase53_descriptor_bind(mismatch='fte-metadata', leaf_page_bind=True)
        self.assertFalse(state['active'])
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-leaf-page-bind-reached')
        self.assertTrue(self.endpoint.report['xnu_phase53_leaf_page_bind']['complete'])

    def test_phase53_leaf_page_bind_success(self):
        ns, state, fast_proxy = self._run_phase53_descriptor_bind(leaf_page_bind=True)
        self.assertFalse(state['active'])
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-leaf-page-bind-reached')
        self.assertTrue(self.endpoint.report['xnu_phase53_descriptor_bind']['complete'])
        result = self.endpoint.report['xnu_phase53_leaf_page_bind']
        self.assertTrue(result['complete'])
        self.assertEqual(result['leaf_descriptor'], hex(570442755))
        self.assertEqual(result['leaf_output_pa'], hex(570441728))
        transition = result['stages'][0]['output_fte_transition']
        self.assertEqual(transition['neighbor_index'], 2)
        self.assertEqual(transition['changed_offsets'], [2])
        self.assertEqual([stage['stage'] for stage in result['stages']], ['leaf-map-call', 'leaf-wrapper-entry', 'leaf-genter', 'leaf-genter-return', 'leaf-wrapper-retab', 'leaf-caller-return'])
        self.assertEqual(fast_proxy.state['max_steps'], ns['FC_XNU_PHASE53_LEAF_BIND_FAST_STEPS'])

    def test_phase53_leaf_page_bind_rejects_exact_gates(self):
        cases = {'root': 'root_same', 'flags': 'flags_zero', 'va-alignment': 'mapping_va_page_aligned', 'l2-index': 'same_l2_index', 'leaf-invalid': 'leaf_descriptor_valid', 'leaf-address': 'leaf_output_address_42bit', 'output-zero': 'leaf_output_nonzero', 'output-outside': 'leaf_output_owned', 'parent-va': 'mapping_va_from_parent', 'parent-lr': 'saved_parent_lr', 'parent-call-code': 'leaf_parent_call_live', 'source-type-load-code': 'source_type_load_live', 'table-nonzero': 'l3_table_all_zero', 'prep-code': 'prep0_live', 'output-fte-type': 'output_fte_retype_0b_to_19', 'output-fte-metadata': 'output_fte_only_type_changed', 'unrelated-fte-neighbor': 'fte_unrelated_records_unchanged', 'aggregate-budget': 'aggregate_budget', 'rearm-budget': 'rearm_budget', 'selector': 'selector', 'wrong-slot': 'l3_slot_written', 'l2-changed': 'l2_descriptor_unchanged', 'fte': 'fte_center_unlocked', 'fte-table-metadata': 'fte_table_metadata_transition', 'fte-output-metadata': 'fte_output_metadata_transition', 'fte-unrelated-after': 'fte_unrelated_neighbor_unchanged', 'status': 'status_success'}
        for mismatch, check in cases.items():
            with self.subTest(mismatch=mismatch):
                self.setUp()
                _, state, _ = self._run_phase53_descriptor_bind(leaf_page_bind=True, leaf_mismatch=mismatch)
                self.assertFalse(state['active'])
                result = self.endpoint.report['xnu_phase53_leaf_page_bind']
                self.assertFalse(result['rejection']['checks'][check])
                self.assertIn('phase53-leaf-page-bind-', self.endpoint.report['stop_reason'])
                self.assertIn('gate-rejected', self.endpoint.report['stop_reason'])

    def test_phase53_leaf_page_bind_rejects_expand_provenance(self):
        cases = {'parent-pmap-root': 'pmap_root_same', 'parent-lr': 'saved_parent_lr', 'parent-call-code': 'parent_call_live'}
        for mismatch, check in cases.items():
            with self.subTest(mismatch=mismatch):
                self.setUp()
                _, state, _ = self._run_phase53_descriptor_bind(mismatch=mismatch, leaf_page_bind=True)
                self.assertFalse(state['active'])
                result = self.endpoint.report['xnu_phase53_descriptor_bind']
                self.assertFalse(result['rejection']['checks'][check])
                self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-descriptor-bind-caller-return-gate-rejected')

    def test_phase53_leaf_page_bind_rearms_only_unrelated_parent_frame(self):
        _, state, _ = self._run_phase53_descriptor_bind(leaf_page_bind=True, leaf_mismatch='unrelated-once')
        self.assertFalse(state['active'])
        result = self.endpoint.report['xnu_phase53_leaf_page_bind']
        self.assertTrue(result['complete'])
        self.assertEqual(len(result['unrelated_candidates']), 1)
        self.assertTrue(result['unrelated_candidates'][0]['complete'])
        self.setUp()
        _, state, _ = self._run_phase53_descriptor_bind(leaf_page_bind=True, leaf_mismatch='unrelated-budget')
        self.assertFalse(state['active'])
        rejection = self.endpoint.report['xnu_phase53_leaf_page_bind']['rejection']
        self.assertFalse(rejection['checks']['rearm_budget'])
        self.assertEqual(self.endpoint.report['stop_reason'], 'phase53-leaf-page-bind-unrelated-gate-rejected')

    def test_phase53_descriptor_bind_eret_and_authenticated_retab_relays(self):
        ns, state, fast_proxy = self._run_phase53_descriptor_bind(stop_after='genter')
        ns['a'].free_run = ns['a'].real_guarded = True
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={self.s.ELR_GL1: self.s.ELR_GL12, self.s.SPSR_GL1: self.s.SPSR_GL12, self.s.ESR_GL1: self.s.ESR_EL12, self.s.ASPSR_GL1: self.s.AFSR1_EL12})
        txm_target = ns['FC_XNU_TXM_CONTEXT_TARGET']
        ns['classify_entry'] = lambda target, *args: dict(image='txm', segment='__TEXT_EXEC', target_pc=hex(target), linked_pc=ns['FC_XNU_TXM_CONTEXT_LINKED'], entry_matches=False, bytes_match=True, bytes_hex='00' * 32, instructions_executed=False)
        self.endpoint.hardware.values.update({self.s.ELR_GL12: txm_target, self.s.SPSR_GL12: 5056})
        eret_pc = ns['FC_XNU_TXM_CONTEXT_ERET_PC']
        eret_offset = eret_pc - 4 - ns['FC_IMAGE_BASE']
        sptm_source = bytearray(ns['sources']['sptm'])
        sptm_source.extend(b'\x00' * max(0, eret_offset + 4 - len(sptm_source)))
        struct.pack_into('<I', sptm_source, eret_offset, ns['FC_XNU_TXM_CONTEXT_ERET_WORD'])
        ns['sources']['sptm'] = bytes(sptm_source)
        ns['layout']['images']['sptm']['segments']['__TEXT_EXEC'].update(fileoff=eret_offset, filesize=4)
        fast_proxy.state.update(active=True, status=Vel2StepFilter.RUNNING, steps=11, first_pc=state['segment_start'], expected_first_pc=state['segment_start'], previous_pc=eret_pc - 8, last_pc=eret_pc - 4, range0_hits=9, range1_hits=2, range_switches=1, terminal_pc=state['terminal_pc'], max_steps=ns['FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS'], range0_start=state['range0'][0], range0_end=state['range0'][1], range1_start=ns['FC_SPTM_RUNTIME_TEXT'][0], range1_end=ns['FC_SPTM_RUNTIME_TEXT'][1])
        eret = self.tables.event(1509967872, mode=5)
        eret['pc'] = eret_pc
        self.endpoint.feed(eret)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(state['range0'], ns['FC_TXM_RUNTIME_TEXT'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], txm_target)
        self.setUp()
        ns, state, fast_proxy = self._run_phase53_descriptor_bind(stop_after='pre-map-call')
        state.update(range0=ns['FC_TXM_RUNTIME_TEXT'], segment_start=ns['FC_XNU_TXM_CONTEXT_TARGET'])
        fast_proxy.state.update(active=False, status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'], steps=7, first_pc=state['segment_start'], expected_first_pc=state['segment_start'], previous_pc=ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_PREVIOUS'], last_pc=ns['FC_XNU_TXM_HANDLER_CMD1_RETAB'], range0_hits=5, range1_hits=2, range_switches=1, terminal_pc=state['terminal_pc'], max_steps=ns['FC_XNU_PHASE53_DESCRIPTOR_BIND_FAST_STEPS'], range0_start=state['range0'][0], range0_end=state['range0'][1], range1_start=ns['FC_SPTM_RUNTIME_TEXT'][0], range1_end=ns['FC_SPTM_RUNTIME_TEXT'][1])
        retab = self.tables.event(3388997666, mode=4)
        retab['pc'] = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB']
        retab['spsr'] = ns['FC_XNU_TXM_HANDLER_CMD1_RETAB_SPSR']
        retab['regs'][30] = ns['FC_XNU_PHASE53_PRE_MAP_CALL']
        self.endpoint.feed(retab)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(state['range0'], ns['FC_XNU_RUNTIME_TEXT'])
        self.assertEqual(fast_proxy.state['terminal_pc'], ns['FC_XNU_PHASE53_MAP_WRAPPER_ENTRY'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], ns['FC_XNU_TXM_HANDLER_CMD1_RETAB'])
        self.assertTrue(self.endpoint.report['xnu_phase53_descriptor_bind']['world_transitions'][-1]['complete'])
