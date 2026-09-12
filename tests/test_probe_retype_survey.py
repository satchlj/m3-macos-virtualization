"""Retype survey regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

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
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-target-reached')
        survey = self.endpoint.report['xnu_phase53_retype_survey']
        self.assertTrue(survey['complete'])
        self.assertTrue(survey['target_found'])
        self.assertTrue(survey['primary_target_found'])
        self.assertEqual(survey['completed_calls'], 1)
        self.assertEqual(survey['calls'][0]['frame_table_before'][
            'records'][1]['type'], 0xb)
        self.assertEqual(survey['calls'][0]['frame_table_after'][
            'records'][1]['type'], 0x14)

    def test_phase53_retype_survey_non_target_rearms_with_callback_echo(self):
        ns, state, fast_proxy, _, _, _ = (
            self._run_phase53_retype_survey_call(target_type=0x29, limit=2))
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['active'])
        self.assertEqual(state['stage'], 'seek-entry')
        self.assertEqual(state['completed_calls'], 1)
        self.assertEqual(fast_proxy.state['terminal_pc'],
                         ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'])
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         ns['FC_XNU_PHASE53_RETYPE_WRAPPER_RETAB'])

    def test_phase53_retype_survey_relays_verified_unrelated_gexit_return(self):
        ns, state, fast_proxy, feed, return_pc = (
            self._prepare_phase53_unrelated_gexit_return())
        prior_aggregate = state['aggregate_steps']
        prior_rearms = state['rearms']
        feed(return_pc, {}, ns['FC_XNU_PHASE53_GEXIT'],
             status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'],
             spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertTrue(state['active'])
        self.assertEqual(state['stage'], 'seek-entry')
        self.assertEqual(state['range0'], ns['FC_XNU_RUNTIME_TEXT'])
        self.assertEqual(state['aggregate_steps'], prior_aggregate + 19)
        self.assertEqual(state['rearms'], prior_rearms + 1)
        self.assertEqual(fast_proxy.state['terminal_pc'],
                         ns['FC_XNU_PHASE53_RETYPE_WRAPPER_ENTRY'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], return_pc)
        transition = self.endpoint.report['xnu_phase53_retype_survey'][
            'world_transitions'][-1]
        self.assertEqual(transition['kind'],
                         'survey-unrelated-gexit-return')
        self.assertTrue(transition['complete'])

    def test_phase53_retype_survey_rejects_unrelated_return_flow_or_budget(self):
        ns, state, _, feed, return_pc = (
            self._prepare_phase53_unrelated_gexit_return())
        feed(return_pc, {}, ns['FC_XNU_PHASE53_GEXIT'] + 4,
             status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'],
             spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        rejection = self.endpoint.report['xnu_phase53_retype_survey'][
            'unrelated_return_rejection']
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-unrelated-return-gate-rejected')
        self.assertFalse(rejection['checks']['filter_previous_pc'])

        self.setUp()
        ns, state, _, feed, return_pc = (
            self._prepare_phase53_unrelated_gexit_return())
        state['aggregate_steps'] = ns[
            'FC_XNU_PHASE53_RETYPE_SURVEY_TOTAL_STEPS']
        feed(return_pc, {}, ns['FC_XNU_PHASE53_GEXIT'],
             status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'],
             spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        rejection = self.endpoint.report['xnu_phase53_retype_survey'][
            'unrelated_return_rejection']
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-unrelated-return-gate-rejected')
        self.assertFalse(rejection['checks']['aggregate_budget'])

    def test_phase53_retype_survey_eret_switch_and_gexit_return_relay(self):
        ns, state, fast_proxy, feed, _, _ = (
            self._run_phase53_retype_survey_call(stop_before_return=True))
        ns['a'].free_run = ns['a'].real_guarded = True
        ns['HV'] = SimpleNamespace(MSR_REDIRECTS={
            self.s.ELR_GL1: self.s.ELR_GL12,
            self.s.SPSR_GL1: self.s.SPSR_GL12,
            self.s.ESR_GL1: self.s.ESR_EL12,
            self.s.ASPSR_GL1: self.s.AFSR1_EL12})
        txm_target = ns['FC_XNU_TXM_CONTEXT_TARGET']
        ns['classify_entry'] = lambda target, *args: dict(
            image='txm', segment='__TEXT_EXEC', target_pc=hex(target),
            linked_pc=ns['FC_XNU_TXM_CONTEXT_LINKED'], entry_matches=False,
            bytes_match=True, bytes_hex='00' * 32,
            instructions_executed=False)
        self.endpoint.hardware.values.update({
            self.s.ELR_GL12: txm_target,
            self.s.SPSR_GL12: 0x13c0,
        })
        eret_pc = ns['FC_XNU_TXM_CONTEXT_ERET_PC']
        eret_offset = eret_pc - 4 - ns['FC_IMAGE_BASE']
        sptm_source = bytearray(ns['sources']['sptm'])
        sptm_source.extend(b'\0' * max(
            0, eret_offset + 4 - len(sptm_source)))
        struct.pack_into('<I', sptm_source, eret_offset,
                         ns['FC_XNU_TXM_CONTEXT_ERET_WORD'])
        ns['sources']['sptm'] = bytes(sptm_source)
        sptm_segment = ns['layout']['images']['sptm']['segments'][
            '__TEXT_EXEC']
        sptm_segment.update(fileoff=eret_offset, filesize=4)
        fast_proxy.state.update(
            active=True, status=Vel2StepFilter.RUNNING, steps=11,
            first_pc=ns['FC_XNU_PHASE53_GENTER'],
            previous_pc=eret_pc - 8, last_pc=eret_pc - 4,
            range0_hits=9, range1_hits=2, range_switches=1)
        eret = self.tables.event(0x5a004800, mode=5)
        eret['pc'] = eret_pc
        self.endpoint.feed(eret)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED),
                         self.endpoint.report)
        self.assertEqual(state['range0'], ns['FC_TXM_RUNTIME_TEXT'])
        self.assertEqual(fast_proxy.state['expected_first_pc'], txm_target)
        self.assertEqual(state['stage'], 'seek-genter-return')

        sptm_segment.update(fileoff=0, filesize=4)
        feed(ns['FC_XNU_PHASE53_GENTER_RETURN'],
             {30: ns['FC_XNU_PHASE53_GENTER_PREVIOUS']},
             ns['FC_XNU_PHASE53_GEXIT'],
             status=ns['FC_VEL2_STEP_FILTER_OUTSIDE'],
             spsr=ns['FC_XNU_PHASE53_GENTER_RETURN_SPSR'])
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(state['stage'], 'seek-wrapper-retab')
        self.assertEqual(state['range0'], ns['FC_XNU_RUNTIME_TEXT'])
        self.assertEqual(fast_proxy.state['expected_first_pc'],
                         ns['FC_XNU_PHASE53_GENTER_RETURN'])
        self.assertEqual(len(self.endpoint.report[
            'xnu_phase53_retype_survey']['world_transitions']), 1)

    def test_phase53_retype_survey_stops_at_call_limit(self):
        self._run_phase53_retype_survey_call(target_type=0x29, limit=1)
        self.assertEqual(self.endpoint.replies[-1],
                         int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-call-limit-reached')
        self.assertTrue(self.endpoint.report['xnu_phase53_retype_survey'][
            'limit_reached'])

    def test_phase53_retype_survey_rejects_locked_or_mismatched_fte(self):
        self._run_phase53_retype_survey_call(lock_before=True)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-seek-entry-gate-rejected')
        self.assertFalse(self.endpoint.report['xnu_phase53_retype_survey'][
            'rejection']['checks']['fte_center_unlocked'])

        self.setUp()
        self._run_phase53_retype_survey_call(
            target_type=0x29, limit=2, after_type=0x28)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'phase53-retype-survey-seek-wrapper-retab-gate-rejected')
        self.assertFalse(self.endpoint.report['xnu_phase53_retype_survey'][
            'rejection']['checks']['fte_center_type'])
