"""Txm trace regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from probe_control_support import ProbeControlFixture
import os
import struct
import unittest


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class ProbeTxmTraceTests(ProbeControlFixture, unittest.TestCase):

    def test_txm_handler_register_saves_verify_exact_owned_page_writes(self):
        states, probe = self._complete_txm_handler_boundary('register-saves')
        self.assertEqual(len(states), 31)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-register-saves-complete')
        self.assertTrue(probe['complete'])
        self.assertEqual(probe['result']['extension_instructions'], 8)
        self.assertEqual(probe['result']['saved_register_pairs'], 5)
        self.assertTrue(probe['result']['first_stp_executed'])
        self.assertTrue(probe['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_handler_local_setup_roundtrips_helper_and_stores_marker(self):
        states, probe = self._complete_txm_handler_boundary('local-setup')
        self.assertEqual(len(states), 46)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-local-setup-complete')
        self.assertTrue(probe['complete'])
        self.assertEqual(probe['result']['extension_instructions'], 23)
        self.assertTrue(probe['result']['helper_roundtrip_executed'])
        self.assertTrue(probe['result']['local_marker_stored'])
        self.assertTrue(probe['result']['checks']['memory_local_marker'])
        self.assertTrue(probe['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_handler_validator_entry_gates_global_and_builds_tuple(self):
        states, probe = self._complete_txm_handler_boundary('validator-entry')
        self.assertEqual(len(states), 62)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-validator-entry-complete')
        self.assertTrue(probe['complete'])
        self.assertTrue(probe['checks']['handler_global_initial_zero'])
        self.assertEqual(probe['result']['extension_instructions'], 39)
        self.assertTrue(probe['result']['global_guard_zero'])
        self.assertTrue(probe['result']['validator_tuple_stored'])
        self.assertTrue(probe['result']['checks']['memory_validator_base'])
        self.assertTrue(probe['result']['checks']['memory_validator_sizes'])
        self.assertTrue(probe['result']['checks']['metadata_no_unexpected_page_writes'])

    def test_txm_handler_validator_trace_returns_expected_result(self):
        states, probe = self._complete_txm_handler_boundary('validator-trace')
        self.assertEqual(len(states), 63)
        ns = self.endpoint.namespace
        self.assertTrue(ns['txm_validator_trace_state']['active'])
        returned = self.tables.event(0xcb000022)
        returned['pc'] = ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET'] + 0xa4
        returned['spsr'] = 0x800013c0
        returned['sp'][0] = ns['FC_XNU_TXM_CONTEXT_STACK'] + ns['PAGE'] - 0x470
        returned['regs'][0] = 0x2d
        self.endpoint.feed(returned)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-validator-trace-complete')
        self.assertTrue(probe['complete'])
        self.assertTrue(probe['result']['validator_returned'])
        self.assertTrue(probe['result']['checks']['caller_frame_preserved'])
        self.assertEqual(probe['result']['validator_trace_steps'], 1)

    def test_txm_handler_response_trace_builds_descriptor_before_completion(self):
        _, probe = self._complete_txm_handler_boundary('response-trace')
        ns = self.endpoint.namespace
        state = ns['txm_validator_trace_state']
        returned = self.tables.event(0xcb000022)
        returned['pc'] = ns['FC_XNU_TXM_CONTEXT_OUTBOUND_TARGET'] + 0xa4
        returned['spsr'] = 0x600013c0
        returned['sp'][0] = state['expected_sp']
        returned['regs'][0] = 0x2d
        self.endpoint.feed(returned)
        self.assertEqual(state['phase'], 'response')
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
        stopped = self.tables.event(0xcb000022)
        stopped['pc'] = ns['FC_XNU_TXM_HANDLER_RESPONSE_STOP']
        stopped['spsr'] = 0x600013c0
        stopped['sp'][0] = state['expected_sp']
        self.endpoint.feed(stopped)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-response-trace-complete')
        self.assertTrue(probe['complete'])
        self.assertTrue(probe['result']['response_completed'])
        self.assertTrue(probe['result']['checks']['response_type_three'])
        self.assertTrue(probe['result']['checks']['completion_slot_zero'])

    def test_txm_handler_cmd1_completion_releases_claim_and_returns_to_xnu(self):
        _, probe = self._complete_txm_handler_boundary('cmd1-completion-trace')
        ns = self.endpoint.namespace
        state = ns['txm_validator_trace_state']
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
        self.assertEqual(state['phase'], 'completion')
        self.tables.memory.write(frame_pa + 0x58, b'\x00')
        completion = self.tables.event(0xcb000022)
        completion['pc'] = ns['FC_XNU_TXM_HANDLER_CMD1_XNU_RETURN']
        completion['sp'][0] = state['expected_sp']
        self.endpoint.feed(completion)
        self.assertEqual(self.endpoint.report['stop_reason'],
                         'txm-handler-cmd1-completion-trace-complete')
        self.assertTrue(probe['complete'])
        self.assertTrue(probe['result']['cmd1_xnu_return'])
        self.assertTrue(probe['result']['checks']['claim_released'])
