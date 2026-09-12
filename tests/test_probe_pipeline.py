from pathlib import Path
import json
import sys
import tarfile
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from run_probe_pipeline import probe_command,package,lint_config,summarize_report
from run_manifest import file_identity


class PipelineTests(unittest.TestCase):
    def test_summary_distinguishes_final_stop_from_handoff_observer(self):
        private = {'enabled': True, 'mapped': True, 'raw_source_artifact_saved': False}
        cntp_cleanup = {'register': 'CNTP_CTL_EL02', 'attempted': True,
                        'verified': True, 'host_timer_bank_touched': False}
        apple_timer = {'enabled': True, 'routing_established': False}
        report = {
            'stop_reason': 'hang', 'trace_total_events': 9052,
            'xnu_sptm_callbacks': 7266,
            'xnu_private_panic_carveout': private,
            'xnu_cntp_ctl_cleanup': cntp_cleanup,
            'xnu_apple_physical_timer_hypothesis': apple_timer,
            'handoff': {'image': 'kernelcache', 'last_pc': '0xfffffe002bfb453c',
                        'observed_events': 64},
            'trace': [
                {'kind': 'staged-apple-register', 'pc': 0x1000},
                {'kind': 'real-guarded-redirect', 'pc': 0x2000},
                {'kind': 'hang-budget', 'pc': 0x3000, 'reason': 2, 'code': 0},
            ],
        }
        summary = summarize_report(report)
        self.assertEqual(summary['stop_event'],
            {'kind': 'hang-budget', 'pc': 0x3000, 'reason': 2, 'code': 0})
        self.assertEqual(summary['activity'], {
            'trace_total_events': 9052, 'xnu_sptm_callbacks': 7266,
            'retained_events': 3, 'retained_distinct_pcs': 3})
        self.assertEqual(summary['handoff']['last_pc'], '0xfffffe002bfb453c')
        self.assertEqual(summary['handoff']['last_observed_pc'],
                         summary['handoff']['last_pc'])
        self.assertIn('handoff observer', summary['handoff']['last_pc_scope'])
        self.assertIn('not every callback or watchdog stop',
                      summary['handoff']['last_pc_scope'])
        self.assertNotIn('prefix_last_pc', summary['handoff'])
        self.assertIs(summary['xnu_private_panic_carveout'], private)
        self.assertIs(summary['xnu_cntp_ctl_cleanup'], cntp_cleanup)
        self.assertIs(summary['xnu_apple_physical_timer_hypothesis'], apple_timer)

    def test_tpidr_gl2_fast_shadow_is_explicit_and_requires_xnu_run(self):
        base = dict(payload='/payload', checkout='/checkout', device='/dev/test',
                    steps=16, free_run=True, real_guarded=True, hang_budget=120,
                    native_handoff=True, xnu_steps=64, xnu_run=True)
        command = probe_command(dict(base, xnu_tpidr_gl2_fast_shadow=True),
                                Path('/output'), True)
        self.assertIn('--xnu-tpidr-gl2-fast-shadow', command)
        self.assertNotIn('--xnu-tpidr-gl2-fast-shadow',
                         probe_command(dict(base, xnu_tpidr_gl2_fast_shadow=False),
                                       Path('/output'), True))
        with self.assertRaisesRegex(ValueError, 'requires xnu_run'):
            probe_command(dict(base, xnu_run=False,
                               xnu_tpidr_gl2_fast_shadow=True),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'Expected Boolean'):
            probe_command(dict(base, xnu_tpidr_gl2_fast_shadow=1),
                          Path('/output'), True)

    def test_txm_context_entry_one_step_is_explicit_and_requires_xnu_run(self):
        base = dict(payload='/payload', checkout='/checkout', device='/dev/test',
                    steps=16, free_run=True, real_guarded=True, hang_budget=120,
                    native_handoff=True, xnu_steps=64, xnu_run=True)
        command = probe_command(dict(base, xnu_txm_context_entry_one_step=True),
                                Path('/output'), True)
        self.assertIn('--xnu-txm-context-entry-one-step', command)
        self.assertNotIn('--xnu-txm-context-entry-one-step',
                         probe_command(dict(base, xnu_txm_context_entry_one_step=False),
                                       Path('/output'), True))
        with self.assertRaisesRegex(ValueError, 'requires xnu_run'):
            probe_command(dict(base, xnu_run=False,
                               xnu_txm_context_entry_one_step=True),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'Expected Boolean'):
            probe_command(dict(base, xnu_txm_context_entry_one_step=1),
                          Path('/output'), True)
        prefix = probe_command(dict(base, xnu_txm_context_entry_register_prefix=True),
                               Path('/output'), True)
        self.assertIn('--xnu-txm-context-entry-register-prefix', prefix)
        with self.assertRaisesRegex(ValueError, 'requires xnu_run'):
            probe_command(dict(base, xnu_run=False,
                               xnu_txm_context_entry_register_prefix=True),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
            probe_command(dict(base, xnu_txm_context_entry_one_step=True,
                               xnu_txm_context_entry_register_prefix=True),
                          Path('/output'), True)
        claim = probe_command(dict(base, xnu_txm_context_stack_claim_one_step=True),
                              Path('/output'), True)
        self.assertIn('--xnu-txm-context-stack-claim-one-step', claim)
        with self.assertRaisesRegex(ValueError, 'requires xnu_run'):
            probe_command(dict(base, xnu_run=False,
                               xnu_txm_context_stack_claim_one_step=True),
                          Path('/output'), True)
        metadata = probe_command(dict(base, xnu_txm_context_stack_metadata_init=True),
                                 Path('/output'), True)
        self.assertIn('--xnu-txm-context-stack-metadata-init', metadata)
        with self.assertRaisesRegex(ValueError, 'requires xnu_run'):
            probe_command(dict(base, xnu_run=False,
                               xnu_txm_context_stack_metadata_init=True),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'Expected Boolean'):
            probe_command(dict(base, xnu_txm_context_stack_metadata_init=1),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
            probe_command(dict(base, xnu_txm_context_stack_claim_one_step=True,
                               xnu_txm_context_stack_metadata_init=True),
                          Path('/output'), True)
        branch = probe_command(dict(base, xnu_txm_context_x18_branch_one_step=True),
                               Path('/output'), True)
        self.assertIn('--xnu-txm-context-x18-branch-one-step', branch)
        with self.assertRaisesRegex(ValueError, 'requires xnu_run'):
            probe_command(dict(base, xnu_run=False,
                               xnu_txm_context_x18_branch_one_step=True),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'Expected Boolean'):
            probe_command(dict(base, xnu_txm_context_x18_branch_one_step=1),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
            probe_command(dict(base, xnu_txm_context_stack_metadata_init=True,
                               xnu_txm_context_x18_branch_one_step=True),
                          Path('/output'), True)
        outbound = probe_command(dict(
            base, xnu_txm_context_outbound_branch_one_step=True),
            Path('/output'), True)
        self.assertIn('--xnu-txm-context-outbound-branch-one-step', outbound)
        with self.assertRaisesRegex(ValueError, 'requires xnu_run'):
            probe_command(dict(base, xnu_run=False,
                               xnu_txm_context_outbound_branch_one_step=True),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
            probe_command(dict(base, xnu_txm_context_x18_branch_one_step=True,
                               xnu_txm_context_outbound_branch_one_step=True),
                          Path('/output'), True)
        handler = probe_command(dict(base, xnu_txm_handler_boundary='prologue'),
                                Path('/output'), True)
        self.assertIn('--xnu-txm-handler-boundary=prologue', handler)
        with self.assertRaisesRegex(ValueError, 'requires xnu_run'):
            probe_command(dict(base, xnu_run=False,
                               xnu_txm_handler_boundary='prologue'),
                          Path('/output'), True)
        saves = probe_command(dict(base, xnu_txm_handler_boundary='register-saves'),
                              Path('/output'), True)
        self.assertIn('--xnu-txm-handler-boundary=register-saves', saves)
        local = probe_command(dict(base, xnu_txm_handler_boundary='local-setup'),
                              Path('/output'), True)
        self.assertIn('--xnu-txm-handler-boundary=local-setup', local)
        validator = probe_command(dict(base, xnu_txm_handler_boundary='validator-entry'),
                                  Path('/output'), True)
        self.assertIn('--xnu-txm-handler-boundary=validator-entry', validator)
        validator_trace = probe_command(dict(
            base, xnu_txm_handler_boundary='validator-trace'), Path('/output'), True)
        self.assertIn('--xnu-txm-handler-boundary=validator-trace', validator_trace)
        response_trace = probe_command(dict(
            base, xnu_txm_handler_boundary='response-trace'), Path('/output'), True)
        self.assertIn('--xnu-txm-handler-boundary=response-trace', response_trace)
        completion_trace = probe_command(dict(
            base, xnu_txm_handler_boundary='cmd1-completion-trace'),
            Path('/output'), True)
        self.assertIn('--xnu-txm-handler-boundary=cmd1-completion-trace',
                      completion_trace)
        allocation_trace = probe_command(dict(
            base, xnu_txm_handler_boundary='cmd1-completion-trace',
            xnu_txm_sstep_fast_path=True,
            xnu_phase53_allocation_trace=True), Path('/output'), True)
        self.assertIn('--xnu-phase53-allocation-trace', allocation_trace)
        survey = probe_command(dict(
            base, xnu_txm_handler_boundary='cmd1-completion-trace',
            xnu_txm_sstep_fast_path=True,
            xnu_phase53_allocation_trace=True,
            xnu_phase53_retype_survey=True,
            xnu_phase53_retype_survey_limit=7,
            xnu_phase53_descriptor_bind=True,
            xnu_phase53_leaf_page_bind=True), Path('/output'), True)
        self.assertIn('--xnu-phase53-retype-survey', survey)
        self.assertIn('--xnu-phase53-retype-survey-limit=7', survey)
        self.assertIn('--xnu-phase53-descriptor-bind', survey)
        self.assertIn('--xnu-phase53-leaf-page-bind', survey)
        with self.assertRaisesRegex(ValueError, 'requires xnu_phase53_allocation_trace'):
            probe_command(dict(base, xnu_phase53_retype_survey=True),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'must be integer 1..64'):
            probe_command(dict(
                base, xnu_txm_handler_boundary='cmd1-completion-trace',
                xnu_txm_sstep_fast_path=True,
                xnu_phase53_allocation_trace=True,
                xnu_phase53_retype_survey=True,
                xnu_phase53_retype_survey_limit=65), Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'requires xnu_phase53_retype_survey'):
            probe_command(dict(
                base, xnu_txm_handler_boundary='cmd1-completion-trace',
                xnu_txm_sstep_fast_path=True,
                xnu_phase53_allocation_trace=True,
                xnu_phase53_retype_survey_limit=64), Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'requires xnu_phase53_retype_survey'):
            probe_command(dict(
                base, xnu_txm_handler_boundary='cmd1-completion-trace',
                xnu_txm_sstep_fast_path=True,
                xnu_phase53_allocation_trace=True,
                xnu_phase53_descriptor_bind=True), Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'requires xnu_phase53_descriptor_bind'):
            probe_command(dict(
                base, xnu_txm_handler_boundary='cmd1-completion-trace',
                xnu_txm_sstep_fast_path=True,
                xnu_phase53_allocation_trace=True,
                xnu_phase53_retype_survey=True,
                xnu_phase53_leaf_page_bind=True), Path('/output'), True)
        with self.assertRaisesRegex(
                ValueError, 'requires cmd1-completion-trace and xnu_txm_sstep_fast_path'):
            probe_command(dict(base, xnu_phase53_allocation_trace=True),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'must be prologue, register-saves, local-setup, validator-entry, validator-trace, response-trace, or cmd1-completion-trace'):
            probe_command(dict(base, xnu_txm_handler_boundary='unknown'),
                          Path('/output'), True)
        with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
            probe_command(dict(base, xnu_txm_context_outbound_branch_one_step=True,
                               xnu_txm_handler_boundary='prologue'),
                          Path('/output'), True)

    def test_summary_retains_txm_context_gate_and_eret_classification(self):
        gate = {'enabled': True, 'checks': {'target_pc': True}}
        metadata = {'enabled': True, 'checks': {'post_claim_source': True}}
        branch = {'enabled': True, 'checks': {'x18_branch_source': True}}
        outbound = {'enabled': True, 'checks': {'outbound_target_source': True}}
        handler = {'enabled': True, 'boundary': 'prologue'}
        classifications = [{'status': 'classified', 'decision': 'txm-context-one-step'}]
        summary = summarize_report({'trace': [],
            'xnu_txm_context_entry_one_step': gate,
            'xnu_txm_context_stack_metadata_init': metadata,
            'xnu_txm_context_x18_branch_one_step': branch,
            'xnu_txm_context_outbound_branch_one_step': outbound,
            'xnu_txm_handler_boundary': handler,
            'eret_classifications': classifications})
        self.assertIs(summary['xnu_txm_context_entry_one_step'], gate)
        self.assertIs(summary['xnu_txm_context_stack_metadata_init'], metadata)
        self.assertIs(summary['xnu_txm_context_x18_branch_one_step'], branch)
        self.assertIs(summary['xnu_txm_context_outbound_branch_one_step'], outbound)
        self.assertIs(summary['xnu_txm_handler_boundary'], handler)
        self.assertIs(summary['eret_classifications'], classifications)

    def test_summary_handles_empty_trace(self):
        summary = summarize_report({'trace': [], 'trace_total_events': 0})
        self.assertNotIn('stop_event', summary)
        self.assertEqual(summary['activity']['retained_distinct_pcs'], 0)

    def test_long_budget_contract_and_explicit_execution(self):
        config=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=33554432)
        with self.assertRaises(ValueError):probe_command(config,Path('/output'),True)
        config.update(step_batch=256,trace_window=8192)
        with self.assertRaises(ValueError):probe_command(dict(config,steps=33554433),Path('/output'),True)
        self.assertNotIn('--execute',probe_command(config,Path('/output'),False))
        self.assertIn('--execute',probe_command(config,Path('/output'),True))
        with self.assertRaises(ValueError):probe_command(dict(config,execute=True),Path('/output'),True)
        with self.assertRaises(ValueError):probe_command(dict(config,steps=True),Path('/output'),True)

    def test_guard_and_vector_fields_are_explicit_and_bounded(self):
        config=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=16,
                    stop_on_vector_entry=True,pause_on_guard=True,pause_timeout=600,observe_sprr=True,virtual_gxf=True,stage_el2_config=True)
        command=probe_command(config,Path('/output'),True)
        for option in ('--stop-on-vector-entry','--pause-on-guard','--pause-timeout=600','--observe-sprr','--virtual-gxf','--stage-el2-config'):
            self.assertIn(option,command)
        self.assertNotIn('--pause-on-guard',probe_command(dict(config,pause_on_guard=False),Path('/output'),True))
        for bad in (dict(pause_timeout=0),dict(pause_timeout=86401),dict(pause_timeout=1.5),
                    dict(stop_on_vector_entry=1),dict(pause_on_guard='yes'),dict(resume_pause='x')):
            with self.subTest(bad=bad),self.assertRaises(ValueError):probe_command(dict(config,**bad),Path('/output'),True)

    def test_back_page_diagnostic_field_is_emitted_and_validated(self):
        base=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=16)
        command=probe_command(dict(base,back_page='0x211050000'),Path('/output'),True)
        self.assertIn('--back-page=0x211050000',command)
        self.assertNotIn('back-page','\n'.join(probe_command(base,Path('/output'),True)))
        self.assertIn('--back-page=0x211050000:16',probe_command(dict(base,back_page='0x211050000:16'),Path('/output'),True))
        listed=[c for c in probe_command(dict(base,back_page=['0x211050000:3','0x211e40000:3']),Path('/output'),True) if c.startswith('--back-page=')]
        self.assertEqual(listed,['--back-page=0x211050000:3','--back-page=0x211e40000:3'])
        for bad in (dict(back_page=0x211050000),dict(back_page=''),dict(back_page='0x211050001'),dict(back_page='notahex'),
                    dict(back_page='0x211050000:0'),dict(back_page='0x211050000:5000'),dict(back_page='0x211050000:x'),
                    dict(back_page=[]),dict(back_page=['0x211050000','0x211050001'])):
            with self.subTest(bad=bad),self.assertRaises(ValueError):probe_command(dict(base,**bad),Path('/output'),True)

    def test_leaf_snapshot_and_single_step_fields(self):
        base=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=16)
        command=probe_command(dict(base,snapshot_leaf='0xfffffe00070ac000',single_step_after=7807000),Path('/output'),True)
        self.assertIn('--snapshot-leaf=0xfffffe00070ac000',command)
        self.assertIn('--single-step-after=7807000',command)
        listed=[c for c in probe_command(dict(base,snapshot_leaf=['0xfffffe0034000000','0xfffffe0036000000']),Path('/output'),True) if c.startswith('--snapshot-leaf=')]
        self.assertEqual(listed,['--snapshot-leaf=0xfffffe0034000000','--snapshot-leaf=0xfffffe0036000000'])
        for bad in (dict(snapshot_leaf=0xac000),dict(snapshot_leaf=''),dict(snapshot_leaf='nothex'),dict(snapshot_leaf=[]),dict(snapshot_leaf=['0xfffffe0034000000','nothex']),
                    dict(single_step_after='7807000'),dict(single_step_after=-1),dict(single_step_after=33554433)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):probe_command(dict(base,**bad),Path('/output'),True)

    def test_free_run_flag_and_exclusions(self):
        base=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=16)
        self.assertIn('--free-run',probe_command(dict(base,hang_budget=120,free_run=True),Path('/output'),True))
        self.assertNotIn('--free-run',probe_command(dict(base,free_run=False),Path('/output'),True))
        for bad in (dict(free_run=True,single_step_window='100:10'),
                    dict(free_run=True,single_step_after=100),
                    dict(free_run=True,real_guarded=True,guarded_call_selectors='0x1b'),
                    dict(free_run=True,real_guarded=True,first_contact=True)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):probe_command(dict(base,**bad),Path('/output'),True)
        # free_run + on_demand_stage2 is the intended pairing
        cmd=probe_command(dict(base,hang_budget=120,free_run=True,on_demand_stage2=16384),Path('/output'),True)
        self.assertIn('--free-run',cmd); self.assertIn('--on-demand-stage2=16384',cmd)

    def test_free_run_requires_bounded_watchdog(self):
        base=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=16)
        self.assertTrue(any('hang_budget' in warning for warning in lint_config(dict(base,free_run=True))))
        for bad in ({'free_run':True}, {'free_run':True,'hang_budget':0},
                    {'free_run':True,'hang_budget':86401}, {'free_run':True,'hang_budget':True},
                    {'free_run':True,'hang_budget':1.5}, {'hang_budget':120}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe_command(dict(base,**bad),Path('/output'),True)
        self.assertIn('--hang-budget=120',probe_command(dict(base,free_run=True,hang_budget=120),Path('/output'),True))

    def test_handoff_steps_require_guarded_free_run_and_bounded_count(self):
        base=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=16,
                  free_run=True,real_guarded=True,hang_budget=120)
        self.assertIn('--handoff-steps=4096',probe_command(dict(base,handoff_steps=4096),Path('/output'),True))
        for bad in ({'handoff_steps':True}, {'handoff_steps':-1}, {'handoff_steps':4097},
                    {'handoff_steps':1.5}, {'handoff_steps':1,'real_guarded':False}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe_command(dict(base,**bad),Path('/output'),True)
        for bad in ({'handoff_steps':32,'handoff_breakpoint_offset':0x4c},
                    {'handoff_breakpoint_offset':0x4c}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe_command(dict(base,**bad),Path('/output'),True)
        native = dict(base, handoff_steps=0, native_handoff=True)
        self.assertIn('--native-handoff', probe_command(native,Path('/output'),True))
        for bad in ({'native_handoff':True,'free_run':False},
                    {'native_handoff':True,'real_guarded':False},
                    {'native_handoff':True,'handoff_steps':1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe_command(dict(base,**bad),Path('/output'),True)

    def test_xnu_steps_require_native_handoff_and_bounded_integer(self):
        base = dict(payload='/payload', checkout='/checkout', device='/dev/test', steps=16,
                    free_run=True, real_guarded=True, hang_budget=120, native_handoff=True)
        for count in (0, 1, 4096):
            self.assertIn('--xnu-steps=%d' % count,
                          probe_command(dict(base, xnu_steps=count), Path('/output'), True))
        for bad in (True, -1, 4097, 1.5, '2'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe_command(dict(base, xnu_steps=bad), Path('/output'), True)
        with self.assertRaises(ValueError):
            probe_command(dict(base, native_handoff=False, xnu_steps=1), Path('/output'), True)
        probe_command(dict(base, native_handoff=False, xnu_steps=0), Path('/output'), True)
        self.assertIn('--xnu-run', probe_command(dict(base, xnu_steps=64, xnu_run=True), Path('/output'), True))
        self.assertIn('--xnu-m3-nop-ahcr-compat', probe_command(dict(
            base, xnu_steps=64, xnu_run=True, xnu_m3_nop_ahcr_compat=True), Path('/output'), True))
        with self.assertRaises(ValueError):
            probe_command(dict(base, xnu_run=True), Path('/output'), True)
        with self.assertRaises(ValueError):
            probe_command(dict(base, xnu_m3_nop_ahcr_compat=True), Path('/output'), True)
        cmd = probe_command(dict(base, xnu_steps=64, xnu_run=True,
            on_demand_stage2=16384, xnu_dockchannel_uart_mmio=True), Path('/output'), True)
        self.assertIn('--xnu-dockchannel-uart-mmio', cmd)
        with self.assertRaises(ValueError):
            probe_command(dict(base, xnu_steps=64, xnu_run=True,
                xnu_dockchannel_uart_mmio=True), Path('/output'), True)
        cmd = probe_command(dict(base, xnu_steps=64, xnu_run=True,
            on_demand_stage2=16384, xnu_private_panic_carveout=True),
            Path('/output'), True)
        self.assertIn('--xnu-private-panic-carveout', cmd)
        with self.assertRaises(ValueError):
            probe_command(dict(base, xnu_steps=64, xnu_run=True,
                xnu_private_panic_carveout=True), Path('/output'), True)
        cmd = probe_command(dict(base, xnu_steps=64, xnu_run=True,
            on_demand_stage2=16384, xnu_private_socd_trace=True),
            Path('/output'), True)
        self.assertIn('--xnu-private-socd-trace', cmd)
        with self.assertRaises(ValueError):
            probe_command(dict(base, xnu_steps=64, xnu_run=True,
                xnu_private_socd_trace=True), Path('/output'), True)
        cmd = probe_command(dict(base, xnu_steps=64, xnu_run=True,
            xnu_apple_physical_timer_hypothesis=True), Path('/output'), True)
        self.assertIn('--xnu-apple-physical-timer-hypothesis', cmd)
        with self.assertRaises(ValueError):
            probe_command(dict(base, xnu_apple_physical_timer_hypothesis=True),
                          Path('/output'), True)
        cmd = probe_command(dict(base, xnu_steps=64, xnu_run=True,
            xnu_pperm_guest_window=True, xnu_pperm_guest_window_limit=256), Path('/output'), True)
        self.assertIn('--xnu-pperm-guest-window', cmd)
        self.assertIn('--xnu-pperm-guest-window-limit=256', cmd)
        with self.assertRaises(ValueError):
            probe_command(dict(base, xnu_pperm_guest_window=True), Path('/output'), True)
        for limit in (0, 4097, True):
            with self.assertRaises(ValueError):
                probe_command(dict(base, xnu_pperm_guest_window_limit=limit), Path('/output'), True)

    def test_on_demand_stage2_field(self):
        base=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=16)
        self.assertIn('--on-demand-stage2=8192',probe_command(dict(base,on_demand_stage2=8192),Path('/output'),True))
        self.assertNotIn('on-demand-stage2','\n'.join(probe_command(base,Path('/output'),True)))
        for bad in (dict(on_demand_stage2='8192'),dict(on_demand_stage2=-1),dict(on_demand_stage2=1048577),dict(on_demand_stage2=1.5)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):probe_command(dict(base,**bad),Path('/output'),True)

    def test_real_guarded_flag_and_mutual_exclusion(self):
        base=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=16)
        self.assertIn('--real-guarded',probe_command(dict(base,real_guarded=True),Path('/output'),True))
        self.assertNotIn('--real-guarded',probe_command(dict(base,real_guarded=False),Path('/output'),True))
        self.assertNotIn('real-guarded','\n'.join(probe_command(base,Path('/output'),True)))
        command=probe_command(dict(base,real_guarded=True,real_guarded_vbar=True),Path('/output'),True)
        self.assertIn('--real-guarded-vbar',command)
        self.assertNotIn('--real-guarded-vbar',probe_command(dict(base,real_guarded=True,
                                                                  real_guarded_vbar=False),Path('/output'),True))
        for bad in (dict(real_guarded_vbar=True),
                    dict(real_guarded=False,real_guarded_vbar=True),
                    dict(real_guarded=True,real_guarded_vbar=1),
                    dict(real_guarded=True,real_guarded_vbar='yes')):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                probe_command(dict(base,**bad),Path('/output'),True)
        with self.assertRaises(ValueError):
            probe_command(dict(base,real_guarded=True,virtual_gxf=True),Path('/output'),True)

    def test_single_step_window_and_guarded_vector_stop_fields(self):
        base=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=16)
        cmd=probe_command(dict(base,single_step_window='7785000:4000'),Path('/output'),True)
        self.assertIn('--single-step-window=7785000:4000',cmd)
        cmd=probe_command(dict(base,real_guarded=True,stop_on_guarded_vector=True),Path('/output'),True)
        self.assertIn('--stop-on-guarded-vector',cmd)
        self.assertNotIn('--stop-on-guarded-vector',probe_command(dict(base,real_guarded=True,stop_on_guarded_vector=False),Path('/output'),True))
        # stop_on_guarded_vector requires real_guarded
        with self.assertRaises(ValueError):
            probe_command(dict(base,stop_on_guarded_vector=True),Path('/output'),True)
        for bad in (dict(single_step_window=''),dict(single_step_window='notanum'),
                    dict(single_step_window='10:20:30'),dict(single_step_window='5:0'),
                    dict(single_step_window='-1:4'),dict(single_step_window=7785000),
                    dict(single_step_window='5:2000000')):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                probe_command(dict(base,**bad),Path('/output'),True)

    def test_first_contact_and_guarded_call_selectors_fields(self):
        base=dict(payload='/payload',checkout='/checkout',device='/dev/test',steps=16)
        self.assertIn('--first-contact',probe_command(dict(base,real_guarded=True,first_contact=True),Path('/output'),True))
        with self.assertRaises(ValueError):  # first_contact requires real_guarded
            probe_command(dict(base,first_contact=True),Path('/output'),True)
        cmd=probe_command(dict(base,real_guarded=True,guarded_call_selectors='0x0,0x1'),Path('/output'),True)
        self.assertIn('--guarded-call-selectors=0x0,0x1',cmd)
        with self.assertRaises(ValueError):  # requires real_guarded
            probe_command(dict(base,guarded_call_selectors='0x0'),Path('/output'),True)
        for bad in (dict(guarded_call_selectors=''),dict(guarded_call_selectors='   '),
                    dict(guarded_call_selectors='nothex'),dict(guarded_call_selectors=0)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                probe_command(dict(base,real_guarded=True,**bad),Path('/output'),True)
        # lint: multi-call without single-step coverage warns
        from run_probe_pipeline import lint_config
        w=lint_config(dict(base,real_guarded=True,stage_el2_config=True,stop_on_guarded_vector=True,guarded_call_selectors='0x0'))
        self.assertTrue(any('guarded_call_selectors' in x for x in w))

    def test_lint_flags_costly_but_valid_configs(self):
        base=dict(payload='/payload',checkout='/checkout',device='/dev/test')
        # A real-guarded run that both enables the EL2 context and halts at the
        # guarded divert is clean (the corrected next-run shape).
        clean=dict(base,steps=16777216,step_batch=256,trace_window=8192,
                   single_step_after=0,real_guarded=True,stage_el2_config=True,
                   stop_on_guarded_vector=True)
        self.assertEqual(lint_config(clean),[])
        # The attempt-17 crawl shape: single-steps a huge tail -> one warning.
        crawl=dict(clean,single_step_after=7786000)
        warnings=lint_config(crawl)
        self.assertEqual(len(warnings),1)
        self.assertIn('single_step_after',warnings[0])
        self.assertIn('batched',warnings[0])
        # A small single-step window near the end is not flagged (below threshold).
        self.assertEqual(lint_config(dict(clean,steps=16,single_step_after=8)),[])
        # single_step_after >= steps single-steps nothing -> no warning.
        self.assertEqual(lint_config(dict(clean,single_step_after=16777216)),[])
        # real_guarded without the EL2 context enable -> the EC-0-fault warning.
        missing=lint_config(dict(base,steps=16,real_guarded=True,stop_on_guarded_vector=True))
        self.assertTrue(any('stage_el2_config' in w for w in missing))
        # real_guarded without a guarded-vector stop -> the spin-to-budget warning (attempt-18).
        spin=lint_config(dict(base,steps=16,real_guarded=True,stage_el2_config=True))
        self.assertTrue(any('VBAR_GL1' in w and 'spins to the step budget' in w for w in spin))
        # A single_step_window satisfies that rule too (bounded, self-halting).
        self.assertEqual(lint_config(dict(clean,stop_on_guarded_vector=False,single_step_window='7785000:4000')),[])
        # Both footguns at once (crawl + missing EL2 context) -> both warnings, plus the spin rule.
        both=lint_config(dict(base,steps=16777216,single_step_after=1,real_guarded=True))
        self.assertEqual(len(both),3)

    def test_closed_archive_retains_failure_evidence_and_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'attempt';output.mkdir()
            (output/'pipeline.json').write_text('{"phase":"failed"}')
            (output/'partial-trace').write_bytes(b'captured event\n'*100)
            identity=package(output);archive=Path(identity['path'])
            self.assertEqual(file_identity(archive),identity)
            with tarfile.open(archive) as f:
                self.assertEqual(f.extractfile('attempt/partial-trace').read(),b'captured event\n'*100)
                self.assertEqual(json.load(f.extractfile('attempt/pipeline.json'))['phase'],'failed')
            self.assertFalse(archive.with_name(archive.name+'.partial').exists())
            with self.assertRaises(ValueError):package(output)
