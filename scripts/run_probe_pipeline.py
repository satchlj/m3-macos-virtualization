#!/usr/bin/env python3
"""Run one probe, collect diagnostics, and publish a fast compressed transfer bundle."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from fresh_gate_receipt import DEFAULT_KEY as FRESH_GATE_KEY, acquire_device_lock, consume_receipt
from run_manifest import atomic_json, file_identity, utc

REPO = Path(__file__).resolve().parents[1]
FIELDS = {'payload','checkout','device','steps','step_batch','trace_window','pause_timeout',
          'allow_monitor_mmu','emulate_zero_loops','relocate_boot_data','allow_live_ttbr',
          'stop_on_vector_entry','pause_on_guard','observe_sprr','virtual_gxf','stage_el2_config',
          'back_page','snapshot_leaf','single_step_after','real_guarded',
          'single_step_window','stop_on_guarded_vector','first_contact','guarded_call_selectors',
          'on_demand_stage2','free_run','hang_budget','handoff_steps','handoff_breakpoint_offset',
          'real_guarded_vbar','native_handoff','xnu_steps','xnu_run','xnu_m3_nop_ahcr_compat',
          'xnu_dockchannel_uart_mmio','xnu_private_panic_carveout',
          'xnu_private_socd_trace',
          'xnu_pperm_guest_window',
          'xnu_pperm_guest_window_limit',
          'xnu_apple_physical_timer_hypothesis',
          'xnu_tpidr_gl2_fast_shadow','xnu_txm_context_entry_one_step',
          'xnu_txm_context_entry_register_prefix','xnu_txm_context_stack_claim_one_step',
          'xnu_txm_context_stack_metadata_init','xnu_txm_context_x18_branch_one_step',
          'xnu_txm_context_outbound_branch_one_step','xnu_txm_handler_boundary',
          'xnu_txm_sstep_fast_path','xnu_phase53_allocation_trace',
          'xnu_phase53_retype_survey','xnu_phase53_retype_survey_limit'}
FLAGS = {'allow_monitor_mmu','emulate_zero_loops','relocate_boot_data','allow_live_ttbr',
         'stop_on_vector_entry','pause_on_guard','observe_sprr','virtual_gxf','stage_el2_config',
         'real_guarded','real_guarded_vbar','stop_on_guarded_vector','first_contact','free_run',
         'native_handoff','xnu_run','xnu_m3_nop_ahcr_compat','xnu_dockchannel_uart_mmio',
         'xnu_private_panic_carveout','xnu_apple_physical_timer_hypothesis'}
FLAGS.add('xnu_private_socd_trace')
FLAGS.add('xnu_pperm_guest_window')
FLAGS.add('xnu_tpidr_gl2_fast_shadow')
FLAGS.add('xnu_txm_context_entry_one_step')
FLAGS.add('xnu_txm_context_entry_register_prefix')
FLAGS.add('xnu_txm_context_stack_claim_one_step')
FLAGS.add('xnu_txm_context_stack_metadata_init')
FLAGS.add('xnu_txm_context_x18_branch_one_step')
FLAGS.add('xnu_txm_context_outbound_branch_one_step')
FLAGS.add('xnu_txm_sstep_fast_path')
FLAGS.add('xnu_phase53_allocation_trace')
FLAGS.add('xnu_phase53_retype_survey')


# Approximate cost of one USB single-step, from attempt-17 (~525K steps in ~15 min).
SINGLE_STEP_MS = 1.7
# Warn once a single-step tail is expected to exceed this many minutes.
SLOW_SINGLE_STEP_MINUTES = 3.0

SUMMARY_FIELDS = (
    'stop_reason', 'guest_returned', 'proxy_alive_after_exit',
    'guest_execution_duration_seconds', 'xnu_guest_registers',
    'xnu_agtcnt_rdir_cleanup', 'xnu_cntp_ctl_cleanup', 'xnu_m3_ahcr_compat',
    'xnu_txm_sstep_fast_path',
    'xnu_phase53_allocation_trace',
    'xnu_phase53_retype_survey',
    'xnu_pmcr1_bank_collapse', 'error', 'cleanup_error',
    'xnu_dockchannel_uart_mmio', 'xnu_private_panic_carveout',
    'xnu_private_socd_trace',
    'xnu_pperm_guest_window', 'xnu_pperm_guest_window_cleanup',
    'xnu_apple_physical_timer_hypothesis', 'xnu_apple_physical_timer_cleanup',
    'xnu_tpidr_gl2_fast_shadow',
    'xnu_txm_context_entry_one_step', 'eret_classifications',
    'xnu_txm_context_entry_register_prefix',
    'xnu_txm_context_stack_claim_one_step',
    'xnu_txm_context_stack_metadata_init',
    'xnu_txm_context_x18_branch_one_step',
    'xnu_txm_context_outbound_branch_one_step',
    'xnu_txm_handler_boundary',
    'report_save_error', 'trace_incomplete', 'unsupported_exception_fault',
    'final_guest_exception_registers',
)


def summarize_report(report):
    """Build a compact summary without confusing handoff observer state with the stop."""
    summary = {key: report[key] for key in SUMMARY_FIELDS if key in report}
    trace = report.get('trace') or []
    events = [event for event in trace if isinstance(event, dict)]
    if events:
        last = events[-1]
        summary['stop_event'] = {key: last[key] for key in
            ('kind', 'pc', 'esr', 'far', 'reason', 'code') if key in last}
    pcs = {event['pc'] for event in events if event.get('pc') is not None}
    summary['activity'] = dict(
        trace_total_events=report.get('trace_total_events', len(trace)),
        xnu_sptm_callbacks=report.get('xnu_sptm_callbacks', 0),
        retained_events=len(trace), retained_distinct_pcs=len(pcs))
    if 'handoff' in report:
        handoff = {key: report['handoff'][key] for key in
            ('image', 'entry_reached', 'instructions_executed',
             'last_pc', 'observed_events') if key in report['handoff']}
        if 'last_pc' in handoff:
            handoff['last_observed_pc'] = handoff['last_pc']
            handoff['last_pc_scope'] = (
                'handoff observer; legacy alias of last_observed_pc; updated during '
                'bounded handoff steps and terminal native exceptions, but not every callback '
                'or watchdog stop')
        summary['handoff'] = handoff
    return summary


def lint_config(config):
    """Non-fatal pre-flight warnings for configs that are valid but costly or
    likely-wrong on hardware. Returns a list of warning strings (empty = clean).

    These never block a run; they surface footguns that have burned real hardware
    attempts on the target M3 (see docs/speed-retrospective.md). Hardware attempts are the
    scarce resource, so catching a slow or misconfigured run before launch is worth
    more than a fast one afterward.
    """
    warnings = []
    steps = config.get('steps', 0)
    after = config.get('single_step_after', 0)
    if after and 0 < after < steps:
        tail = steps - after
        minutes = tail * SINGLE_STEP_MS / 60000.0
        if minutes >= SLOW_SINGLE_STEP_MINUTES:
            warnings.append(
                'single_step_after={} with steps={} single-steps ~{} events over USB '
                '(~{:.0f} min at ~{:g} ms/step). Attempt-17 crawled exactly this way. '
                'Use single_step_after=0 for a fully batched run, or bound the window.'
                .format(after, steps, tail, minutes, SINGLE_STEP_MS))
    if config.get('real_guarded') and not config.get('stage_el2_config'):
        warnings.append(
            'real_guarded is set but stage_el2_config is not. Real guarded execution '
            'needs the EL2 SPRR/GXF context enabled before the guest runs; without it '
            'attempts 12-16 hit EC-0 faults. Set stage_el2_config=true.')
    if (config.get('real_guarded') and not config.get('stop_on_guarded_vector')
            and not config.get('single_step_window') and not config.get('free_run')):
        warnings.append(
            'real_guarded without stop_on_guarded_vector (or single_step_window): a '
            'guarded-world divert vectors through VBAR_GL1, which stop_on_vector_entry '
            '(EL1 VBAR_EL12) does not catch, so the run spins to the step budget as in '
            'attempt-18 (659 s). Set stop_on_guarded_vector=true to halt at the divert.')
    if config.get('first_contact') and not (config.get('single_step_window') or config.get('single_step_after')):
        warnings.append(
            'first_contact without single_step_window/single_step_after: the injected '
            'genter transition (idle -> dispatcher -> 0xa4ac0) must be single-stepped to '
            'be captured and to halt before the service; set single_step_window over the '
            'idle region (~7.81M for the attempt-21 build).')
    if config.get('guarded_call_selectors') and not (config.get('single_step_window') or config.get('single_step_after')):
        warnings.append(
            'guarded_call_selectors without single_step_window/single_step_after: the '
            'per-call x16 set and x0 capture happen at single-step granularity over the '
            'genter loop; set single_step_window over the idle region (~7.81M).')
    if config.get('free_run') and not config.get('hang_budget'):
        warnings.append('free_run requires an explicit hang_budget (seconds) for timer-polled clean exit.')
    return warnings


def probe_command(config, output, execute):
    if set(config)-FIELDS or not {'payload','checkout','device','steps'} <= set(config):
        raise ValueError('Unknown or missing pipeline configuration fields')
    for key in FLAGS & set(config):
        if type(config[key]) is not bool:
            raise ValueError('Expected Boolean configuration: '+key)
    for key in ('payload','checkout','device'):
        if not isinstance(config[key],str) or not config[key]:
            raise ValueError('Expected nonempty configuration string: '+key)
    for key in ('steps','step_batch','trace_window','pause_timeout','single_step_after','on_demand_stage2'):
        if key in config and type(config[key]) is not int:
            raise ValueError('Expected integer configuration: '+key)
    if 'single_step_after' in config and not 0 <= config['single_step_after'] <= 33554432:
        raise ValueError('single_step_after must be 0..33554432')
    if 'on_demand_stage2' in config and not 0 <= config['on_demand_stage2'] <= 1048576:
        raise ValueError('on_demand_stage2 must be 0..1048576')
    if config.get('real_guarded') and config.get('virtual_gxf'):
        raise ValueError('real_guarded and virtual_gxf are mutually exclusive')
    if config.get('real_guarded_vbar') and not config.get('real_guarded'):
        raise ValueError('real_guarded_vbar requires real_guarded')
    if config.get('stop_on_guarded_vector') and not config.get('real_guarded'):
        raise ValueError('stop_on_guarded_vector requires real_guarded')
    if 'handoff_steps' in config:
        if type(config['handoff_steps']) is not int or not 0 <= config['handoff_steps'] <= 4096:
            raise ValueError('handoff_steps must be integer events in 0..4096')
        if config['handoff_steps'] and not (config.get('free_run') and config.get('real_guarded')):
            raise ValueError('handoff_steps requires free_run and real_guarded')
    if 'xnu_steps' in config:
        if type(config['xnu_steps']) is not int or not 0 <= config['xnu_steps'] <= 4096:
            raise ValueError('xnu_steps must be integer events in 0..4096')
        if config['xnu_steps'] and not config.get('native_handoff'):
            raise ValueError('xnu_steps requires native_handoff')
    if config.get('xnu_run') and not config.get('xnu_steps'):
        raise ValueError('xnu_run requires xnu_steps')
    if config.get('xnu_m3_nop_ahcr_compat') and not config.get('xnu_run'):
        raise ValueError('xnu_m3_nop_ahcr_compat requires xnu_run')
    if config.get('xnu_dockchannel_uart_mmio') and not (
            config.get('xnu_run') and config.get('on_demand_stage2')):
        raise ValueError('xnu_dockchannel_uart_mmio requires xnu_run and on_demand_stage2')
    if config.get('xnu_private_panic_carveout') and not (
            config.get('xnu_run') and config.get('on_demand_stage2')):
        raise ValueError('xnu_private_panic_carveout requires xnu_run and on_demand_stage2')
    if config.get('xnu_private_socd_trace') and not (
            config.get('xnu_run') and config.get('on_demand_stage2')):
        raise ValueError('xnu_private_socd_trace requires xnu_run and on_demand_stage2')
    if config.get('xnu_pperm_guest_window') and not config.get('xnu_run'):
        raise ValueError('xnu_pperm_guest_window requires xnu_run')
    if 'xnu_pperm_guest_window_limit' in config:
        limit = config['xnu_pperm_guest_window_limit']
        if type(limit) is not int or not 1 <= limit <= 4096:
            raise ValueError('xnu_pperm_guest_window_limit must be integer 1..4096')
        if limit != 1 and not config.get('xnu_pperm_guest_window'):
            raise ValueError('xnu_pperm_guest_window_limit requires xnu_pperm_guest_window')
    if config.get('xnu_apple_physical_timer_hypothesis') and not config.get('xnu_run'):
        raise ValueError('xnu_apple_physical_timer_hypothesis requires xnu_run')
    if config.get('xnu_tpidr_gl2_fast_shadow') and not config.get('xnu_run'):
        raise ValueError('xnu_tpidr_gl2_fast_shadow requires xnu_run')
    if config.get('xnu_txm_context_entry_one_step') and not config.get('xnu_run'):
        raise ValueError('xnu_txm_context_entry_one_step requires xnu_run')
    if config.get('xnu_txm_context_entry_register_prefix') and not config.get('xnu_run'):
        raise ValueError('xnu_txm_context_entry_register_prefix requires xnu_run')
    if config.get('xnu_txm_context_stack_claim_one_step') and not config.get('xnu_run'):
        raise ValueError('xnu_txm_context_stack_claim_one_step requires xnu_run')
    if config.get('xnu_txm_context_stack_metadata_init') and not config.get('xnu_run'):
        raise ValueError('xnu_txm_context_stack_metadata_init requires xnu_run')
    if config.get('xnu_txm_context_x18_branch_one_step') and not config.get('xnu_run'):
        raise ValueError('xnu_txm_context_x18_branch_one_step requires xnu_run')
    if config.get('xnu_txm_context_outbound_branch_one_step') and not config.get('xnu_run'):
        raise ValueError('xnu_txm_context_outbound_branch_one_step requires xnu_run')
    if config.get('xnu_txm_handler_boundary') not in (
            None, 'prologue', 'register-saves', 'local-setup', 'validator-entry',
            'validator-trace', 'response-trace', 'cmd1-completion-trace'):
        raise ValueError('xnu_txm_handler_boundary must be prologue, register-saves, local-setup, validator-entry, validator-trace, response-trace, or cmd1-completion-trace')
    if config.get('xnu_txm_handler_boundary') and not config.get('xnu_run'):
        raise ValueError('xnu_txm_handler_boundary requires xnu_run')
    if (config.get('xnu_txm_sstep_fast_path') and
            config.get('xnu_txm_handler_boundary') != 'cmd1-completion-trace'):
        raise ValueError('xnu_txm_sstep_fast_path requires cmd1-completion-trace')
    if (config.get('xnu_phase53_allocation_trace') and
            (not config.get('xnu_txm_sstep_fast_path') or
             config.get('xnu_txm_handler_boundary') != 'cmd1-completion-trace')):
        raise ValueError('xnu_phase53_allocation_trace requires cmd1-completion-trace and xnu_txm_sstep_fast_path')
    if (config.get('xnu_phase53_retype_survey') and
            not config.get('xnu_phase53_allocation_trace')):
        raise ValueError('xnu_phase53_retype_survey requires xnu_phase53_allocation_trace')
    if 'xnu_phase53_retype_survey_limit' in config:
        limit = config['xnu_phase53_retype_survey_limit']
        if type(limit) is not int or not 1 <= limit <= 64:
            raise ValueError('xnu_phase53_retype_survey_limit must be integer 1..64')
        if not config.get('xnu_phase53_retype_survey'):
            raise ValueError('xnu_phase53_retype_survey_limit requires xnu_phase53_retype_survey')
    if sum(bool(config.get(name)) for name in ('xnu_txm_context_entry_one_step',
            'xnu_txm_context_entry_register_prefix',
            'xnu_txm_context_stack_claim_one_step',
            'xnu_txm_context_stack_metadata_init',
            'xnu_txm_context_x18_branch_one_step',
            'xnu_txm_context_outbound_branch_one_step',
            'xnu_txm_handler_boundary')) > 1:
        raise ValueError('TXM context-entry probes are mutually exclusive')
    if config.get('native_handoff'):
        if not (config.get('free_run') and config.get('real_guarded')):
            raise ValueError('native_handoff requires free_run and real_guarded')
        if config.get('handoff_steps'):
            raise ValueError('native_handoff and handoff_steps are mutually exclusive')
    if 'handoff_breakpoint_offset' in config:
        raise ValueError('handoff_breakpoint_offset is unsafe in real guarded execution')
    if 'hang_budget' in config and (type(config['hang_budget']) is not int or not 1 <= config['hang_budget'] <= 86400):
        raise ValueError('hang_budget must be integer seconds in 1..86400')
    if 'hang_budget' in config and not config.get('free_run'):
        raise ValueError('hang_budget requires free_run')
    if config.get('free_run'):
        if 'hang_budget' not in config:
            raise ValueError('free_run requires hang_budget')
        for incompatible in ('single_step_window','guarded_call_selectors','first_contact','single_step_after'):
            if config.get(incompatible):
                raise ValueError('free_run is incompatible with '+incompatible)
    if config.get('first_contact') and not config.get('real_guarded'):
        raise ValueError('first_contact requires real_guarded')
    if 'guarded_call_selectors' in config:
        spec = config['guarded_call_selectors']
        if not config.get('real_guarded'):
            raise ValueError('guarded_call_selectors requires real_guarded')
        if not isinstance(spec, str) or not spec.strip():
            raise ValueError('guarded_call_selectors must be a nonempty comma-separated string')
        try:
            sels = [int(s, 0) for s in spec.split(',') if s.strip()]
        except ValueError:
            raise ValueError('guarded_call_selectors must be comma-separated hex/int values: '+spec)
        if not sels or len(sels) > 256:
            raise ValueError('guarded_call_selectors must list 1..256 selectors')
    if 'single_step_window' in config:
        spec = config['single_step_window']
        if not isinstance(spec, str) or not spec:
            raise ValueError('single_step_window must be a nonempty START[:COUNT] string')
        parts = spec.split(':')
        if len(parts) > 2:
            raise ValueError('single_step_window must be START[:COUNT]: '+spec)
        try:
            start = int(parts[0], 0)
            count = int(parts[1], 0) if len(parts) > 1 else 1
        except ValueError:
            raise ValueError('single_step_window START/COUNT must be decimal or 0x hex: '+spec)
        if start < 0 or not 1 <= count <= 1048576:
            raise ValueError('single_step_window START must be >= 0 and COUNT 1..1048576: '+spec)
    if 'pause_timeout' in config and not 0 < config['pause_timeout'] <= 86400:
        raise ValueError('Guard pause timeout must be 1..86400 seconds')
    if 'back_page' in config:
        specs = config['back_page']
        specs = specs if isinstance(specs, list) else [specs]
        if not specs:
            raise ValueError('back_page must be a nonempty hex string or list')
        for spec in specs:
            if not isinstance(spec, str) or not spec:
                raise ValueError('Expected nonempty hex string configuration: back_page')
            base, _, count_text = spec.partition(':')
            try:
                ipa = int(base, 0)
                count = int(count_text, 0) if count_text else 1
            except ValueError:
                raise ValueError('back_page must be IPA[:count] (hex/int): '+spec)
            if ipa & 0x3fff:
                raise ValueError('back_page IPA must be 16KB aligned: '+spec)
            if not 1 <= count <= 4096:
                raise ValueError('back_page count must be 1..4096: '+spec)
    if 'snapshot_leaf' in config:
        specs = config['snapshot_leaf']
        specs = specs if isinstance(specs, list) else [specs]
        if not specs:
            raise ValueError('snapshot_leaf must be a nonempty hex string or list')
        for spec in specs:
            if not isinstance(spec, str) or not spec:
                raise ValueError('Expected nonempty hex string configuration: snapshot_leaf')
            try:
                int(spec, 0)
            except ValueError:
                raise ValueError('snapshot_leaf must be a hex integer string: '+spec)
    steps=config['steps'];batch=config.get('step_batch',0);window=config.get('trace_window')
    if not 1 <= steps <= 33554432 or not 0 <= batch <= 256:
        raise ValueError('Unsupported execution budget or batch size')
    if steps > 2097152 and not batch or steps > 131072 and window is None or window is not None and window < 8192:
        raise ValueError('Long probes require batching and a bounded trace window')
    command=[sys.executable,str(REPO/'scripts/sptm_entry_probe.py'),
             '--report='+str(output/'report.json'),'--run-dir='+str(output/'runs')]
    for key,value in sorted(config.items()):
        option='--'+key.replace('_','-')
        if key in FLAGS:
            if value:command.append(option)
        elif isinstance(value,list):
            for item in value:command.append(option+'='+str(item))
        else:command.append(option+'='+str(value))
    if execute:command.append('--execute')
    return command


def package(output):
    """Publish only a closed archive; never include the archive inside itself."""
    target=output.with_name(output.name+'.tar.gz')
    if target.exists():raise ValueError('Transfer archive already exists')
    temporary=target.with_name(target.name+'.partial')
    with tarfile.open(temporary,'w:gz',compresslevel=1) as archive:
        archive.add(output,arcname=output.name)
    temporary.rename(target)
    identity=file_identity(target)
    atomic_json(target.with_name(target.name+'.identity.json'),identity)
    return identity


def consume_pipeline_receipt(receipt_path, key_path, config, output):
    """Consume and retain a gate receipt while the caller holds the device lock."""
    checkout = Path(config['checkout'])
    record = consume_receipt(
        receipt_path=receipt_path, key_path=key_path,
        expected_device=config['device'],
        expected_runtime_image=checkout/'build/m1n1.bin',
        expected_runtime_elf=checkout/'build/m1n1-raw.elf')
    retained = Path(output)/'fresh-gate-receipt.json'
    retained.write_bytes(Path(receipt_path).read_bytes())
    atomic_json(Path(output)/'fresh-gate-consumption.json', record)
    return {'mode': 'authenticated-one-use', 'receipt': file_identity(retained),
            'consumption': record}


def validate_gate_selection(execute, receipt, legacy_full_gate):
    if execute and bool(receipt) == bool(legacy_full_gate):
        raise ValueError(
            '--execute requires exactly one of --fresh-gate-receipt or --legacy-full-gate')
    if not execute and (receipt or legacy_full_gate):
        raise ValueError('Fresh-gate options apply only with --execute')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True,help='New directory for this attempt')
    ap.add_argument('--execute',action='store_true')
    ap.add_argument('--fresh-gate-receipt',type=Path,
                    help='Authenticated one-use receipt from the accelerated fresh gate')
    ap.add_argument('--legacy-full-gate',action='store_true',
                    help='Transitional assertion that the four-stage legacy gate passed')
    a=ap.parse_args();config=json.loads(a.config.read_text());output=a.output.resolve()
    try:
        validate_gate_selection(a.execute,a.fresh_gate_receipt,a.legacy_full_gate)
    except ValueError as error:
        ap.error(str(error))
    for warning in lint_config(config):
        print('PRE-FLIGHT WARNING: '+warning,file=sys.stderr)
    command=probe_command(config,output,a.execute)
    output.mkdir(parents=True,exist_ok=False)
    atomic_json(output/'config.json',config)
    result=dict(started_at=utc(),ended_at=None,execute=a.execute,phase='starting',command=command)
    lock=None;code=1
    try:
        if a.execute:
            lock=acquire_device_lock(config['device'])
            if a.fresh_gate_receipt:
                result['phase']='consume-fresh-gate';atomic_json(output/'pipeline.json',result)
                result['fresh_gate']=consume_pipeline_receipt(
                    a.fresh_gate_receipt,FRESH_GATE_KEY,config,output)
            else:
                result['fresh_gate']={'mode':'legacy-full-gate-operator-asserted'}
        result['phase']='probe';atomic_json(output/'pipeline.json',result)
        with (output/'console.log').open('w') as log:
            code=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT).returncode
        result['probe_exit_code']=code
        if code:
            # Setup can fail before report error fields exist; surface the original traceback.
            result['failure_console_tail'] = (output/'console.log').read_text(errors='replace')[-4000:]
        report_path=output/'report.json'
        if a.execute and report_path.exists():
            report=json.loads(report_path.read_text());result['run_id']=report.get('run_id')
            result['probe_summary'] = summarize_report(report)
            # Decode the full event archive so early console output survives a
            # rolling report window. This is offline and also works after faults.
            from extract_xnu_console import recover_console
            try:
                recovered, evidence = recover_console(report, output/'runs')
                (output/'xnu-console.txt').write_bytes(recovered)
                result['xnu_console_bytes'] = len(recovered)
                result['xnu_console_evidence'] = evidence
                result['probe_summary']['console_tail'] = recovered[-2048:].decode(
                    'utf-8', errors='backslashreplace')
            except Exception as console_error:
                result['xnu_console_error'] = str(console_error)
            if report.get('proxy_alive_after_exit') is True and report.get('monitor_mmu_controls'):
                result['phase']='diagnostics';atomic_json(output/'pipeline.json',result)
                diagnostic=[sys.executable,str(REPO/'scripts/probe_diagnostics.py'),str(report_path),
                    '--checkout='+config['checkout'],'--device='+config['device'],
                    '--output='+str(output/'diagnostics.json'),'--table-snapshot='+str(output/'tables')]
                with (output/'diagnostics.log').open('w') as log:
                    diag_code=subprocess.run(diagnostic,stdout=log,stderr=subprocess.STDOUT).returncode
                result['diagnostics_exit_code']=diag_code
                code=code or diag_code
        result['phase']='finished' if code==0 else 'failed'
    except BaseException as error:
        result['error']=str(error);result['phase']='failed';code=code or 1
    finally:
        if lock is not None:lock.close()
        result['ended_at']=utc();atomic_json(output/'pipeline.json',result)
    # Preserve failure evidence too, without labelling a failed probe successful.
    identity=package(output)
    print(json.dumps(dict(pipeline=result,transfer=identity),indent=2))
    raise SystemExit(code)


if __name__=='__main__':main()
