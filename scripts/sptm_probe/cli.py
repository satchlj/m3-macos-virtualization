# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
'Bounded SPTM instruction trace in isolated guest RAM; not a macOS boot loader.'
import argparse
import os
from pathlib import Path
import signal
import sys
from run_manifest import RunCapture
from .runtime import run_probe

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--checkout', type=Path, default=os.environ.get('VEL2_CHECKOUT'))
    ap.add_argument('--payload', type=Path, required=True)
    ap.add_argument('--device')
    ap.add_argument('--execute', action='store_true')
    ap.add_argument('--allow-monitor-mmu', action='store_true', help='Permit only the captured VHE monitor profile after address checks')
    ap.add_argument('--emulate-zero-loops', action='store_true', help='Emulate only an exact bounded zero-fill instruction pattern')
    ap.add_argument('--allow-live-ttbr', action='store_true', help='Validate bounded same-profile root replacements and continuation mappings')
    ap.add_argument('--relocate-boot-data', action='store_true', help='Copy RTBuddySeg, SEPFW and preoslog into guest RAM with contained firmware aliases')
    ap.add_argument('--steps', type=int, default=128)
    ap.add_argument('--report', type=Path, required=True)
    ap.add_argument('--run-dir', type=Path, help='Parent for unique attempt bundles; defaults beside report')
    ap.add_argument('--trace-window', type=int, help='Keep this many recent events in JSON and stream all events to JSONL; minimum 8192')
    ap.add_argument('--step-batch', type=int, default=0, help='Native ordinary-step batch size (0 disables; maximum 256); requires matching batch-capable runtime')
    ap.add_argument('--observe-sprr', action='store_true', help='Stage SPRR configuration writes while translation is live without enforcing any permission; observation only')
    ap.add_argument('--virtual-gxf', action='store_true', help='Observation-grade guarded world: genter/gexit control flow and banked exception state, no permission or guarded-page enforcement')
    ap.add_argument('--stage-el2-config', action='store_true', help='Record the monitor\'s remaining EL2 configuration writes (stage-2, traps, CTRR, locks, timers) without applying them')
    ap.add_argument('--stop-on-vector-entry', action='store_true', help='Exit at the first recorded PC inside the current guest VBAR_EL12 vector range')
    ap.add_argument('--pause-on-guard', action='store_true', help='Hold a deliberately rejected policy guard for a local resume/exit decision')
    ap.add_argument('--pause-timeout', type=float, default=3600, help='Seconds to wait for a guard decision before exiting the guest (maximum 86400)')
    ap.add_argument('--back-page', action='append', default=None, metavar='IPA[:COUNT]', help='Diagnostic: back COUNT contiguous 16KB guest IPA pages (hex base, 0x4000-aligned; COUNT default 1) with zeroed host RAM so monitor reads/writes to that region resolve; repeatable, observation only')
    ap.add_argument('--on-demand-stage2', type=int, default=0, metavar='MAXPAGES', help='Back guest stage-2 translation faults on demand: on a data-abort translation fault, translate the faulting VA stage-1-only to its IPA, map a fresh zeroed 16KB host page there, and retry. MAXPAGES caps the total pages mapped (0 disables). Needed once SPTM builds its frame table over physical pages our fixed guest window does not back.')
    ap.add_argument('--handoff-steps', type=int, default=0, help='After a verified TXM/XNU entry handoff, single-step at most 1..4096 events; default 0 stops before transfer')
    ap.add_argument('--handoff-breakpoint-offset', type=lambda value: int(value, 0), help='Rejected legacy control: software HVC breakpoints route into SPTM under real guarded execution')
    ap.add_argument('--native-handoff', action='store_true', help='After a verified TXM/XNU entry handoff, resume it natively without single-step; use guarded-vector and watchdog stops to capture the next firmware exception')
    ap.add_argument('--xnu-steps', type=int, default=0, help='After native TXM completion, normalize the verified XNU GEXIT to physical EL1h and single-step up to 1..4096 events')
    ap.add_argument('--xnu-run', action='store_true', help='After the bounded verified XNU prefix, run natively until the next probe exception or watchdog')
    ap.add_argument('--xnu-m3-nop-ahcr-compat', action='store_true', help='Diagnostic: reproduce upstream m1n1 M3 behavior by NOPing only the exact pinned XNU AHCR_EL2 pair; does not emulate AHCR hardware effects')
    ap.add_argument('--xnu-dockchannel-uart-mmio', action='store_true', help='After XNU handoff, lazily identity-map only the source-verified M3 dockchannel-uart register page on its exact stage-2 fault; requires --xnu-run and --on-demand-stage2')
    ap.add_argument('--xnu-private-panic-carveout', action='store_true', help='Copy the verified panic-log carveout into private host RAM, then remap its original IPA only at the exact first XNU fault; original firmware memory is never written; requires --xnu-run and --on-demand-stage2')
    ap.add_argument('--xnu-private-socd-trace', action='store_true', help='Copy only the exact 924-byte /socd-trace-ram region into a private zero-padded 16KB page and map it at the exact first XNU fault; requires --xnu-run and --on-demand-stage2')
    ap.add_argument('--xnu-pperm-guest-window', action='store_true', help='Redirect only the pinned XNU temporary PPERM A-B-A window to PPERM_EL12; requires --xnu-run')
    ap.add_argument('--xnu-pperm-guest-window-limit', type=int, default=1, help='Maximum complete PPERM guest windows (1..4096); requires --xnu-pperm-guest-window for values other than 1')
    ap.add_argument('--xnu-apple-physical-timer-hypothesis', action='store_true', help='Diagnostic hypothesis: service only the exact attempt-65 Apple timer trap through candidate guest bank S3_4_C15_C4_3 after verifying its retained raw value 6; routing and bit semantics remain inferred; requires --xnu-run')
    ap.add_argument('--xnu-tpidr-gl2-fast-shadow', action='store_true', help='After the verified XNU prefix only, move the existing TPIDR_GL2 HVC shadow into the pinned firmware fast path; requires --xnu-run')
    ap.add_argument('--xnu-gl1-fast-redirect', action='store_true', help='After the verified XNU prefix only, accelerate the seven pinned GL1 exception-bank HVC sites through live GL12 aliases; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-entry-one-step', action='store_true', help='At the exact verified TXM context-entry ERET only, execute mov sp,x0 and stop at the following software-step; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-entry-register-prefix', action='store_true', help='Execute only the exact deterministic non-memory TXM context-entry prefix and stop before its first CASB; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-stack-claim-one-step', action='store_true', help='After the verified TXM register prefix, execute only its exact CASB 0-to-1 owned-stack claim and stop; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-stack-metadata-init', action='store_true', help='After the verified TXM stack claim, take only the exact x9==0 path, verify its three same-page metadata stores, and stop before the x18 branch; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-x18-branch-one-step', action='store_true', help='After verified TXM stack metadata initialization, execute only the exact taken x18 CBNZ and stop before its target branch; requires --xnu-run')
    ap.add_argument('--xnu-txm-context-outbound-branch-one-step', action='store_true', help='After the verified x18 branch, execute only the exact outbound B into the TXM command handler and stop before PACIBSP; requires --xnu-run')
    ap.add_argument('--xnu-txm-handler-boundary', choices=('prologue', 'register-saves', 'local-setup', 'validator-entry', 'validator-trace', 'response-trace', 'cmd1-completion-trace'), help='Replay the exact TXM context-entry path and stop at a named, source-pinned handler boundary; requires --xnu-run')
    ap.add_argument('--xnu-txm-sstep-fast-path', action='store_true', help='At the source/live-verified cmd1 completion SVC only, use the bounded firmware software-step filter across TXM/SPTM and stop at the exact XNU return; requires --xnu-txm-handler-boundary=cmd1-completion-trace')
    ap.add_argument('--xnu-phase53-allocation-trace', action='store_true', help='After verified cmd1 completion, continue with the bounded firmware filter to the exact XNU allocation call; requires cmd1 completion fast path')
    ap.add_argument('--xnu-phase53-retype-survey', action='store_true', help='After the verified Phase 5.3 allocation retype, survey at most 64 subsequent common-wrapper retypes and stop at the first XNU root/page-table target')
    ap.add_argument('--xnu-phase53-retype-survey-limit', type=int, default=64, help='Maximum completed common-wrapper retypes in the Phase 5.3 survey (1..64)')
    ap.add_argument('--xnu-phase53-retype-hvc-fast-path', action='store_true', help='Late-patch three pinned common-wrapper MOVs with strict PRE/GENTER/POST HVC callbacks, eliminating survey seek loops while proving actual genter arguments; requires the Phase 5.3 retype survey and GL1 fast redirect')
    ap.add_argument('--xnu-phase53-descriptor-bind', action='store_true', help='After the primary 0xb-to-0x14 survey target, verify the bounded selector-3 L2 descriptor bind; requires the Phase 5.3 retype survey')
    ap.add_argument('--xnu-phase53-leaf-page-bind', action='store_true', help='After the verified selector-3 L2 descriptor bind, verify the bounded selector-2 leaf-page bind; requires the Phase 5.3 descriptor bind')
    ap.add_argument('--xnu-phase53-adt-entropy-replay', action='store_true', help='Replace only /chosen random-seed, cl4-entropy, and boot-nonce in the constructed guest ADT with the pinned Attempt108 values; requires the Phase 5.3 retype survey')
    ap.add_argument('--hang-budget', type=int, help='Required with --free-run: guest wall-clock limit in seconds (1..86400); timer-polled clean interrupt, then 15s grace')
    ap.add_argument('--free-run', action='store_true', help='Run the guest natively (no single-step) to reach a milestone fast: handle every trap as now but resume without the single-step bit, disable batching, enable HCR.TWE so the panic wfe-halt (0xf8b88) traps (a benign wfe is skipped), and stop at a verified image entry handoff or the panic halt. Pair with --on-demand-stage2. Per-step features (zero-loop emulation, single-step window, guarded-call selectors) do not apply.')
    ap.add_argument('--snapshot-leaf', action='append', default=None, metavar='VA', help='At exit, walk the final monitor ttbr for each VA (hex), save the walked tables, and decode the leaf against live guest SPRR permissions in real mode (staged otherwise); observation only, repeatable')
    ap.add_argument('--single-step-after', type=int, default=0, help='After this many recorded events, stop native batching and single-step so a vector-entry syndrome is captured without batch overshoot (0 disables)')
    ap.add_argument('--real-guarded', action='store_true', help='R2 (real enforcement): do not virtualize genter/gexit (native GXF transitions) and really enable SPRR at the enable point (apply captured permissions then config), instead of staging. Off by default; first-contact use only, gated by the reversibility rehearsal.')
    ap.add_argument('--real-guarded-vbar', action='store_true', help='With real guarded execution, apply SPTM VBAR_GL1 writes through the existing VBAR_GL12 alias so TXM exceptions reach SPTM vectors; hardware-check one register path at a time')
    ap.add_argument('--single-step-window', metavar='START:COUNT', help='Single-step recorded events in [START, START+COUNT) and batch outside it, so a bounded transition (e.g. the genter divert) is captured at instruction granularity without crawling the whole tail or spinning to budget. COUNT default 1.')
    ap.add_argument('--stop-on-guarded-vector', action='store_true', help='In --real-guarded, stop at the first guarded-world exception vector entry (a recorded PC inside the current VBAR_GL1 range) and snapshot the guarded bank (ESR_GL1/ELR_GL1/VBAR_GL1) so the original trigger syndrome is captured before the self-fault spin overwrites it.')
    ap.add_argument('--first-contact', action='store_true', help='R2 first contact (requires --real-guarded): patch the SPTM normal-world WFE idle at 0xf8b88 to genter #0 so, once SPTM finishes init and reaches idle, it issues a real guarded call into the dispatcher (0xa4524). Single-step across the boundary and HALT at 0xa4ac0, before the T0 branch to the C service (0xe8d4c) -- non-mutating by construction. Requires single-step coverage of the idle region (single-step-window/after).')
    ap.add_argument('--guarded-call-selectors', metavar='HEX[,HEX...]', help='R2 multi-call (requires --real-guarded): reuse the idle->genter patch to issue one real guarded call per selector, IN ONE run (the patched idle is a genter loop: genter->service->gexit->b->genter). Sets x16=selector at each genter and captures x0 at each return; stops after the list. MUTATING -- the C service runs. Needs single-step coverage of the call region. This is the way to do consecutive guarded work without a power cycle (a 2nd hv_start cannot: SPTM locks SPRR/GXF).')
    a = ap.parse_args()
    if a.checkout is None or not 1 <= a.steps <= 33554432:
        ap.error('A checkout and 1..33554432 steps are required')
    if a.real_guarded and a.virtual_gxf:
        ap.error('--real-guarded and --virtual-gxf are mutually exclusive (real vs observation-grade GXF)')
    if a.real_guarded_vbar and not a.real_guarded:
        ap.error('--real-guarded-vbar requires --real-guarded')
    if a.single_step_window is not None:
        try:
            parts = a.single_step_window.split(':')
            start = int(parts[0], 0)
            count = int(parts[1], 0) if len(parts) > 1 else 1
        except (ValueError, IndexError):
            ap.error('--single-step-window must be START[:COUNT] (decimal or 0x hex)')
        if len(parts) > 2 or start < 0 or not 1 <= count <= 1048576:
            ap.error('--single-step-window START must be >= 0 and COUNT 1..1048576')
    if a.stop_on_guarded_vector and not a.real_guarded:
        ap.error('--stop-on-guarded-vector requires --real-guarded')
    if a.first_contact and not a.real_guarded:
        ap.error('--first-contact requires --real-guarded')
    if a.guarded_call_selectors is not None:
        if not a.real_guarded:
            ap.error('--guarded-call-selectors requires --real-guarded')
        try:
            sels = [int(s, 0) for s in a.guarded_call_selectors.split(',') if s.strip()]
        except ValueError:
            ap.error('--guarded-call-selectors must be a comma-separated list of hex/int selector values')
        if not sels or len(sels) > 256 or any(not 0 <= s <= (1 << 64) - 1 for s in sels):
            ap.error('--guarded-call-selectors: 1..256 selectors, each a 64-bit value')
    if not 0 <= a.step_batch <= 256:
        ap.error('--step-batch must be 0..256')
    if a.steps > 2097152 and not a.step_batch:
        ap.error('Budgets above 2097152 require native step batching')
    if a.trace_window is not None and a.trace_window < 8192:
        ap.error('--trace-window must be at least 8192')
    if a.steps > 131072 and a.trace_window is None:
        ap.error('Budgets above 131072 require --trace-window')
    if a.execute and not a.device:
        ap.error('--execute requires --device')
    if not 0 < a.pause_timeout <= 86400:
        ap.error('--pause-timeout must be in (0, 86400] seconds')
    if a.free_run and (a.hang_budget is None or not 1 <= a.hang_budget <= 86400):
        ap.error('--free-run requires --hang-budget in 1..86400 seconds')
    if a.hang_budget is not None and not a.free_run:
        ap.error('--hang-budget requires --free-run')
    if a.xnu_apple_physical_timer_hypothesis and not a.xnu_run:
        ap.error('--xnu-apple-physical-timer-hypothesis requires --xnu-run')
    if a.xnu_tpidr_gl2_fast_shadow and not a.xnu_run:
        ap.error('--xnu-tpidr-gl2-fast-shadow requires --xnu-run')
    if getattr(a, 'xnu_gl1_fast_redirect', False) and not a.xnu_run:
        ap.error('--xnu-gl1-fast-redirect requires --xnu-run')
    if a.xnu_txm_context_entry_one_step and not a.xnu_run:
        ap.error('--xnu-txm-context-entry-one-step requires --xnu-run')
    if a.xnu_txm_context_entry_register_prefix and not a.xnu_run:
        ap.error('--xnu-txm-context-entry-register-prefix requires --xnu-run')
    if a.xnu_txm_context_stack_claim_one_step and not a.xnu_run:
        ap.error('--xnu-txm-context-stack-claim-one-step requires --xnu-run')
    if a.xnu_txm_context_stack_metadata_init and not a.xnu_run:
        ap.error('--xnu-txm-context-stack-metadata-init requires --xnu-run')
    if a.xnu_txm_context_x18_branch_one_step and not a.xnu_run:
        ap.error('--xnu-txm-context-x18-branch-one-step requires --xnu-run')
    if a.xnu_txm_context_outbound_branch_one_step and not a.xnu_run:
        ap.error('--xnu-txm-context-outbound-branch-one-step requires --xnu-run')
    if a.xnu_txm_handler_boundary is not None and not a.xnu_run:
        ap.error('--xnu-txm-handler-boundary requires --xnu-run')
    if (a.xnu_txm_sstep_fast_path and
            a.xnu_txm_handler_boundary != 'cmd1-completion-trace'):
        ap.error('--xnu-txm-sstep-fast-path requires --xnu-txm-handler-boundary=cmd1-completion-trace')
    if (a.xnu_phase53_allocation_trace and
            (not a.xnu_txm_sstep_fast_path or
             a.xnu_txm_handler_boundary != 'cmd1-completion-trace')):
        ap.error('--xnu-phase53-allocation-trace requires the cmd1 completion fast path')
    if a.xnu_phase53_retype_survey and not a.xnu_phase53_allocation_trace:
        ap.error('--xnu-phase53-retype-survey requires --xnu-phase53-allocation-trace')
    if not 1 <= a.xnu_phase53_retype_survey_limit <= 64:
        ap.error('--xnu-phase53-retype-survey-limit must be in 1..64')
    if (a.xnu_phase53_retype_survey_limit != 64 and
            not a.xnu_phase53_retype_survey):
        ap.error('--xnu-phase53-retype-survey-limit requires --xnu-phase53-retype-survey')
    if (a.xnu_phase53_retype_hvc_fast_path and
            (not a.xnu_phase53_retype_survey or
             not a.xnu_gl1_fast_redirect)):
        ap.error('--xnu-phase53-retype-hvc-fast-path requires --xnu-phase53-retype-survey and --xnu-gl1-fast-redirect')
    if a.xnu_phase53_descriptor_bind and not a.xnu_phase53_retype_survey:
        ap.error('--xnu-phase53-descriptor-bind requires --xnu-phase53-retype-survey')
    if a.xnu_phase53_leaf_page_bind and not a.xnu_phase53_descriptor_bind:
        ap.error('--xnu-phase53-leaf-page-bind requires --xnu-phase53-descriptor-bind')
    if a.xnu_phase53_adt_entropy_replay and not a.xnu_phase53_retype_survey:
        ap.error('--xnu-phase53-adt-entropy-replay requires --xnu-phase53-retype-survey')
    if sum((a.xnu_txm_context_entry_one_step,
            a.xnu_txm_context_entry_register_prefix,
            a.xnu_txm_context_stack_claim_one_step,
            a.xnu_txm_context_stack_metadata_init,
            a.xnu_txm_context_x18_branch_one_step,
            a.xnu_txm_context_outbound_branch_one_step,
            a.xnu_txm_handler_boundary is not None)) > 1:
        ap.error('TXM context-entry probes are mutually exclusive')
    if not 0 <= a.handoff_steps <= 4096 or (a.handoff_steps and not (a.free_run and a.real_guarded)):
        ap.error('--handoff-steps requires --free-run --real-guarded and a budget in 1..4096')
    if a.native_handoff and (not (a.free_run and a.real_guarded) or a.handoff_steps):
        ap.error('--native-handoff requires --free-run --real-guarded and is mutually exclusive with handoff steps')
    if not 0 <= a.xnu_steps <= 4096 or (a.xnu_steps and not a.native_handoff):
        ap.error('--xnu-steps requires --native-handoff and a budget in 1..4096')
    if a.xnu_run and not a.xnu_steps:
        ap.error('--xnu-run requires --xnu-steps')
    if a.xnu_m3_nop_ahcr_compat and not a.xnu_run:
        ap.error('--xnu-m3-nop-ahcr-compat requires --xnu-run')
    if a.xnu_dockchannel_uart_mmio and not (a.xnu_run and a.on_demand_stage2):
        ap.error('--xnu-dockchannel-uart-mmio requires --xnu-run and --on-demand-stage2')
    if a.xnu_private_panic_carveout and not (a.xnu_run and a.on_demand_stage2):
        ap.error('--xnu-private-panic-carveout requires --xnu-run and --on-demand-stage2')
    if a.xnu_private_socd_trace and not (a.xnu_run and a.on_demand_stage2):
        ap.error('--xnu-private-socd-trace requires --xnu-run and --on-demand-stage2')
    if a.xnu_pperm_guest_window and not a.xnu_run:
        ap.error('--xnu-pperm-guest-window requires --xnu-run')
    if not 1 <= a.xnu_pperm_guest_window_limit <= 4096:
        ap.error('--xnu-pperm-guest-window-limit must be 1..4096')
    if a.xnu_pperm_guest_window_limit != 1 and not a.xnu_pperm_guest_window:
        ap.error('--xnu-pperm-guest-window-limit requires --xnu-pperm-guest-window')
    if a.handoff_breakpoint_offset is not None:
        ap.error('--handoff-breakpoint-offset is unsafe in real guarded execution: its HVC routes to SPTM, not EL2')
    parameters = {k: str(v) if isinstance(v, Path) else v for k, v in vars(a).items()}
    capture = RunCapture(a.run_dir or a.report.parent/(a.report.name+'.runs'), a.report,
                         parameters, repo=Path(__file__).resolve().parents[2], checkout=a.checkout)
    report = {'scope': 'bounded-sptm-entry', 'guest_boot_verified': False,
              'hardware_executed': False, 'steps_limit': a.steps, 'trace': [], 'run_id': capture.run_id, 'trace_window': a.trace_window}
    error = None
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Received signal '+str(signum))
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        capture.save(report)
        run_probe(a, report, lambda: capture.save(report), capture)
    except BaseException as caught:
        error = caught
        raise
    finally:
        signal.signal(signal.SIGTERM, previous)
        try:
            capture.finish(report, error)
        except Exception as save_error:
            print('Attempt finalization failed:', save_error, file=sys.stderr)
            if error is None:
                raise
        print('Attempt bundle:', capture.root, file=sys.stderr)
