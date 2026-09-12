#!/usr/bin/env python3
"""Replay debug traps through the real probe callback and an in-memory transport.

This does not execute guest instructions or emulate a CPU, TLB, USB, or an M3.
It compiles the callback and encoding AST: main() and hardware setup/cleanup
are never executed. Tests can supply synthetic RAM and guest register banks.
"""
import argparse
import ast
from run_manifest import trace_count, append_event
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from guest_debug import GuestDebugState, MDSCR_EL1, OSLAR_EL1, UnsupportedGuestDebug
from guest_pt import PAGE, validate_monitor_entry, validate_root_switch, translate
from sprr_permissions import leaf_permissions
from zero_loop import recognize as recognize_zero_loop

REPO = Path(__file__).resolve().parents[1]
DEFAULT_TRACE = REPO / 'artifacts/evidence/2026-09-09/mmu-sptm/sptm-entry-timer.json.gz'


class ForbiddenHardware:
    def __init__(self):
        self.attempts = []

    def __getattr__(self, name):
        self.attempts.append(name)
        raise AssertionError('Unexpected hardware access: ' + name)


class GuestMemory:
    """Sparse, bounded synthetic RAM; uninitialized reads are errors, not zeroes."""
    def __init__(self, base, size):
        self.base, self.size = base, size
        self.pages = {}
        self.reads = []

    def check(self, address, size):
        if not 0 < size or not self.base <= address < address+size <= self.base+self.size:
            raise ValueError('Fake memory access outside guest allocation')

    def add_page(self, address, data=None):
        self.check(address, PAGE)
        if address % PAGE or (data is not None and len(data) != PAGE):
            raise ValueError('Invalid fake memory page')
        self.pages[address] = bytearray(PAGE if data is None else data)

    def read(self, address, size):
        self.check(address, size)
        self.reads.append((address, size))
        data = bytearray()
        while size:
            page, offset = address & -PAGE, address % PAGE
            count = min(size, PAGE-offset)
            if page not in self.pages:
                raise ValueError('Uninitialized fake guest page')
            data.extend(self.pages[page][offset:offset+count])
            address, size = address+count, size-count
        return bytes(data)

    def write(self, address, data):
        self.check(address, len(data))
        while data:
            page, offset = address & -PAGE, address % PAGE
            count = min(len(data), PAGE-offset)
            if page not in self.pages:
                raise ValueError('Uninitialized fake guest page')
            self.pages[page][offset:offset+count] = data[:count]
            address, data = address+count, data[count:]


class GuestRegisters(ForbiddenHardware):
    """Whitelisted guest EL12 banks and recorded barriers; no CPU execution."""
    def __init__(self, allowed):
        super().__init__()
        self.values = dict.fromkeys(allowed, 0)
        self.calls = []

    def mrs(self, register):
        if register not in self.values:
            return self.__getattr__('mrs '+str(register))
        self.calls.append(('mrs', register))
        return self.values[register]

    def msr(self, register, value):
        if register not in self.values:
            return self.__getattr__('msr '+str(register))
        self.calls.append(('msr', register, value))
        self.values[register] = value

    def exec(self, code):
        if code not in ('isb', 'dsb ishst', 'dsb ishst; tlbi vmalle1is; dsb ish; isb',
                        'isb; dsb ishst; tlbi vmalle1is; dsb ish; isb',
                        'dsb ishst; tlbi vmalls12e1is; dsb ish; isb'):
            return self.__getattr__('exec '+code)
        self.calls.append(('barrier', code))


class CallbackReplay:
    """A virtual exception endpoint using the pinned, real ExcInfo wire format."""
    INFO = 0x1000

    def __init__(self, checkout, steps=4096, *, memory=None, entered=True,
                 allow_monitor_mmu=False, allow_live_ttbr=False, observe_sprr=False,
                 virtual_gxf=False, stage_el2_config=False, real_guarded=False,
                 real_guarded_vbar=False, entry=None, args_off=0):
        proxy_path = str(Path(checkout).resolve() / 'proxyclient')
        # Only pure definitions/serializers are imported; never instantiate UartInterface.
        sys.path.insert(0, proxy_path)
        try:
            from m1n1.proxy import START, EXC, EXC_RET, ExcInfo
            from m1n1 import sysreg
            from m1n1.hv import HV
            spec = importlib.util.spec_from_file_location('m1n1.hv.vel2', Path(proxy_path)/'m1n1/hv/vel2.py')
            vel2 = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(vel2)
        finally:
            sys.path.remove(proxy_path)
        self.codec = ExcInfo
        self.START, self.EXC, self.EXC_RET = START, EXC, EXC_RET
        self.sysreg = sysreg
        self.memory = memory
        self.debug = GuestDebugState()
        self.hardware = ForbiddenHardware() if memory is None else GuestRegisters([
            sysreg.TCR_EL12, sysreg.TTBR0_EL12, sysreg.TTBR1_EL12,
            sysreg.MAIR_EL12, sysreg.SCTLR_EL12, sysreg.VBAR_EL12,
            sysreg.VBAR_GL12,
            sysreg.AGTCNTRDIR_EL12,
            sysreg.CNTP_CTL_EL02,
            (3, 4, 15, 4, 3),
            sysreg.MDSCR_EL1,
            sysreg.ESR_EL12, sysreg.ELR_EL12, sysreg.FAR_EL12, sysreg.SPSR_EL12, sysreg.AFSR1_EL12])
        self.report = {'trace': [], 'guest_debug': self.debug.snapshot()}
        self.replies = []
        self.operations = []
        self.saved = []
        self.inputs = {}
        self.wire = None
        self.fail_write = False
        self.fail_save = False
        tree = ast.parse((REPO / 'scripts/sptm_entry_probe.py').read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_probe')
        callback = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == 'stopped')
        dockchannel_match = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                                 and n.name == 'match_xnu_dockchannel_uart')
        panic_match = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                           and n.name == 'match_xnu_panic_carveout')
        socd_match = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                          and n.name == 'match_xnu_socd_trace')
        guard = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == 'pause_guard')
        gxf_report = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == 'gxf_report')
        # Preserve the callback intact, including nonlocals, catches, and finally.
        factory = ast.parse('def bind(entered, shadow_hcr, shadow_sctlr, shadow_sprr_config, real_sprr_on, guarded_vbar, monitor_mmu_validated):\n    pass').body[0]
        factory.body = [dockchannel_match, panic_match, socd_match, gxf_report, guard, callback,
                        ast.Return(value=ast.Name(id='stopped', ctx=ast.Load()))]
        namespace = dict(vars(sysreg), batch=None, trace_count=trace_count, append_event=append_event, START=START, EXC=EXC, EXC_RET=EXC_RET, ExcInfo=ExcInfo,
                         UnsupportedGuestDebug=UnsupportedGuestDebug, HV=HV,
                         PpermWindowLimit=type('PpermWindowLimit',(Exception,),{}),
                         guest_debug=self.debug, report=self.report, iface=self,
                         p=SimpleNamespace(exit=self.exit, dc_cvau=self.cache_op, ic_ivau=self.cache_op,
                             hv_translate=lambda va, *_: va,
                             hv_map=lambda ipa, pte, size, flags:
                                 self.operations.append(('hv_map', ipa, pte, size, flags)) or 0),
                         u=self.hardware, PAGE=PAGE, translate=translate, leaf_permissions=leaf_permissions, validate_monitor_entry=validate_monitor_entry,
                         validate_root_switch=validate_root_switch,
                         capture=SimpleNamespace(save_input=lambda name, data: self.inputs.__setitem__(name, data)),
                         recognize_zero_loop=recognize_zero_loop,
                         a=SimpleNamespace(steps=steps, allow_monitor_mmu=allow_monitor_mmu, allow_live_ttbr=allow_live_ttbr,
                                           emulate_zero_loops=False, stop_on_vector_entry=False, pause_on_guard=False,
                                           observe_sprr=observe_sprr, virtual_gxf=virtual_gxf, stage_el2_config=stage_el2_config,
                                           single_step_after=0, real_guarded=real_guarded, handoff_steps=0,
                                           handoff_breakpoint_offset=None, free_run=False,
                                           real_guarded_vbar=real_guarded_vbar, native_handoff=False, xnu_steps=0, xnu_run=False,
                                           xnu_m3_nop_ahcr_compat=False,
                                           xnu_dockchannel_uart_mmio=False,
                                           xnu_private_panic_carveout=False,
                                           xnu_private_socd_trace=False,
                                           xnu_pperm_guest_window=False,
                                           xnu_pperm_guest_window_limit=1,
                                           xnu_apple_physical_timer_hypothesis=False,
                                           xnu_tpidr_gl2_fast_shadow=False,
                                           xnu_txm_context_entry_one_step=False,
                                           xnu_txm_context_entry_register_prefix=False,
                                           xnu_txm_context_stack_claim_one_step=False,
                                           xnu_txm_context_stack_metadata_init=False,
                                           xnu_txm_context_x18_branch_one_step=False,
                                           xnu_txm_context_outbound_branch_one_step=False,
                                           xnu_txm_handler_boundary=None,
                                           xnu_phase53_retype_survey=False,
                                           xnu_phase53_retype_survey_limit=64,
                                           on_demand_stage2=0,
                                           single_step_window=None, stop_on_guarded_vector=False,
                                           first_contact=False, guarded_call_selectors=None), save=self.save,
                         # Tests inject a detector or pause channel by name; both default to disabled.
                         vector_stop=None, guarded_vector_stop=None, ss_window=None, guard_pause=None,
                         watchdog=None, handoff_state=dict(active=False, events=0),
                         txm_context_step_state=dict(active=False),
                         txm_validator_trace_state=dict(active=False),
                         phase53_allocation_trace_state=dict(active=False),
                         phase53_retype_survey_state=dict(active=False),
                         dockchannel_mmio=None,
                         panic_carveout=None,
                         socd_trace=None,
                         xnu_agt_state=dict(previous=None, writes=0), layout={}, sources={},
                         xnu_cntp_ctl_state=dict(previous=None, writes=0),
                         xnu_apple_timer_state=dict(previous=None, writes=0),
                         xnu_pperm_state=dict(previous=None, step=0, modified=False,
                                                started=0, completed=0),
                         multi_call_selectors=None, gc_state={'index': 0, 'in_call': False, 'started': 0},
                         exception_registers={'ESR_EL12': sysreg.ESR_EL12, 'ELR_EL12': sysreg.ELR_EL12,
                                              'FAR_EL12': sysreg.FAR_EL12, 'SPSR_EL12': sysreg.SPSR_EL12, 'VBAR_EL12': sysreg.VBAR_EL12},
                         base=memory.base if memory else 0, guest_size=memory.size if memory else 0,
                         entry=entry, args_off=args_off, blob=b'', original=b'\x1f\x20\x03\xd5',
                         REGISTERS=vel2.REGISTERS, patch_synthetic_code=vel2.patch_synthetic_code)
        # Use the probe's actual register ordering and instruction rewrite, too.
        import struct
        namespace['struct'] = struct
        namespace['hashlib'] = __import__('hashlib')
        # Module-level register lists and the probe's own shadow/rewrite tables: one source of truth.
        assignments = [n for n in tree.body if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and (t.id in ('SPRR_PERMISSION_REGISTERS', 'APPLE_OBSERVED_REGISTERS', 'TXM_WORLD_RETURN_LINKED') or t.id.startswith('FC_')) for t in n.targets)]
        assignments += [n for n in main.body if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id in ('translation_banks', 'apple_cntvoff', 'permission_shadow', 'apple_shadow', 'extra_regs', 'real_native', 'real_redirect', 'gxf_banks', 'gxf_state', 'el2_shadow') for t in n.targets)]
        assignments += [n for n in main.body if isinstance(n, ast.If)
                        and any(isinstance(node, ast.Attribute) and node.attr == 'real_guarded_vbar'
                                for node in ast.walk(n))]
        rewrite = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == 'patch_probe_code')
        # Its local relative import needs the already loaded module, without HV.__init__.
        sys.modules.setdefault('m1n1.hv.vel2', vel2)
        exec(compile(ast.Module(body=assignments+[rewrite], type_ignores=[]),
                     str(REPO/'scripts/sptm_entry_probe.py'), 'exec'), namespace)
        namespace['tpidr_gl2_register'] = sysreg.sysreg_fwd['TPIDR_GL2']
        namespace['tpidr_gl2_shadow_tag_base'] = (
            0x8000 | (namespace['extra_regs'].index(
                namespace['tpidr_gl2_register']) << 6))
        namespace['tpidr_gl2_fast_shadow'] = None
        self.namespace = namespace
        exec(compile(ast.fix_missing_locations(ast.Module(body=[factory], type_ignores=[])),
                     str(REPO / 'scripts/sptm_entry_probe.py'), 'exec'), namespace)
        self.callback = namespace['bind'](entered, 0, 0, 0, False, 0, False)

    def cache_op(self, address, size):
        self.memory.check(address, size)
        self.operations.append('cache-maintenance')

    def readmem(self, address, size):
        if self.memory is None:
            raise AssertionError('No synthetic guest RAM configured')
        return self.memory.read(address, size)

    def readstruct(self, address, codec):
        if address != self.INFO or codec is not self.codec:
            raise AssertionError('Unexpected context read')
        self.operations.append('read-context')
        return codec.parse(self.wire)

    def writemem(self, address, data):
        if address != self.INFO:
            if self.memory is None:
                raise AssertionError('Unexpected memory write')
            self.memory.write(address, data)
            self.operations.append('write-guest-memory')
            return
        self.operations.append('write-context')
        if self.fail_write:
            raise OSError('injected context write failure')
        self.codec.parse(data)
        self.wire = data

    def save(self):
        if self.fail_save:
            raise OSError('injected report save failure')
        self.saved.append(json.loads(json.dumps(self.report)))
        self.operations.append('save-report')

    def exit(self, reply):
        self.replies.append(int(reply))
        self.operations.append('exit-reply')

    def feed(self, event):
        # Recorded reports omit some wire fields. Leave these unused fields zero;
        # do not synthesize missing instruction or hardware execution history.
        ctx = self.codec.parse(bytes(self.codec.sizeof()))
        ctx.regs = list(event['regs'])
        ctx.elr = event['pc']
        ctx.esr = type(ctx.esr)(event['esr'])
        ctx.spsr = type(ctx.spsr)(event['spsr'])
        ctx.far, ctx.sp = event.get('far', 0), list(event.get('sp', [0, 0, 0]))
        self.wire = self.codec.build(ctx)
        before = self.codec.parse(self.wire)
        count = len(self.replies)
        self.callback(event['reason'], event['code'], self.INFO)
        if len(self.replies) != count + 1:
            raise AssertionError('Expected exactly one reply per guest exit')
        return before, self.codec.parse(self.wire)


def replay_trace(path, checkout):
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if path.resolve() == DEFAULT_TRACE.resolve():
        manifest = json.loads((REPO / 'artifacts/evidence/2026-09-09/sha256.json').read_text())
        if digest != manifest['mmu-sptm/sptm-entry-timer.json.gz']:
            raise ValueError('Retained trace checksum mismatch')
    source = json.loads(gzip.decompress(raw) if path.suffix == '.gz' else raw)
    endpoint = CallbackReplay(checkout)
    results = []
    for index, event in enumerate(source['trace']):
        # Decode selection from the raw ESR, not the report's interpreted name.
        esr = event.get('esr', 0)
        reg = ((esr >> 20) & 3, (esr >> 14) & 7, (esr >> 10) & 15,
               (esr >> 1) & 15, (esr >> 17) & 7)
        if event['reason'] != int(endpoint.START.EXCEPTION_LOWER) or esr >> 26 != 0x18 or reg not in (MDSCR_EL1, OSLAR_EL1):
            continue
        before, after = endpoint.feed(event)
        rt = (esr >> 5) & 31
        results.append(dict(trace_index=index, encoding=list(reg), rt=rt,
                            pc_before=before.elr, pc_after=after.elr,
                            rt_before=before.regs[rt], rt_after=after.regs[rt],
                            reply=endpoint.replies[-1], event=endpoint.report['trace'][-1]))
        if endpoint.replies[-1] != int(endpoint.EXC_RET.HANDLED):
            break
    return dict(scope='debug-trap-callback-replay', hardware_executed=False,
                guest_boot_verified=False, instruction_execution_emulated=False,
                source_sha256=digest, source_events=len(source['trace']),
                replayed_debug_traps=len(results), unreplayed_events=len(source['trace'])-len(results),
                results=results, guest_debug=endpoint.debug.snapshot(),
                hardware_access_attempts=endpoint.hardware.attempts,
                stop_reason=endpoint.report.get('stop_reason'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, default=DEFAULT_TRACE)
    parser.add_argument('--checkout', type=Path, default=os.environ.get('VEL2_CHECKOUT'))
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.checkout is None:
        parser.error('Activate the workspace or specify --checkout')
    result = replay_trace(args.trace, args.checkout)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(f"Replayed {result['replayed_debug_traps']} debug traps; "
          f"{result['unreplayed_events']} other events not replayed; no target accessed.")
    if not result['results'] or result['stop_reason'] or result['hardware_access_attempts']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
