#!/usr/bin/env python3
"""Exercise native batching with 64 known additions; hardware requires --execute."""
import argparse
import os
from pathlib import Path
import sys
from run_manifest import atomic_json, append_event, utc
from step_batch import StepBatch, RECORD
from vel2_smoke import verify_image

SOURCE = '''
    mov sp, x1
    mov x0, #0
    hvc #0x7ffe
first_add:
    .rept 64
    add x0, x0, #1
    .endr
finished:
    hvc #0x7fff
    b .
'''


def validate(report, first_add, finished):
    steps = [e for e in report['trace'] if e.get('kind') == 'instruction-step']
    terminal = report['trace'][-1] if report['trace'] else {}
    return dict(step_count=len(steps) == 64,
        step_pcs=[e['pc'] for e in steps] == list(range(first_add+4, finished+4, 4)),
        step_values=[e['regs'][0] for e in steps] == list(range(1, 65)),
        terminal_hvc=terminal.get('esr') == 0x5a007fff,
        terminal_value=terminal.get('regs', [None])[0] == 64,
        native_capture=report.get('native_batched_events', 0) > 0 if report['capacity'] else True,
        clean_return=report.get('proxy_alive_after_exit') is True and not report.get('error') and not report.get('cleanup_error'))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--checkout', type=Path, default=os.environ.get('VEL2_CHECKOUT'))
    ap.add_argument('--device')
    ap.add_argument('--capacity', type=int, default=8)
    ap.add_argument('--execute', action='store_true')
    ap.add_argument('--report', type=Path, required=True)
    ap.add_argument('--fresh-gate-nonce', help='Host gate nonce copied into the report')
    a = ap.parse_args()
    if a.checkout is None or not 0 <= a.capacity <= 256 or (a.execute and not a.device):
        ap.error('A checkout, capacity 0..256, and an explicit device for execution are required')
    sys.path.insert(0, str(a.checkout.resolve()/'proxyclient'))
    from m1n1.asm import ARMAsm
    compiled = ARMAsm(SOURCE, 0x100000)
    report = dict(scope='synthetic-native-step-batch', capacity=a.capacity,
                  hardware_executed=False, passed=False, trace=[], synthetic_bytes=len(compiled.data),
                  started_at=utc(), ended_at=None)
    if a.fresh_gate_nonce:
        report['fresh_gate_nonce'] = a.fresh_gate_nonce
    atomic_json(a.report, report)
    if not a.execute:
        report['ended_at'] = utc()
        atomic_json(a.report, report)
        print('Synthetic batching test compiled; no target accessed.')
        return
    from m1n1.proxy import UartInterface, M1N1Proxy, START, EXC, EXC_RET, ExcInfo, IODEV
    from m1n1.proxyutils import ProxyUtils
    from m1n1.sysreg import SCTLR_EL12, MDCR_EL2, MDSCR_EL1
    from m1n1.hv import HV
    from m1n1.hv.types import HV_EVENT
    iface = UartInterface(a.device)
    batch = None
    active = False
    try:
        iface.nop()
        p = M1N1Proxy(iface)
        p.nop()
        report['image_sections'] = verify_image(iface, p.get_base(), a.checkout/'build/m1n1-raw.elf')
        u = ProxyUtils(p)
        region = u.memalign(0x4000, 0x8000)
        compiled = ARMAsm(SOURCE, region)
        iface.writemem(region, compiled.data)
        if iface.readmem(region, len(compiled.data)) != compiled.data:
            raise ValueError('Synthetic code readback mismatch')
        p.dc_cvau(region, len(compiled.data)); p.ic_ivau(region, len(compiled.data))
        if a.capacity:
            batch = StepBatch(p, iface, u.memalign(16, a.capacity*RECORD.size), a.capacity)
        current = p.iodev_whoami()
        for dev in IODEV:
            if dev >= IODEV.USB0 and dev != current:
                p.iodev_set_usage(dev, 0)
        p.hv_init()
        u.msr(SCTLR_EL12, 0x30d00800)
        u.msr(MDCR_EL2, u.mrs(MDCR_EL2) | (1 << 8))
        u.msr(MDSCR_EL1, 0)
        if p.hv_map(region, region | HV.PTE_ATTRIBUTES | HV.PTE_VALID, 0x8000, 1) < 0:
            raise ValueError('Synthetic guest map failed')
        entered = False
        def stopped(reason, code, info):
            nonlocal entered
            ret = EXC_RET.EXIT_GUEST
            try:
                if batch:
                    batch.drain(report)
                if reason != START.EXCEPTION_LOWER or code != EXC.SYNC:
                    raise ValueError('Unexpected synthetic exception')
                ctx = iface.readstruct(info, ExcInfo)
                event = dict(reason=int(reason), code=int(code), pc=ctx.elr,
                    esr=int(ctx.esr), far=ctx.far, spsr=int(ctx.spsr), regs=list(ctx.regs), sp=list(ctx.sp))
                if not entered and event['esr'] == 0x5a007ffe and ctx.elr == compiled.first_add:
                    entered = True
                    event['kind'] = 'entry-guard'
                    u.msr(MDSCR_EL1, 1)
                    ret = EXC_RET.HANDLED
                elif entered and event['esr'] >> 26 == 0x32:
                    event['kind'] = 'instruction-step'
                    if len(report['trace']) >= 70:
                        raise ValueError('Synthetic event budget exceeded')
                    ret = EXC_RET.HANDLED
                elif entered and event['esr'] == 0x5a007fff:
                    event['kind'] = 'terminal-hvc'
                else:
                    raise ValueError('Unexpected synthetic stop')
                append_event(report, event)
                if ret == EXC_RET.HANDLED:
                    ctx.spsr.SS = 1
                    iface.writemem(info, ExcInfo.build(ctx))
                    if batch:
                        batch.arm(report, 70)
            except Exception as error:
                report['error'] = str(error)
                ret = EXC_RET.EXIT_GUEST
            finally:
                p.exit(ret)
        for reason in (START.EXCEPTION, START.EXCEPTION_LOWER):
            for code in EXC:
                iface.set_handler(reason, code, stopped)
        for code in HV_EVENT:
            iface.set_handler(START.HV, code, stopped)
        p.hv_vel2_set_active(True)
        active = True
        report.update(hardware_executed=True, region=region)
        atomic_json(a.report, report)
        p.hv_start(region, 0, region+0x8000, 0, 0)
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        if active:
            try:
                if batch:
                    batch.disable()
                p.hv_vel2_set_active(False)
                u.msr(MDSCR_EL1, 0)
                p.nop()
                report['proxy_alive_after_exit'] = True
            except Exception as error:
                report['cleanup_error'] = str(error)
        report['checks'] = validate(report, compiled.first_add, compiled.finished)
        report['passed'] = all(report['checks'].values())
        report['ended_at'] = utc()
        atomic_json(a.report, report)
        iface.dev.close()
    if not report['passed']:
        raise SystemExit('Synthetic batching check failed; inspect report')
    print('PASS: 64 additions captured in order and clean proxy return')


if __name__ == '__main__':
    main()
