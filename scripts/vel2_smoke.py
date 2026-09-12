#!/usr/bin/env python3
"""Compile a synthetic vEL2 smoke test; --execute explicitly enables RAM-only target work."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from run_manifest import utc

SOURCE = '''
    mov sp, x1
    mrs x10, CurrentEL
    mov x4, #0x1234
    msr TPIDR_EL2, x4
    mrs x11, TPIDR_EL2
    adr x4, vectors
    msr VBAR_EL2, x4
    msr SP_EL1, x2
    adr x4, lower
    msr ELR_EL2, x4
    mov x4, #0x3c5
    msr SPSR_EL2, x4
    eret
lower:
    mrs x12, CurrentEL
    mov x18, sp
    hvc #0x12
after_hvc:
    mrs x19, CurrentEL
    mov x20, #1
    hvc #0x7fff
    b .
    .balign 2048
vectors:
    .space 1024
handler:
    mrs x13, CurrentEL
    mrs x14, ESR_EL2
    mrs x15, ELR_EL2
    mrs x16, SPSR_EL2
    mov x17, sp
    eret
'''


def verify_image(iface, base, path):
    """Compare immutable raw-ELF sections, applying only AArch64 RELATIVE relocations."""
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected little-endian ELF64')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, strindex = struct.unpack_from('<HHH', data, 58)
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * entsize) for i in range(count)]
    strings = headers[strindex]
    names = data[strings[4]:strings[4] + strings[5]]
    sections = {names[h[0]:].split(b'\0', 1)[0].decode(): h for h in headers}
    rel = sections['.rela.dyn']
    rel_data = data[rel[4]:rel[4]+rel[5]]
    used = len(rel_data) // 24 * 24
    if any(rel_data[used:]):
        raise ValueError('Nonzero relocation padding')
    relocations = list(struct.iter_unpack('<QQq', rel_data[:used]))
    report = {}
    for name in ('.init', '.text', '.rodata'):
        h = sections[name]
        expected = bytearray(data[h[4]:h[4]+h[5]])
        for offset, info, addend in relocations:
            if h[3] <= offset < h[3] + h[5] and info:
                if info != 1027:
                    raise ValueError('Unsupported relocation')
                struct.pack_into('<Q', expected, offset-h[3], base+addend)
        actual = iface.readmem(base+h[3], h[5])
        report[name] = actual == expected
    if not all(report.values()):
        raise RuntimeError('Running image differs from experimental raw ELF: ' + str(report))
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--checkout', type=Path, default=os.environ.get('VEL2_CHECKOUT'))
    ap.add_argument('--device')
    ap.add_argument('--case', choices=('transition', 'reject-mmu', 'mmu-alias', 'mmu-vhe'), default='transition')
    ap.add_argument('--execute', action='store_true')
    ap.add_argument('--report', type=Path, required=True)
    ap.add_argument('--fresh-gate-nonce', help='Host gate nonce copied into the report')
    a = ap.parse_args()
    if a.checkout is None:
        ap.error('Set VEL2_CHECKOUT or --checkout')
    sys.path.insert(0, str(a.checkout.resolve() / 'proxyclient'))
    from m1n1.asm import ARMAsm
    from m1n1.hv.vel2 import patch_synthetic_code
    # Compile before opening any device. Default invocation is strictly offline.
    source = SOURCE if a.case == 'transition' else '''
    mov sp, x1
    mov x20, #0
    mrs x10, CurrentEL
    mov x4, #1
    msr SCTLR_EL2, x4
rejected:
    mov x20, #1
    hvc #0x7fff
'''
    if a.case in ('mmu-alias', 'mmu-vhe'):
        source = '''
    mov sp, x1
    mov x20, #0
    mrs x10, CurrentEL
    mov x4, #0xff
    msr MAIR_EL2, x4
    mov x4, #0xb516
    movk x4, #0x8083, lsl #16
    msr TCR_EL2, x4
    msr TTBR0_EL2, x0
    mov x4, #1
    msr SCTLR_EL2, x4
    isb
    ldr x11, [x2]
    mrs x13, SCTLR_EL2
    msr SCTLR_EL2, xzr
    isb
    mrs x12, SCTLR_EL2
    mov x20, #1
    hvc #0x7fff
'''
    if a.case == 'mmu-vhe':
        source = source.replace('    mov x4, #0xb516', '    mov x4, #0x08000000\n    movk x4, #4, lsl #32\n    msr HCR_EL2, x4\n    mov x4, #0xb516').replace('movk x4, #0x8083, lsl #16', 'movk x4, #0x4096, lsl #16\n    movk x4, #3, lsl #32')
    compiled = ARMAsm(source, 0x100000)
    patched = patch_synthetic_code(compiled.data)
    report = {'case': a.case, 'hardware_executed': False, 'passed': False,
              'synthetic_bytes': len(patched),
              'patched_sha256': hashlib.sha256(patched).hexdigest(),
              'started_at': utc(), 'ended_at': None}
    if a.fresh_gate_nonce:
        report['fresh_gate_nonce'] = a.fresh_gate_nonce
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2)+'\n')
    if not a.execute:
        report['ended_at'] = utc()
        a.report.write_text(json.dumps(report, indent=2)+'\n')
        print('Compiled synthetic smoke test; no target accessed.')
        return
    if not a.device:
        ap.error('--execute requires an explicit --device')
    from m1n1.proxy import UartInterface, M1N1Proxy, START, EXC, EXC_RET, ExcInfo, IODEV
    from m1n1.proxyutils import ProxyUtils
    from m1n1.sysreg import SCTLR_EL12
    from m1n1.hv import HV
    from m1n1.hv.types import HV_EVENT
    iface = UartInterface(a.device)
    p = M1N1Proxy(iface)
    iface.nop()
    p.nop()
    report['image_sections'] = verify_image(iface, p.get_base(), a.checkout / 'build/m1n1-raw.elf')
    u = ProxyUtils(p)
    region_size = 0x20000 if a.case in ('mmu-alias', 'mmu-vhe') else 0xc000
    region = u.memalign(0x4000, region_size)
    args = (0, region+0x8000, region+0xc000, 0)
    compiled = ARMAsm(source, region)
    patched = patch_synthetic_code(compiled.data)
    if len(patched) > 0x4000:
        raise RuntimeError('Code exceeds mapped page')
    iface.writemem(region, patched)
    if iface.readmem(region, len(patched)) != patched:
        raise RuntimeError('Payload readback mismatch')
    p.dc_cvau(region, len(patched))
    p.ic_ivau(region, len(patched))
    if a.case in ('mmu-alias', 'mmu-vhe'):
        # Three-level 16K tables: identity code block plus a single aliased data page.
        if region >> 25 != (region+region_size-1) >> 25:
            raise RuntimeError('Allocation crosses identity block boundary')
        root, code_l2, alias_l2, alias_l3 = [region+i for i in (0xc000, 0x10000, 0x14000, 0x18000)]
        alias = 0x40000000
        tables = bytearray(0x10000)
        def entry(table, index, descriptor):
            struct.pack_into('<Q', tables, table-root+index*8, descriptor)
        entry(root, (region >> 36) & 0x3f, code_l2 | 3)
        entry(code_l2, (region >> 25) & 0x7ff, (region & ~0x1ffffff) | 0x701)
        entry(root, 0, alias_l2 | 3)
        entry(alias_l2, (alias >> 25) & 0x7ff, alias_l3 | 3)
        entry(alias_l3, 0, (region+0x4000) | 0x703)
        iface.writemem(root, tables)
        iface.writemem(region+0x4000, struct.pack('<Q', 0x1122334455667788))
        p.dc_cvau(region, region_size)
        args = (root, region+0x8000, alias, 0)
    current = p.iodev_whoami()
    for dev in IODEV:
        if dev >= IODEV.USB0 and dev != current:
            p.iodev_set_usage(dev, 0)
    p.hv_init()
    # Guest stage 1 off, little endian, required architectural RES1 bits set.
    # Host translation is untouched. Stage 2 maps only the allocated three pages.
    u.msr(SCTLR_EL12, 0x30d00800)
    if p.hv_map(region, region | HV.PTE_ATTRIBUTES | HV.PTE_VALID, region_size, 1) < 0:
        raise RuntimeError('Stage-2 map failed')
    events = []
    def stopped(reason, code, info):
        event = {'reason': int(reason), 'code': int(code), 'info': info}
        events.append(event)
        try:
            if reason in (START.EXCEPTION, START.EXCEPTION_LOWER):
                ctx = iface.readstruct(info, ExcInfo)
                event.update(esr=int(ctx.esr), pc=ctx.elr, regs=list(ctx.regs), sp=list(ctx.sp))
        finally:
            p.exit(EXC_RET.EXIT_GUEST)
    for reason in (START.EXCEPTION, START.EXCEPTION_LOWER):
        for code in EXC:
            iface.set_handler(reason, code, stopped)
    for code in HV_EVENT:
        iface.set_handler(START.HV, code, stopped)
    p.hv_vel2_set_active(True)
    report.update(hardware_executed=True, region=region)
    a.report.write_text(json.dumps(report, indent=2)+'\n')
    try:
        p.hv_start(region, *args)
        p.hv_vel2_set_active(False)
        p.nop()
        report['proxy_alive_after_exit'] = True
        report['events'] = events
        if len(events) != 1:
            raise RuntimeError('Expected exactly one stop event')
        event = events[0]
        expected = {10: 8, 11: 0x1234, 12: 4, 13: 8, 14: 0x5a000012,
                    15: getattr(compiled, "after_hvc", 0), 16: 0x3c5, 17: region+0x8000,
                    18: region+0xc000, 19: 4, 20: 1}
        if a.case == 'reject-mmu':
            expected = {10: 8, 20: 0}
        if a.case in ('mmu-alias', 'mmu-vhe'):
            expected = {10: 8, 11: 0x1122334455667788, 12: 0, 13: 1, 20: 1}
        checks = {f'x{k}': event.get('regs', [None]*32)[k] == v for k, v in expected.items()}
        checks['stop'] = event['reason'] == int(START.EXCEPTION_LOWER) and event['code'] == int(EXC.SYNC) and event.get('esr') == (0x5a004044 if a.case == 'reject-mmu' else 0x5a007fff)
        if a.case == 'reject-mmu':
            checks['stopped_at_request'] = event.get('pc') == compiled.rejected
            checks['guest_translation_still_off'] = not (u.mrs(SCTLR_EL12) & 1)
        report['checks'] = checks
        report['passed'] = all(checks.values())
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        report['events'] = events
        report['ended_at'] = utc()
        a.report.write_text(json.dumps(report, indent=2)+'\n')
        iface.dev.close()
    if not report['passed']:
        raise SystemExit('Smoke test failed; inspect report before another run.')
    print('PASS:', a.case, 'and clean proxy return')

if __name__ == '__main__':
    main()
