#!/usr/bin/env python3
"""RAM-only native busy-loop; prove the timer kick exits with a live proxy."""
import argparse
from pathlib import Path
import os
import sys
from free_run_watchdog import FreeRunWatchdog
from run_manifest import atomic_json
from vel2_smoke import verify_image


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--checkout', type=Path, default=os.environ.get('VEL2_CHECKOUT'))
    ap.add_argument('--device', required=True)
    ap.add_argument('--report', type=Path, required=True)
    ap.add_argument('--execute', action='store_true')
    a = ap.parse_args()
    if not a.execute:
        print('Dry run: native b . loop, 2s watchdog, 15s grace; no target accessed')
        return
    sys.path.insert(0, str(a.checkout.resolve()/'proxyclient'))
    from m1n1.proxy import UartInterface, M1N1Proxy, START, EXC, EXC_RET, ExcInfo, IODEV
    from m1n1.proxyutils import ProxyUtils
    from m1n1.hv import HV
    from m1n1.hv.types import HV_EVENT
    from m1n1.sysreg import SCTLR_EL12, MDSCR_EL1, HCR_EL2
    report = dict(scope='free-run-native-busy-loop', passed=False)
    iface = UartInterface(a.device)
    returned = False
    watchdog = FreeRunWatchdog(iface, 2)
    try:
        iface.nop()
        p = M1N1Proxy(iface)
        p.nop()
        report['image_sections'] = verify_image(iface, p.get_base(), a.checkout/'build/m1n1-raw.elf')
        u = ProxyUtils(p)
        region = u.memalign(0x4000, 0x4000)
        iface.writemem(region, bytes.fromhex('00000014'))  # b .; no traps or WFE
        p.dc_cvau(region, 4)
        p.ic_ivau(region, 4)
        current = p.iodev_whoami()
        for dev in IODEV:
            if dev >= IODEV.USB0 and dev != current:
                p.iodev_set_usage(dev, 0)
        p.hv_init()
        u.msr(SCTLR_EL12, 0x30d00800)
        u.msr(MDSCR_EL1, 0)
        if p.hv_map(region, region | HV.PTE_ATTRIBUTES | HV.PTE_VALID, 0x4000, 1) < 0:
            raise RuntimeError('Synthetic guest map failed')
        def stopped(reason, code, info):
            try:
                ctx = iface.readstruct(info, ExcInfo)
                report['stop'] = dict(reason=int(reason), code=int(code), pc=ctx.elr)
            finally:
                p.exit(EXC_RET.EXIT_GUEST)
        for reason in (START.EXCEPTION, START.EXCEPTION_LOWER):
            for code in EXC:
                iface.set_handler(reason, code, stopped)
        for code in HV_EVENT:
            iface.set_handler(START.HV, code, stopped)
        p.hv_vel2_set_active(True)
        hcr = u.mrs(HCR_EL2)
        p.hv_write_hcr(hcr | (1 << 3))  # FMO routes physical timer FIQ to EL2
        report['hcr'] = hex(u.mrs(HCR_EL2))
        atomic_json(a.report, report)
        watchdog.run(lambda: p.hv_start(region, 0, 0, 0, 0))
        returned = True
        report['passed'] = (report.get('stop') == dict(reason=int(START.HV),
                             code=int(HV_EVENT.USER_INTERRUPT), pc=region) and watchdog.kicked)
    finally:
        report['watchdog'] = watchdog.status()
        if returned:
            p.hv_vel2_set_active(False)
            p.nop()
            report['proxy_alive_after_exit'] = True
        else:
            report['cleanup_skipped'] = 'hv_start did not return'
        atomic_json(a.report, report)
        iface.dev.close()
    if not report['passed']:
        raise SystemExit('Watchdog smoke failed')
    print('PASS: native busy-loop interrupted by EL2 timer; clean return and proxy NOP')


if __name__ == '__main__':
    main()
