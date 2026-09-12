#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See ../LICENSES/Asahi-m1n1-MIT.txt and ../THIRD_PARTY_NOTICES.md.
"""Request a guarded target reboot and wait for the m1n1 proxy to return.

Calling the proxy P_REBOOT primitive without first clearing the PMU boot-error
breadcrumb can cause iBoot to demote the selected boot object. This helper follows
the ordering used by m1n1's in-tree reboot tool.

Asahi's own in-tree reboot tool (proxyclient/tools/reboot.py) does the safe thing:

    PMU(u).reset_panic_counter()   # clear the breadcrumb so iBoot keeps trusting us
    p.reboot()                     # then the watchdog reset

It then waits for USB to re-enumerate and confirms a fresh proxy is answering.

TWO PREREQUISITES for this to land back in m1n1 (read before --execute):

  1. m1n1 must be the default boot object. A reset boots whatever is selected.
     Changing that selection requires local owner authorization and recovery
     access; this script cannot do it.
  2. This must run while m1n1 is alive on the proxy (the normal probe context).

If a prerequisite is unmet, the machine may boot macOS and the USB proxy will not
return. This is gated behind --execute and requires the target owner's approval.
"""
import argparse
import sys
import time


def _add_proxyclient_path():
    import os
    for env in ('VEL2_CHECKOUT', 'M1N1_CHECKOUT'):
        base = os.environ.get(env)
        if base:
            pc = os.path.join(base, 'proxyclient')
            if os.path.isdir(pc) and pc not in sys.path:
                sys.path.insert(0, pc)


def _open(device):
    _add_proxyclient_path()
    from m1n1.proxy import UartInterface, M1N1Proxy
    from m1n1.proxyutils import ProxyUtils
    iface = UartInterface(device)
    iface.nop()
    p = M1N1Proxy(iface)
    p.nop()
    u = ProxyUtils(p)
    return iface, p, u


def _open_retry(device, tries=6, delay=3.0):
    # The proxy can be momentarily unready right after a prior run's teardown; retry
    # a few times so a transient UART timeout does not abort the whole reboot.
    last = None
    for _ in range(tries):
        try:
            return _open(device)
        except Exception as e:
            last = e
            time.sleep(delay)
    raise last


def clean_reboot(device, return_timeout=240.0):
    _add_proxyclient_path()
    from m1n1.hw.pmu import PMU
    iface, p, u = _open_retry(device)
    # The step the bricking helper omitted: clear the boot-error/panic breadcrumb
    # so iBoot does not demote the default boot object across this reset.
    PMU(u).reset_panic_counter()
    print('reset PMU panic counter; issuing reboot', flush=True)
    p.reboot()
    print('sent reboot; waiting for USB renumeration', flush=True)
    deadline = time.time() + return_timeout
    last = None
    while time.time() < deadline:
        time.sleep(2)
        try:
            iface2, p2, _ = _open(device)
            p2.nop()
            print('proxy is back and answering', flush=True)
            return True
        except Exception as e:  # node not back yet, or booted elsewhere
            last = e
    print(f'proxy did not return within {return_timeout:.0f}s (last: {last})', flush=True)
    print('the target may have booted its default macOS volume; see prerequisite 1', flush=True)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--device', default=None)
    ap.add_argument('--return-timeout', type=float, default=240.0)
    ap.add_argument('--execute', action='store_true',
                    help='Actually reboot. Without it, this only prints the plan.')
    a = ap.parse_args()
    if not a.device:
        ap.error('--device is required')
    if not a.execute:
        print('DRY RUN. Would: reset PMU panic counter, then p.reboot(), then wait '
              f'up to {a.return_timeout:.0f}s for the proxy to return on {a.device}.')
        print('Re-run with --execute to perform it. Read the prerequisites in the '
              'module docstring first.')
        return 0
    ok = clean_reboot(a.device, a.return_timeout)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
