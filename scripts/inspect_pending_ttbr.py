#!/usr/bin/env python3
"""Read-only validation of the latest stopped probe's proposed root switch."""
import argparse
import os
from pathlib import Path
import sys
from guest_pt import validate_root_switch, PAGE
from run_manifest import atomic_json, file_identity
from trace_diff import load_report
from vel2_smoke import verify_image


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('report', type=Path)
    ap.add_argument('--checkout', type=Path, default=os.environ.get('VEL2_CHECKOUT'))
    ap.add_argument('--device', required=True)
    ap.add_argument('--output', type=Path, required=True, help='New snapshot directory')
    a = ap.parse_args()
    r = load_report(a.report); e = r['trace'][-1]
    if r.get('stop_reason') != 'live-translation-control-change' or r.get('proxy_alive_after_exit') is not True:
        ap.error('Requires latest clean stopped root-switch attempt')
    if e.get('register') not in ('TTBR0_EL1','TTBR0_EL2','TTBR1_EL1','TTBR1_EL2') or e.get('read') is not False:
        ap.error('Last event is not a proposed root write')
    a.output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(a.checkout.resolve()/'proxyclient'))
    from m1n1.proxy import UartInterface, M1N1Proxy
    from m1n1.proxyutils import ProxyUtils
    from m1n1.sysreg import VBAR_EL12
    result = dict(run_id=r['run_id'], source_report=file_identity(a.report), guest_resumed=False, pages=[])
    iface = UartInterface(a.device)
    try:
        iface.nop(); p=M1N1Proxy(iface); p.nop()
        result['image_sections'] = verify_image(iface, p.get_base(), a.checkout/'build/m1n1-raw.elf')
        u=ProxyUtils(p)
        vector=u.mrs(VBAR_EL12)
        def read(address):
            data=iface.readmem(address,PAGE)
            path=a.output/f'{address:x}.bin'; path.write_bytes(data)
            result['pages'].append(dict(address=address,**file_identity(path)))
            return data
        mode=e['spsr'] & 15
        if mode not in (4,5):
            raise ValueError('Unsupported physical guest mode')
        sp=e['sp'][mode-4]
        result['arguments']=dict(controls=r['monitor_mmu_controls'],register=e['register'][:5].lower(),
            value=e['value'],pc=e['pc'],sp=sp,vector=vector,base=r['guest_base'],size=r['guest_size'],pan=bool(e['spsr'] & (1<<22)))
        result['validation']=validate_root_switch(**result['arguments'],read_page=read)
        p.nop();result['proxy_alive']=True
    except BaseException as error:
        result['error']=str(error)
        raise
    finally:
        atomic_json(a.output/'report.json',result);iface.dev.close()


if __name__ == '__main__':main()
