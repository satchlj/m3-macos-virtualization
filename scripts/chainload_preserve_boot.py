#!/usr/bin/env python3
# Copyright The Asahi Linux Contributors (upstream portions).
# See ../LICENSES/Asahi-m1n1-MIT.txt and ../THIRD_PARTY_NOTICES.md.
# SPDX-License-Identifier: MIT
# RAM reload sequence derived from Asahi m1n1 proxyclient/tools/chainload.py.
"""Load the research runtime from a fresh baseline, preserving boot-data aliases."""
import argparse
import os
from pathlib import Path
import sys
from boot_data_relocation import plan_copies, relocate_tree
from run_manifest import atomic_json, file_identity, git_identity, utc
from sptm_layout import PAGE, align


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--checkout', type=Path, default=os.environ.get('M1N1_CHECKOUT'))
    ap.add_argument('--image', type=Path, required=True)
    ap.add_argument('--device', required=True)
    ap.add_argument('--output', type=Path, required=True, help='New capture directory')
    ap.add_argument('--fresh-gate-nonce', help='Host gate nonce copied into the report')
    a = ap.parse_args()
    if a.checkout is None:
        ap.error('Source checkout required')
    a.output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(a.checkout.resolve()/'proxyclient'))
    from m1n1.proxy import UartInterface, M1N1Proxy
    from m1n1.proxyutils import ProxyUtils
    from m1n1.tgtypes import BootArgs_r3
    from m1n1 import asm
    report = dict(scope='fresh-baseline-ram-chainload', image=file_identity(a.image),
                  sources=git_identity(Path(__file__).resolve().parents[1]),
                  installed_boot_object_changed=False, started_at=utc(), ended_at=None)
    if a.fresh_gate_nonce:
        report['fresh_gate_nonce'] = a.fresh_gate_nonce
    iface = None
    try:
        iface = UartInterface(a.device); iface.nop(); p = M1N1Proxy(iface); p.nop()
        u = ProxyUtils(p)
        if u.ba.revision != 3:
            raise ValueError('Expected revision-3 boot arguments')
        original = u.get_adt(); (a.output/'original.adt').write_bytes(original)
        rtbuddy = u.adt['chosen']['memory-map'].RTBuddySeg
        if iface.readmem(rtbuddy[0], 4) != b'[AFK':
            raise ValueError('RTBuddySeg original payload marker missing; require fresh installed baseline')
        image = a.image.read_bytes()+b'\0\0\0\0'
        new_base = u.base
        copies = plan_copies(u.adt['chosen']['memory-map'], u.ba.phys_base, u.ba.mem_size, align(len(image)))
        # On a previously chainloaded image these stale ranges can overlap the runtime.
        for span in copies['spans']:
            if span['start'] < new_base+len(image) and new_base < span['end']:
                # A fresh installed image may be smaller than the incoming image;
                # overlap with the incoming image is expected and handled by staging.
                report['incoming_image_overwrites_boot_inputs'] = True
        args_off = copies['end_offset']; image_size = args_off+PAGE
        image_addr = u.malloc(image_size+PAGE)
        if any(image_addr < s['end'] and s['start'] < image_addr+image_size+PAGE for s in copies['spans']):
            raise ValueError('Staging allocation overlaps original boot inputs')
        report.update(base=new_base, staging=image_addr, size=image_size, boot_copies=copies)
        report['relocations'] = relocate_tree(u.adt, copies, new_base)
        u.compressed_writemem(image_addr, image, True)
        p.dc_cvau(image_addr, len(image))
        for index, span in enumerate(copies['spans']):
            print(f"Preserving boot span {index}: {span['start']:#x}+{span['size']:#x}", flush=True)
            dest = image_addr+span['offset']
            p.memcpy8(dest, span['start'], span['size'])
            # Read a stable staging copy in bounded USB transfers.
            path = a.output/f'boot-data-{index}.bin'
            with path.open('wb') as f:
                for off in range(0, span['size'], 0x10000):
                    f.write(iface.readmem(dest+off, min(0x10000, span['size']-off)))
            span['capture'] = file_identity(path)
        u.adt['chosen']['memory-map'].BootArgs = (new_base+args_off, PAGE)
        (a.output/'relocated.adt').write_bytes(u.adt.build())
        u.push_adt()
        ba = u.ba.copy(); ba.top_of_kernel_data = new_base+image_size
        iface.writemem(image_addr+args_off, BootArgs_r3.build(ba))
        entry = new_base+0x800
        stub = asm.ARMAsm(f'''
1:
    ldp x4, x5, [x1], #16
    stp x4, x5, [x2]
    dc cvau, x2
    ic ivau, x2
    add x2, x2, #16
    sub x3, x3, #16
    cbnz x3, 1b
    ldr x1, ={entry}
    br x1
''', image_addr+image_size)
        if stub.len > PAGE:
            raise ValueError('Reload stub exceeds allocation')
        iface.writemem(stub.addr, stub.data); p.dc_cvau(stub.addr, stub.len); p.ic_ivau(stub.addr, stub.len)
        report['phase'] = 'prepared'; atomic_json(a.output/'report.json', report)
        p.reload(stub.addr, new_base+args_off, image_addr, new_base, image_size)
        iface.nop(); p.nop()
        report['phase'] = 'proxy-returned'
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        report['ended_at'] = utc()
        atomic_json(a.output/'report.json', report)
        if iface is not None:
            iface.dev.close()


if __name__ == '__main__':
    main()
