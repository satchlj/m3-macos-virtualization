#!/usr/bin/env python3
"""Offline segmented SPTM/TXM/BootKC placement from the pinned public QEMU loader.

Reads Mach-O headers and load commands only. A layout is not a boot-readiness claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from inspect_guest_payload import inspect

PAGE = 0x4000

def align(n):
    return (n + PAGE - 1) & -PAGE


def image(path):
    data = path.read_bytes()
    inspect(data)
    ncmds = struct.unpack_from('<I', data, 16)[0]
    pos, segments, entry = 32, {}, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, pos)
        if cmd == 0x19:
            name = data[pos+8:pos+24].split(b'\0')[0].decode('ascii')
            va, length, offset, filesize = struct.unpack_from('<4Q', data, pos+24)
            if name in segments or length % PAGE or filesize > length or va % PAGE:
                raise ValueError('Unsupported segment layout: ' + name)
            segments[name] = dict(va=va, size=length, fileoff=offset, filesize=filesize)
        elif cmd == 5:
            cursor = pos + 8
            while cursor < pos+size:
                flavor, words = struct.unpack_from('<II', data, cursor)
                if flavor == 6:
                    entry = struct.unpack_from('<Q', data, cursor+8+32*8)[0]
                cursor += 8+words*4
        pos += size
    ordered = sorted(segments.values(), key=lambda s: s['va'])
    for a, b in zip(ordered, ordered[1:]):
        if a['va']+a['size'] > b['va']:
            raise ValueError('Overlapping virtual segments')
    return dict(path=str(path), sha256=hashlib.sha256(data).hexdigest(), segments=segments,
                vmin=ordered[0]['va'], vmax=max(s['va']+s['size'] for s in ordered), entry=entry)


def plan(payload, adt_size, trustcache_size):
    images = {n: image(payload / (n+'.macho')) for n in ('sptm', 'txm', 'kernelcache')}
    regions, placements = {}, []
    head = 0
    def raw(name, size):
        nonlocal head
        size = align(size)
        regions[name] = [head, size]
        head += size
    def group(name, which, names):
        nonlocal head
        start = head
        for segname in names:
            seg = images[which]['segments'][segname]
            placements.append(dict(image=which, segment=segname, offset=head, size=seg['size']))
            head += seg['size']
        regions[name] = [start, head-start]
    before = [
        ('TXM-ro', 'txm', ['__TEXT','__DATA_CONST']),
        ('TXM-rx', 'txm', ['__TEXT_EXEC']),
        ('TXM-bx', 'txm', ['__TEXT_BOOT_EXEC']),
        ('BootKC-rx','kernelcache',['__TEXT_EXEC']),
        ('BootKC-bx','kernelcache',['__TEXT_BOOT_EXEC']),
        ('BootKC-ro','kernelcache',['__TEXT','__PRELINK_TEXT','__DATA_CONST']),
        ('BootKC-rs','kernelcache',['__DATA_SPTM']),
    ]
    prefix_size = sum(images[which]['segments'][s]['size'] for _,which,names in before for s in names)
    prefix_size += align(trustcache_size) + PAGE + align(adt_size)
    desired = images['kernelcache']['vmin'] & ((1 << 36)-1)
    if desired < prefix_size:
        raise ValueError('Public layout alignment assumption does not fit')
    head = desired - prefix_size
    for i, (name, which, names) in enumerate(before):
        group(name, which, names)
        if i == 2:
            raw('TrustCache', trustcache_size)
            raw('AuxKC-ro', 0)
            raw('AuxKC-rx', 0)
            raw('AuxKC-rw', 0)
            raw('AuxKC-le', 0)
    raw('CL4-rx', 0)
    raw('CL4-ro', 0)
    raw('CL4-rw', 0)
    raw('CL4-le', 0)
    raw('DeviceTree', PAGE+align(adt_size))
    adt_offset = regions['DeviceTree'][0]+PAGE
    sptm_offset = head
    for name, names in [
        ('SPTM-ro',['__TEXT','__DATA_CONST','__LATE_CONST']),
        ('SPTM-rx',['__TEXT_EXEC','__LAST']),
        ('SPTM-rw',['__DATA','__BOOTDATA']),
        ('SPTM-le',['__LINKEDIT'])]:
        for segname in names:
            seg = images['sptm']['segments'][segname]
            if head != sptm_offset + seg['va'] - images['sptm']['vmin']:
                raise ValueError('SPTM must retain its linked segment spacing')
            # Advance checked by group below, not this loop.
            head += seg['size']
        head -= sum(images['sptm']['segments'][s]['size'] for s in names)
        group(name, 'sptm', names)
    # SPTM's hib bootstrap registers two "iBoot loaded ranges" split around
    # SPTM-rm: [SPTM-ro.base, SPTM-rm.base) and [SPTM-rm.end, SPTM-rx.end)
    # (0xe0a80..0xe0dc8 -> hib_bootstrap_register_iboot_loaded_range at 0xc0e18,
    # which panics unless each range's base and size are 16 KB aligned). Our SPTM
    # is contiguous ro|rx, with no separate read-mostly segment, so pin SPTM-rm as
    # a zero-size marker at the ro/rx boundary (== SPTM-rx.base): range 1 becomes
    # exactly [ro] and range 2 exactly [rx], both page aligned. Left as the -1 host
    # sentinel it produced a garbage, unaligned size and panicked (attempt-27).
    regions['SPTM-rm'] = [regions['SPTM-rx'][0], 0]
    group('TXM-rw','txm',['__DATA'])
    group('TXM-le','txm',['__LINKEDIT'])
    group('BootKC-rw','kernelcache',['__PRELINK_INFO','__DATA'])
    group('BootKC-le','kernelcache',['__LINKEDIT'])
    raw('CL4-dummypage',PAGE)
    raw('BootArgs',PAGE)
    raw('RAMDisk',0)
    for name, which in [('SPTM','sptm'),('TXM','txm'),('BootKC','kernelcache')]:
        regions[name+'-virt'] = [images[which]['vmin'],0]
        regions[name+'-entry'] = [images[which]['entry'],0]
    # CL4 (cryptex boot collection) is absent from this guest. SPTM's boot still
    # looks up CL4-entry/CL4-virt (required=1) while computing per-image entry PCs
    # and never enters CL4 on the XNU path, so zero VA pseudo-regions satisfy the
    # lookup harmlessly. They end in -virt/-entry, so the probe emits them as raw
    # (value,0) tuples like the real image pseudo-regions.
    regions['CL4-virt'] = [0,0]
    regions['CL4-entry'] = [0,0]
    # 'slide' is iBoot's KASLR-slide handoff entry: SPTM copies its paddr straight
    # into the XNU boot handoff as the kernel slide. We load every image at its
    # linked address with no randomization, so the applied slide is 0. Flagged
    # 'slide-zero' so the probe emits paddr 0 (a normal paddr region would encode
    # base+offset, which XNU would misread as a huge slide).
    regions['slide'] = [0,0]
    for i, which in enumerate(('txm','kernelcache'),1):
        if (images['sptm']['vmin']-images[which]['vmin']) & ((1<<36)-1) != i*0x10000000:
            raise ValueError('Monitor virtual-stride assumption changed')
    return dict(scope='offline-monitor-layout', guest_boot_verified=False, images=images,
                regions=regions, placements=placements, size=align(head), adt_offset=adt_offset,
                virtual_base=images['kernelcache']['vmin'] & ~((1<<36)-1),
                entry_offset=sptm_offset+images['sptm']['entry']-images['sptm']['vmin'])

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('payload', type=Path)
    p.add_argument('--adt-size', type=lambda s:int(s,0), default=0x80000)
    p.add_argument('--trustcache-size', type=lambda s:int(s,0), default=0x4000)
    p.add_argument('--output', type=Path, required=True)
    a=p.parse_args()
    a.output.write_text(json.dumps(plan(a.payload,a.adt_size,a.trustcache_size),indent=2)+'\n')
