#!/usr/bin/env python3
"""Observe guest ownership of ADT boot ranges; never grant mappings or remove data."""
import argparse
import os
from pathlib import Path
import struct
import sys
from run_manifest import atomic_json, file_identity
SEGMENT = struct.Struct('<QQQII')  # Pinned m1n1 src/adt.h: phys, iova, remap, size, unknown.


def audit_tree(adt, base, size):
    if not 0 <= base < base+size <= 1 << 42:
        raise ValueError('Invalid owned guest RAM')
    ranges, issues = [], []
    def add(path, name, address, length, **extra):
        item = dict(path=path, name=name, address=address, size=length, **extra)
        if not all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 1 << 64 for v in (address, length)) or address+length > 1 << 64:
            item['ownership'] = 'invalid-range'
        elif not length:
            item['ownership'] = 'empty'
        elif base <= address < address+length <= base+size:
            item['ownership'] = 'owned'
        else:
            item['ownership'] = 'outside-owned-guest-ram'
        ranges.append(item)
    mmap = adt['/chosen/memory-map']
    for name, value in sorted(mmap._properties.items()):
        if name.endswith(('-virt', '-entry')):
            continue  # Declared virtual metadata, not a physical allocation.
        if isinstance(value, bytes) and len(value) == 16:
            value = struct.unpack('<QQ', value)
        if isinstance(value, (list, tuple)) and len(value) == 2:
            add('/chosen/memory-map', name, *value, kind='memory-map')
    for node in adt.walk_tree():
        data = getattr(node, 'segment_ranges', None)
        if data is None:
            continue
        names = getattr(node, 'segment_names', None)
        if not isinstance(data, bytes) or len(data) % SEGMENT.size or not isinstance(names, str):
            issues.append(dict(path=node._path, error='Unsupported segment metadata representation'))
            continue
        names = names.split(';')
        if len(names) != len(data)//SEGMENT.size:
            issues.append(dict(path=node._path, error='Segment name/range count mismatch'))
            continue
        for name, (phys, iova, remap, length, unknown) in zip(names, SEGMENT.iter_unpack(data)):
            add(node._path, name, phys, length, kind='firmware-segment', iova=iova, remap=remap, unknown=unknown)
    return dict(scope='observational-boot-data-ownership-audit', guest_base=base, guest_size=size,
        ranges=ranges, parse_issues=issues, permission_or_mapping_changes=False,
        complete_guest_isolation_claimed=False,
        interpretation='Outside ranges are candidates for investigation; this audit does not classify their necessity or authorize copying, omission, or MMIO access')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('adt', type=Path)
    ap.add_argument('--checkout', type=Path, default=os.environ.get('VEL2_CHECKOUT'))
    ap.add_argument('--guest-base', type=lambda x:int(x,0), required=True)
    ap.add_argument('--guest-size', type=lambda x:int(x,0), required=True)
    ap.add_argument('--address', type=lambda x:int(x,0), help='Find ranges containing a recorded physical address')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    if a.checkout is None:
        ap.error('A source checkout is required for the ADT decoder')
    sys.path.insert(0, str(a.checkout.resolve()/'proxyclient'))
    from m1n1.adt import ADTNode, ADTNodeStruct
    # Parsing boot ranges does not need load_adt's PMGR device initialization.
    result = audit_tree(ADTNode(ADTNodeStruct.parse(a.adt.read_bytes())), a.guest_base, a.guest_size)
    result['source'] = file_identity(a.adt)
    if a.address is not None:
        result['matching_ranges'] = [r for r in result['ranges'] if r['ownership'] != 'invalid-range' and r['address'] <= a.address < r['address']+r['size']]
        result['queried_address'] = a.address
    atomic_json(a.output, result)


if __name__ == '__main__':
    main()
