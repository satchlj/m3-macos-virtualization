"""Bounded RAM copies for selected boot inputs; no firmware or MMIO execution."""
from boot_data_audit import SEGMENT
from sptm_layout import PAGE, align

NAMES = ('RTBuddySeg', 'SEPFW', 'preoslog')
MAX_BYTES = 0x2000000


def plan_copies(mmap, host_base, host_size, offset):
    """Merge overlapping RAM ranges so aliases retain identical copied bytes."""
    if not 0 <= host_base < host_base + host_size <= 1 << 42:
        raise ValueError('Invalid host RAM bounds')
    entries = []
    for name in NAMES:
        value = mmap._properties.get(name)
        if value is None:
            continue
        if not isinstance(value, (tuple, list)) or len(value) != 2:
            raise ValueError('Unsupported boot range: ' + name)
        address, size = value
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in value):
            raise ValueError('Noninteger boot range: ' + name)
        if size == 0:
            continue
        if size < 0 or not host_base <= address < address+size <= host_base+host_size:
            raise ValueError('Boot input outside declared host RAM: ' + name)
        start, end = address & -PAGE, align(address+size)
        if start < host_base or end > host_base+host_size:
            raise ValueError('Aligned boot input outside host RAM: ' + name)
        entries.append(dict(name=name, address=address, size=size, start=start, end=end))
    spans = []
    for item in sorted(entries, key=lambda x: x['start']):
        if spans and item['start'] <= spans[-1]['end']:
            spans[-1]['end'] = max(spans[-1]['end'], item['end'])
        else:
            spans.append(dict(start=item['start'], end=item['end']))
    if sum(s['end']-s['start'] for s in spans) > MAX_BYTES:
        raise ValueError('Boot input copy exceeds 32 MiB bound')
    offset = align(offset)
    for span in spans:
        span['offset'] = offset
        span['size'] = span['end']-span['start']
        offset += span['size']
    return dict(entries=entries, spans=spans, end_offset=offset)


def relocate_tree(adt, plan, base):
    """Retarget selected allocations and fully contained firmware aliases."""
    def mapped(address, size):
        for span in plan['spans']:
            if span['start'] <= address and address+size <= span['end']:
                return base+span['offset']+address-span['start']
        return None
    changes, pending = [], []
    mmap = adt['/chosen/memory-map']
    for item in plan['entries']:
        target = mapped(item['address'], item['size'])
        if target is None:
            raise ValueError('Missing boot copy span')
        pending.append((mmap, item['name'], (target, item['size'])))
        changes.append(dict(path='/chosen/memory-map', name=item['name'],
                            source=item['address'], destination=target, size=item['size']))
    for node in adt.walk_tree():
        data = getattr(node, 'segment_ranges', None)
        if data is None:
            continue
        names = getattr(node, 'segment_names', None)
        if not isinstance(data, bytes) or len(data) % SEGMENT.size or not isinstance(names, str) or len(names.split(';')) != len(data)//SEGMENT.size:
            raise ValueError('Malformed firmware segment metadata')
        output = bytearray()
        for name, fields in zip(names.split(';'), SEGMENT.iter_unpack(data)):
            phys, iova, remap, size, unknown = fields
            target = mapped(phys, size) if size else None
            if target is not None:
                target_remap = mapped(remap, size) if remap else 0
                if target_remap is None:
                    raise ValueError('Copied firmware segment has external remap')
                changes.append(dict(path=node._path, name=name, source=phys,
                                    destination=target, size=size, remap_source=remap,
                                    remap_destination=target_remap, iova_unchanged=iova))
                phys, remap = target, target_remap
            elif size and any(phys < s['end'] and s['start'] < phys+size for s in plan['spans']):
                raise ValueError('Partially overlapping firmware alias')
            output.extend(SEGMENT.pack(phys, iova, remap, size, unknown))
        pending.append((node, 'segment_ranges', bytes(output)))
    # Validate all metadata before making any tree mutation.
    for node, name, value in pending:
        setattr(node, name, value)
    return changes


def read_copy(readmem, address, size):
    """Bound USB requests and reject truncated input before publishing a copy."""
    if not 0 < size <= MAX_BYTES:
        raise ValueError('Invalid boot copy size')
    chunks = []
    for offset in range(0, size, 0x10000):
        count = min(0x10000, size-offset)
        data = readmem(address+offset, count)
        if len(data) != count:
            raise ValueError('Truncated host boot input')
        chunks.append(data)
    return b''.join(chunks)
