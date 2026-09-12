"""Classify an eret target by live translation and verified loaded entry bytes."""
from guest_pt import translate, PAGE
from trace_disassembly import resolve


def classify_entry(target, layout, base, size, roots, readmem, sources):
    def bounded(pa, length):
        if not base <= pa < pa + length <= base + size:
            raise ValueError('Handoff read outside owned guest RAM')
        data = readmem(pa, length)
        if len(data) != length:
            raise ValueError('Truncated handoff read')
        return data
    mapping = translate(target, roots['ttbr0'], roots['ttbr1'], lambda pa: bounded(pa, PAGE))
    if not base <= mapping['pa'] < mapping['pa'] + 32 <= base + size:
        raise ValueError('Handoff target outside owned guest RAM')
    placement = resolve(layout, mapping['pa'], guest_base=base, guest_size=size)
    if placement['status'] != 'mapped':
        raise ValueError('Handoff target is not loaded image bytes')
    name, segment_name = placement['image'], placement['segment']
    meta = layout['images'][name]
    segment = meta['segments'][segment_name]
    linked_pc = segment['va'] + placement['fileoff'] - segment['fileoff']
    data = bounded(mapping['pa'], 32)
    expected = sources[name][placement['fileoff']:placement['fileoff'] + 32]
    return dict(image=name, segment=segment_name, target_pc=hex(target), pa=hex(mapping['pa']),
                linked_pc=hex(linked_pc), entry_matches=linked_pc == meta['entry'],
                bytes_match=data == expected, bytes_hex=data.hex(),
                instructions_executed=False)
