"""Bounded 16 KiB, 47-bit guest table walk for pre-entry address checks."""
import struct
from sprr_permissions import leaf_permissions
PAGE = 0x4000
PA_MASK = (1 << 42)-PAGE
MONITOR_TCR = 0x10800236511a511
MONITOR_MAIR = 0x0c0804ff00bb44ff


class UnmappedAddress(ValueError):
    """An invalid descriptor, distinct from a malformed or inaccessible table."""


def translate(va, ttbr0, ttbr1, read_page):
    if not 0 <= va < 1 << 64:
        raise ValueError('Address outside uint64')
    high = va >> 47
    if high == 0:
        table = ttbr0
    elif high == (1 << 17)-1:
        table = ttbr1
    else:
        raise ValueError('Noncanonical 47-bit address')
    # The captured profile uses plain aligned roots, without ASID/CnP tags.
    # Reject unsupported bits rather than silently turning a bad root into RAM.
    if not 0 < table <= PA_MASK or table & (PAGE-1):
        raise ValueError('Unsupported or misaligned 42-bit table root')
    table_ro = table_pxn = table_uxn = table_privileged = False
    for level,shift in [(1,36),(2,25),(3,14)]:
        data = read_page(table)
        if len(data) != PAGE:
            raise ValueError('Truncated table page')
        index = (va >> shift) & 0x7ff
        desc = struct.unpack_from('<Q',data,index*8)[0]
        if not desc & 1:
            raise UnmappedAddress('Unmapped address')
        if desc & (((1 << 48)-1) ^ ((1 << 42)-1)):
            raise ValueError('Descriptor address exceeds 42-bit PA range')
        if level < 3 and desc & 2:
            # Hierarchical permissions are enabled in the captured VHE profile.
            table_ro |= bool(desc & (1 << 62))
            table_privileged |= bool(desc & (1 << 61))
            table_uxn |= bool(desc & (1 << 60))
            table_pxn |= bool(desc & (1 << 59))
            table = desc & PA_MASK
            continue
        if level == 1 or (level == 3 and not desc & 2):
            raise ValueError('Unsupported descriptor type')
        mask = (1 << shift)-1
        if level == 2 and desc & PA_MASK & mask:
            raise ValueError('Misaligned block output address')
        pa = (desc & PA_MASK & ~mask) | (va & mask)
        return dict(pa=pa,level=level,descriptor=desc,
                    access_flag=bool(desc & (1 << 10)),
                    read_only=table_ro or bool(desc & (1 << 7)),
                    user_access=not table_privileged and bool(desc & (1 << 6)),
                    pxn=table_pxn or bool(desc & (1 << 53)),
                    uxn=table_uxn or bool(desc & (1 << 54)))
    raise ValueError('No leaf')


def sprr_state(sprr):
    """Validate an optional SPRR permission state before any table page is read.

    Only the ordinary world is supported; a guarded-world request fails closed.
    """
    if sprr is None:
        return None
    if not isinstance(sprr, dict) or not {'pperm', 'uperm'} <= set(sprr) <= {'pperm', 'uperm', 'world'}:
        raise ValueError('Invalid SPRR permission state')
    if any(type(sprr[key]) is not int or not 0 <= sprr[key] < 1 << 64 for key in ('pperm', 'uperm')):
        raise ValueError('Expected uint64 SPRR permission registers')
    if sprr.get('world', 'ordinary') != 'ordinary':
        raise ValueError('Guarded-world SPRR continuation is unsupported')
    return dict(pperm=sprr['pperm'], uperm=sprr['uperm'], world='ordinary')


def sprr_continuation(name, result, sprr, pan):
    """Apply continuation requirements with SPRR-effective permissions; fail closed.

    Upstream ignores hierarchical table attributes under SPRR because their
    semantics are unknown, so any detected table restriction is rejected here,
    as is any effective pair an ordinary leaf cannot express exactly.
    """
    view = leaf_permissions(result['descriptor'], sprr['pperm'], sprr['uperm'], sprr['world'])
    if any(result[key] != value for key, value in view['native'].items()):
        raise ValueError('Hierarchical table restriction has unknown SPRR semantics: '+name)
    if not view['representable_natively']:
        raise ValueError('SPRR permissions are not natively representable: '+name)
    if name in ('pc', 'vector') and not view['kernel_execute']:
        raise ValueError('SPRR-effective continuation code is execute-never: '+name)
    if name == 'stack':
        if not view['kernel_write']:
            raise ValueError('SPRR-effective continuation stack is not writable')
        if pan and (view['user_read'] or view['user_write']):
            raise ValueError('SPRR-effective continuation stack is user accessible under PAN')
    return dict(sprr=view)


def validate_monitor_entry(controls, pc, sp, bootargs, base, size, read_page, *, pan=False,
                           on_check=None, sprr=None):
    """Check immediate entry spans only, for the one captured monitor profile.

    This does not validate the whole address space, emulate TLBs, or authorize
    later accesses. Only a genuinely unmapped old BootArgs pointer is optional.
    """
    if controls['tcr'] != MONITOR_TCR or controls['mair'] != MONITOR_MAIR:
        raise ValueError('Monitor MMU profile changed')
    if not 0 <= base < base+size <= 1 << 42 or base % PAGE or size % PAGE:
        raise ValueError('Invalid owned guest RAM range')
    if not 0 <= pc < 1 << 64 or pc % 4:
        raise ValueError('Invalid monitor PC alignment or range')
    if not 16 <= sp < 1 << 64 or sp % 16:
        raise ValueError('Invalid monitor stack alignment or range')
    sprr = sprr_state(sprr)
    cache = {}

    def owned_page(address):
        if not base <= address < address+PAGE <= base+size or address % PAGE:
            raise ValueError('Table walk left owned guest RAM')
        if address not in cache:
            cache[address] = read_page(address)
        return cache[address]

    checked = {}
    for name, address, length in [('pc', pc, 4), ('stack', sp-16, 16), ('bootargs', bootargs, 1)]:
        if on_check is not None:
            on_check(name, address)
        try:
            result = translate(address, controls['ttbr0'], controls['ttbr1'], owned_page)
        except UnmappedAddress as error:
            if name != 'bootargs':
                raise
            checked[name] = dict(va=address, unmapped=str(error))
            continue
        if not base <= result['pa'] < result['pa']+length <= base+size:
            raise ValueError('Initial monitor mapping leaves guest RAM: '+name)
        if name != 'stack' and result['pa'] != address:
            raise ValueError('Initial monitor mapping is not identity: '+name)
        if not result['access_flag']:
            raise ValueError('Access flag is clear: '+name)
        extra = {}
        if sprr is None:
            if name == 'pc' and (result['pxn'] or (result['user_access'] and not result['read_only'])):
                raise ValueError('Initial monitor code is execute-never')
            if name == 'stack' and (result['read_only'] or (pan and result['user_access'])):
                raise ValueError('Initial monitor stack is not writable')
        else:
            extra = sprr_continuation(name, result, sprr, pan)
        if name in ('pc', 'stack'):
            attr = (controls['mair'] >> (((result['descriptor'] >> 2) & 7)*8)) & 0xff
            if attr != 0xff:
                raise ValueError('Initial monitor mapping is not supported normal WB memory: '+name)
        checked[name] = dict(va=address, bytes=length, **result, **extra)
    return checked


def validate_root_switch(controls, register, value, pc, sp, vector, base, size,
                         read_page, *, pan=False, max_pages=256, sprr=None):
    """Validate a same-profile root replacement, not arbitrary control changes.

    Walk the complete candidate root within bounded owned RAM, then require
    continuation code, stack and vector mappings to retain physical identity.
    Other old mappings need not survive an intentional root replacement.
    """
    if register not in ('ttbr0', 'ttbr1') or controls['tcr'] != MONITOR_TCR or controls['mair'] != MONITOR_MAIR:
        raise ValueError('Unsupported live translation profile')
    if not 0 <= base < base+size <= 1 << 42 or base % PAGE or size % PAGE:
        raise ValueError('Invalid owned guest RAM')
    if not 0 < value <= PA_MASK or value % PAGE:
        raise ValueError('Unsupported live table root')
    if pc % 4 or sp < 16 or sp % 16 or vector % 2048 or not vector:
        raise ValueError('Invalid continuation address alignment')
    if not 1 <= max_pages <= 4096:
        raise ValueError('Invalid table walk budget')
    sprr = sprr_state(sprr)
    candidate = dict(controls, **{register: value})
    pages = {}
    def owned(address):
        if not base <= address < address+PAGE <= base+size or address % PAGE:
            raise ValueError('Live table walk left owned guest RAM')
        if address not in pages:
            if len(pages) >= max_pages:
                raise ValueError('Live table page budget exhausted')
            data = read_page(address)
            if len(data) != PAGE:
                raise ValueError('Truncated live table page')
            pages[address] = data
        return pages[address]
    leaves = visits = 0
    def walk(address, level, prefix, ancestors):
        nonlocal leaves, visits
        visits += 1
        if visits > max_pages:
            raise ValueError('Live table traversal budget exhausted')
        if address in ancestors:
            raise ValueError('Cyclic live table')
        data = owned(address)
        shift = {1: 36, 2: 25, 3: 14}[level]
        for index, (desc,) in enumerate(struct.iter_unpack('<Q', data)):
            if not desc & 1:
                continue
            va = prefix | index << shift
            if desc & (((1 << 48)-1) ^ ((1 << 42)-1)):
                raise ValueError('Live descriptor exceeds 42-bit PA')
            if level < 3 and desc & 2:
                walk(desc & PA_MASK, level+1, va, ancestors | {address})
            else:
                if register == 'ttbr1':
                    va |= ((1 << 17)-1) << 47
                result = translate(va, candidate['ttbr0'], candidate['ttbr1'], owned)
                length = 1 << shift
                if not base <= result['pa'] < result['pa']+length <= base+size:
                    raise ValueError('Candidate leaf leaves owned guest RAM')
                leaves += 1
                if leaves > 524288:
                    raise ValueError('Live leaf budget exhausted')
    walk(value, 1, 0, set())
    checks = {}
    for name, address, length in [('pc', pc, 4), ('stack', sp-16, 16), ('vector', vector, 4)]:
        old = translate(address, controls['ttbr0'], controls['ttbr1'], owned)
        new = translate(address, candidate['ttbr0'], candidate['ttbr1'], owned)
        if old['pa'] != new['pa'] or not base <= new['pa'] < new['pa']+length <= base+size:
            raise ValueError('Root replacement changes continuation backing: '+name)
        if not new['access_flag']:
            raise ValueError('Root replacement clears continuation AF: '+name)
        extra = {}
        if sprr is None:
            if name in ('pc', 'vector') and (new['pxn'] or (new['user_access'] and not new['read_only'])):
                raise ValueError('Root replacement makes continuation execute-never: '+name)
            if name == 'stack' and (new['read_only'] or (pan and new['user_access'])):
                raise ValueError('Root replacement makes stack unwritable')
        else:
            extra = sprr_continuation(name, new, sprr, pan)
        attr = (candidate['mair'] >> (((new['descriptor'] >> 2) & 7)*8)) & 0xff
        if attr != 0xff:
            raise ValueError('Unsupported continuation memory type: '+name)
        checks[name] = dict(va=address, bytes=length, **new, **extra)
    return dict(controls=candidate, continuation=checks, table_pages=len(pages),
                candidate_leaves=leaves, complete_candidate_root=True,
                complete_machine_state_validation=False)
