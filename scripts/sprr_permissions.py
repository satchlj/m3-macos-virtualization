# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See ../LICENSES/Asahi-m1n1-MIT.txt and ../THIRD_PARTY_NOTICES.md.
"""Offline exact representability audit of upstream SPRR permission mappings.

No page tables or device state are modified. The nibble interpretation follows
pinned public hv_sprr.c; it is not independent M3/Tahoe validation.
"""
from itertools import product

R, W, X = 4, 2, 1
EL = (0, R|X, R, R|W, 0, R|X, R, 0, 0, X, R, R|W, 0, R|X, R, R|W)
GL = (0, 0, 0, 0, R|X, R|X, R|X, R|X, R, R, R, R, R|W, R|W, R|W, R|W)


def ordinary_access(bits):
    """Leaf access with AF set, no table restrictions, PAN clear, WXN clear."""
    if bits is None:
        return 0, 0
    user = bool(bits & (1 << 6))
    writable = not bits & (1 << 7)
    kernel = R | (W if writable else 0) | (0 if bits & (1 << 53) else X)
    unprivileged = (R | (W if writable else 0) | (0 if bits & (1 << 54) else X)) if user else 0
    return kernel, unprivileged


def exact_leaf(kernel, user):
    """Return exact permission bits, None for unmapped, or raise; never overgrant."""
    if any(type(v) is not int or not 0 <= v <= 7 for v in (kernel, user)):
        raise ValueError('Invalid RWX mask')
    if (kernel, user) == (0, 0):
        return None
    for el0, ro, pxn, uxn in product((0, 1), repeat=4):
        bits = el0 << 6 | ro << 7 | pxn << 53 | uxn << 54
        if ordinary_access(bits) == (kernel, user):
            return bits
    raise ValueError('SPRR access pair cannot be represented exactly by an ordinary leaf')


def audit(perm_el1, perm_el0, guarded=False):
    if any(type(v) is not int or not 0 <= v < 1 << 64 for v in (perm_el1, perm_el0)):
        raise ValueError('Expected uint64 permission registers')
    table = GL if guarded else EL
    results = []
    for index in range(16):
        kernel, user = (table[(v >> (index*4)) & 15] for v in (perm_el1, perm_el0))
        item = dict(index=index, kernel_rwx=kernel, user_rwx=user)
        try:
            item.update(representable=True, leaf_permission_bits=exact_leaf(kernel, user))
        except ValueError as error:
            item.update(representable=False, reason=str(error))
        results.append(item)
    return dict(scope='offline-upstream-sprr-permission-audit', guarded=guarded,
                hardware_validated=False, assumptions=['AF set', 'PAN clear', 'WXN clear',
                'no hierarchical permission restrictions', 'ordinary stage-1 leaf'], indices=results)


# Upstream leaf-to-index layout, copied from pinned hv_sprr.c (SPRR_IDX_* and
# sprr_mirror_entry) with the PTE bit positions from its memory.h:
#   index bit 0 = SPRR_IDX_PXN    <- PTE_PXN    (descriptor bit 53)
#   index bit 1 = SPRR_IDX_UXN    <- PTE_UXN    (descriptor bit 54)
#   index bit 2 = SPRR_IDX_AP_EL0 <- PTE_AP_EL0 (descriptor bit 6, AP[1])
#   index bit 3 = SPRR_IDX_AP_RO  <- PTE_AP_RO  (descriptor bit 7, AP[2])
# The selected nibble is (perm >> (index * 4)) & 0xf (sprr_perm_nibble), then
# sprr_el_rwx / sprr_gl_rwx (EL / GL above) give RWX with R=4, W=2, X=1.
SPRR_IDX_PXN, SPRR_IDX_UXN, SPRR_IDX_AP_EL0, SPRR_IDX_AP_RO = 1, 2, 4, 8
WORLDS = dict(ordinary=EL, guarded=GL)


def leaf_index(descriptor):
    """The 4-bit SPRR index encoded in a stage-1 leaf's AP[2:1]/UXN/PXN bits."""
    return ((SPRR_IDX_PXN if descriptor & (1 << 53) else 0) |
            (SPRR_IDX_UXN if descriptor & (1 << 54) else 0) |
            (SPRR_IDX_AP_EL0 if descriptor & (1 << 6) else 0) |
            (SPRR_IDX_AP_RO if descriptor & (1 << 7) else 0))


def leaf_permissions(descriptor, perm_el1, perm_el0, world='ordinary'):
    """Interpret one leaf under SPRR_PPERM_EL1/SPRR_UPERM_EL0; pure and offline.

    Returns the index, the two selected nibbles, explicit effective booleans,
    the native (SPRR-off) reading of the same bits, and whether the effective
    pair is exactly representable by an ordinary leaf. Hierarchical table
    attributes are not considered; upstream ignores them under SPRR.
    """
    if any(type(v) is not int or not 0 <= v < 1 << 64 for v in (descriptor, perm_el1, perm_el0)):
        raise ValueError('Expected uint64 descriptor and permission registers')
    if world not in WORLDS:
        raise ValueError('Unknown SPRR world')
    if not descriptor & 1:
        raise ValueError('Descriptor is not valid')
    index = leaf_index(descriptor)
    pperm_nibble = (perm_el1 >> (index*4)) & 15
    uperm_nibble = (perm_el0 >> (index*4)) & 15
    kernel, user = WORLDS[world][pperm_nibble], WORLDS[world][uperm_nibble]
    item = dict(world=world, index=index,
                index_bits=dict(pxn=bool(index & SPRR_IDX_PXN), uxn=bool(index & SPRR_IDX_UXN),
                                ap_el0=bool(index & SPRR_IDX_AP_EL0), ap_ro=bool(index & SPRR_IDX_AP_RO)),
                pperm_nibble=pperm_nibble, uperm_nibble=uperm_nibble,
                kernel_rwx=kernel, user_rwx=user,
                kernel_read=bool(kernel & R), kernel_write=bool(kernel & W), kernel_execute=bool(kernel & X),
                user_read=bool(user & R), user_write=bool(user & W), user_execute=bool(user & X),
                native=dict(read_only=bool(descriptor & (1 << 7)), user_access=bool(descriptor & (1 << 6)),
                            pxn=bool(descriptor & (1 << 53)), uxn=bool(descriptor & (1 << 54))),
                hardware_validated=False)
    try:
        item.update(representable_natively=True, leaf_permission_bits=exact_leaf(kernel, user))
    except ValueError as error:
        item.update(representable_natively=False, reason=str(error))
    return item
