#!/usr/bin/env python3
"""Decode one stage-1 leaf descriptor under recorded SPRR permission registers.

Prints the upstream-model interpretation as JSON: the SPRR index encoded in
the leaf's AP[2:1]/UXN/PXN bits, the SPRR_PPERM_EL1 / SPRR_UPERM_EL0 nibbles
that index selects, the effective kernel/user RWX, the native (SPRR-off)
reading of the same bits, and whether the pair is natively representable.
Offline only; nibble meanings are the public upstream model, not M3-validated.
"""
import argparse
import json
import sys
from sprr_permissions import leaf_permissions


def uint(text):
    return int(text, 0)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('descriptor', type=uint, help='stage-1 leaf descriptor (block or page)')
    ap.add_argument('pperm', type=uint, help='SPRR_PPERM_EL1 value')
    ap.add_argument('uperm', type=uint, help='SPRR_UPERM_EL0 value')
    ap.add_argument('--world', choices=('ordinary', 'guarded'), default='ordinary')
    args = ap.parse_args(argv)
    try:
        view = leaf_permissions(args.descriptor, args.pperm, args.uperm, args.world)
    except ValueError as error:
        print('error: '+str(error), file=sys.stderr)
        return 2
    print(json.dumps(dict(descriptor=args.descriptor, pperm_el1=args.pperm, uperm_el0=args.uperm, **view),
                     indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
