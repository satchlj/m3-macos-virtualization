import itertools
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from sprr_permissions import R,W,X,exact_leaf,ordinary_access,audit


class SprrPermissionTests(unittest.TestCase):
    def test_read_write_execute_and_privilege_constraints(self):
        for kernel,user in [(R,R|W),(0,R),(X,0),(R|W,R),(R|X,R|W|X)]:
            with self.subTest(kernel=kernel,user=user),self.assertRaises(ValueError):
                exact_leaf(kernel,user)
        self.assertIsNone(exact_leaf(0,0))
        for pair in [(R,0),(R|W,0),(R|X,R),(R|W|X,R|W),(R|X,R|X)]:
            self.assertEqual(ordinary_access(exact_leaf(*pair)),pair)

    def test_exhaustive_no_overgrant_or_undergrant(self):
        representable={(0,0)}
        # Independent architectural access construction for ordinary AP/PXN/UXN.
        for user,readonly,kexec,uexec in itertools.product((False,True),repeat=4):
            k=R | (0 if readonly else W) | (X if kexec else 0)
            u=(R | (0 if readonly else W) | (X if uexec else 0)) if user else 0
            representable.add((k,u))
        for pair in itertools.product(range(8),repeat=2):
            if pair in representable:
                self.assertEqual(ordinary_access(exact_leaf(*pair)),pair)
            else:
                with self.assertRaises(ValueError):exact_leaf(*pair)

    def test_guarded_world_differs_and_execute_only_rejects(self):
        self.assertFalse(audit(9,0)['indices'][0]['representable'])
        self.assertEqual(audit(9,0,True)['indices'][0]['kernel_rwx'],R)
        self.assertTrue(audit(9,0,True)['indices'][0]['representable'])
        self.assertFalse(audit(9,0)['hardware_validated'])


from sprr_permissions import (leaf_permissions, leaf_index, SPRR_IDX_PXN, SPRR_IDX_UXN,
                              SPRR_IDX_AP_EL0, SPRR_IDX_AP_RO)

# Recorded on hardware when SPTM enabled SPRR (see docs/sprr-leaf-permissions.md).
PPERM = 0x2020a52a302abaf5
UPERM = 0x2010002030100000


def descriptor_for(index):
    """Build a valid page leaf whose AP[2:1]/UXN/PXN encode the given index."""
    return (0x403 | (index & 1) << 53 | ((index >> 1) & 1) << 54 |
            ((index >> 2) & 1) << 6 | ((index >> 3) & 1) << 7)


class SprrLeafPermissionTests(unittest.TestCase):
    def test_index_layout_matches_upstream_bit_assignment(self):
        self.assertEqual((SPRR_IDX_PXN, SPRR_IDX_UXN, SPRR_IDX_AP_EL0, SPRR_IDX_AP_RO), (1, 2, 4, 8))
        for bit, index in ((53, 1), (54, 2), (6, 4), (7, 8)):
            self.assertEqual(leaf_index(0x403 | 1 << bit), index)
        self.assertEqual(leaf_index(0x403 | 3 << 53 | 3 << 6), 15)
        # Other attribute bits do not contribute to the index.
        self.assertEqual(leaf_index(0x403 | 1 << 10 | 1 << 52 | 1 << 55 | 1 << 5 | 1 << 8), 0)
        for index in range(16):
            self.assertEqual(leaf_permissions(descriptor_for(index), PPERM, UPERM)['index'], index)

    def test_recorded_registers_exhaustive_ordinary_world(self):
        # Independently hand-decoded from the recorded values with sprr_el_rwx.
        kernel = [R|X, R|W, R, R|W, R, R, 0, R|W, R, R, R|X, R, 0, R, 0, R]
        user = [0, 0, 0, 0, 0, R|X, 0, R|W, 0, R, 0, 0, 0, R|X, 0, R]
        for index in range(16):
            with self.subTest(index=index):
                view = leaf_permissions(descriptor_for(index), PPERM, UPERM)
                self.assertEqual(view['world'], 'ordinary')
                self.assertEqual(view['pperm_nibble'], (PPERM >> (index*4)) & 15)
                self.assertEqual(view['uperm_nibble'], (UPERM >> (index*4)) & 15)
                self.assertEqual((view['kernel_rwx'], view['user_rwx']), (kernel[index], user[index]))
                self.assertEqual([view[k] for k in ('kernel_read', 'kernel_write', 'kernel_execute')],
                                 [bool(kernel[index] & m) for m in (R, W, X)])
                self.assertEqual([view[k] for k in ('user_read', 'user_write', 'user_execute')],
                                 [bool(user[index] & m) for m in (R, W, X)])
                self.assertTrue(view['representable_natively'])
                self.assertEqual(view['leaf_permission_bits'],
                                 audit(PPERM, UPERM)['indices'][index]['leaf_permission_bits'])
                self.assertFalse(view['hardware_validated'])
                self.assertEqual(view['index_bits'], dict(pxn=bool(index & 1), uxn=bool(index & 2),
                                                          ap_el0=bool(index & 4), ap_ro=bool(index & 8)))

    def test_recorded_registers_exhaustive_guarded_world(self):
        kernel = [R|X, R|W, R, R, R, 0, 0, 0, R, 0, R|X, R, 0, 0, 0, 0]
        for index in range(16):
            with self.subTest(index=index):
                view = leaf_permissions(descriptor_for(index), PPERM, UPERM, 'guarded')
                self.assertEqual(view['world'], 'guarded')
                self.assertEqual((view['kernel_rwx'], view['user_rwx']), (kernel[index], 0))
                self.assertFalse(view['user_read'] or view['user_write'] or view['user_execute'])
                self.assertTrue(view['representable_natively'])
                self.assertEqual(view['leaf_permission_bits'],
                                 audit(PPERM, UPERM, True)['indices'][index]['leaf_permission_bits'])

    def test_native_looking_user_access_is_not_sprr_user_access(self):
        # AP[1] set reads natively as EL0 RW; under the recorded SPRR values
        # index 4 is kernel read-only with no user access at all.
        view = leaf_permissions(descriptor_for(4), PPERM, UPERM)
        self.assertEqual(view['native'], dict(read_only=False, user_access=True, pxn=False, uxn=False))
        self.assertEqual((view['kernel_rwx'], view['user_rwx']), (R, 0))
        # Index 3 (PXN|UXN) is natively privileged RW execute-never and stays kernel RW.
        view = leaf_permissions(descriptor_for(3), PPERM, UPERM)
        self.assertTrue(view['native']['pxn'] and view['native']['uxn'])
        self.assertTrue(view['kernel_write'] and not view['kernel_execute'])

    def test_unrepresentable_pairs_and_invalid_inputs(self):
        view = leaf_permissions(0x403, 9, 0)  # nibble 9: execute-only kernel
        self.assertEqual(view['kernel_rwx'], X)
        self.assertFalse(view['representable_natively'])
        self.assertIn('cannot be represented', view['reason'])
        self.assertNotIn('leaf_permission_bits', view)
        view = leaf_permissions(0x403, 0, 0)
        self.assertTrue(view['representable_natively'])
        self.assertIsNone(view['leaf_permission_bits'])
        for args in ((0x402, PPERM, UPERM), (0x403, PPERM, UPERM, 'gl'), (-1, 0, 0),
                     (1 << 64, 0, 0), (0x403, 1 << 64, 0), (0x403, 0, '0'), (True, 0, 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                leaf_permissions(*args)
