from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from guest_pt import translate, validate_monitor_entry, PAGE, UnmappedAddress
from probe_fixtures import Tables, HIGH

class GuestPageTableTests(unittest.TestCase):
    def setUp(self):
        self.pages={a:bytearray(0x4000) for a in (0x4000,0x8000,0xc000)}
        struct.pack_into('<Q',self.pages[0x4000],0,0x8003)
        struct.pack_into('<Q',self.pages[0x8000],0,0xc003)
        struct.pack_into('<Q',self.pages[0xc000],0,0x20000703)

    def test_page_translation_preserves_offset(self):
        self.assertEqual(translate(0x1234,0x4000,0,self.pages.__getitem__)['pa'],0x20001234)

    def test_block_translation(self):
        struct.pack_into('<Q',self.pages[0x8000],0,0x40000701)
        result=translate(0x123456,0x4000,0,self.pages.__getitem__)
        self.assertEqual((result['pa'],result['level']),(0x40123456,2))

    def test_high_canonical_address_uses_ttbr1(self):
        struct.pack_into('<Q',self.pages[0x4000],2047*8,0x8003)
        struct.pack_into('<Q',self.pages[0x8000],2047*8,0xc003)
        struct.pack_into('<Q',self.pages[0xc000],2047*8,0x20000703)
        self.assertEqual(translate((1<<64)-1,0,0x4000,self.pages.__getitem__)['pa'],0x20003fff)

    def test_bad_addresses_and_unmapped_leaf_rejected(self):
        for va in (-1,1<<64,1<<47,0x4000):
            with self.assertRaises(ValueError):translate(va,0x4000,0,self.pages.__getitem__)

    def test_reader_enforces_owned_pages(self):
        struct.pack_into('<Q',self.pages[0x4000],0,0xdead0003)
        with self.assertRaises(KeyError):translate(0,0x4000,0,self.pages.__getitem__)

    def test_truncated_tables_at_each_level_fail(self):
        for address in self.pages:
            pages = dict(self.pages)
            pages[address] = bytes(PAGE-1)
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, 'Truncated'):
                translate(0, 0x4000, 0, pages.__getitem__)

    def test_root_address_tags_misalignment_and_overflow_are_not_masked(self):
        for root in (0, -1, 0x4001, 0x4000 | (1 << 42), 0x4000 | (1 << 48), 1 << 64):
            with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'root'):
                translate(0, root, 0, lambda _: self.fail('Must reject before reading RAM'))

    def test_out_of_range_descriptor_addresses_fail_at_each_level(self):
        for address in self.pages:
            original = struct.unpack_from('<Q', self.pages[address])[0]
            for bit in range(42, 48):
                struct.pack_into('<Q', self.pages[address], 0, original | (1 << bit))
                with self.subTest(address=address, bit=bit), self.assertRaisesRegex(ValueError, '42-bit'):
                    translate(0, 0x4000, 0, self.pages.__getitem__)
            struct.pack_into('<Q', self.pages[address], 0, original)

    def test_parent_permission_restrictions_accumulate(self):
        struct.pack_into('<Q', self.pages[0x4000], 0, 0x8003 | (1 << 59) | (1 << 61))
        struct.pack_into('<Q', self.pages[0x8000], 0, 0xc003 | (1 << 60) | (1 << 62))
        struct.pack_into('<Q', self.pages[0xc000], 0, 0x20000743)
        result = translate(0, 0x4000, 0, self.pages.__getitem__)
        self.assertTrue(result['pxn'])
        self.assertTrue(result['uxn'])
        self.assertTrue(result['read_only'])
        self.assertFalse(result['user_access'])

    def test_misaligned_block_is_rejected_instead_of_rounded_down(self):
        struct.pack_into('<Q', self.pages[0x8000], 0, 0x40004701)
        with self.assertRaisesRegex(ValueError, 'Misaligned block'):
            translate(0, 0x4000, 0, self.pages.__getitem__)

    def test_reserved_leaf_type_is_not_an_optional_unmapped_address(self):
        struct.pack_into('<Q', self.pages[0xc000], 0, 0x20000701)
        with self.assertRaisesRegex(ValueError, 'Unsupported descriptor') as error:
            translate(0, 0x4000, 0, self.pages.__getitem__)
        self.assertNotIsInstance(error.exception, UnmappedAddress)

    def test_no_level1_block_and_no_unbounded_recursive_walk(self):
        struct.pack_into('<Q', self.pages[0x4000], 0, 0x701)
        with self.assertRaisesRegex(ValueError, 'Unsupported descriptor'):
            translate(0, 0x4000, 0, self.pages.__getitem__)
        struct.pack_into('<Q', self.pages[0x4000], 0, 0x4003)
        calls = []
        def reader(address):
            calls.append(address)
            return self.pages[address]
        # A reused table page is not recursion: the walk has exactly 3 levels.
        self.assertEqual(translate(0, 0x4000, 0, reader)['pa'], 0x4000)
        self.assertEqual(calls, [0x4000]*3)


class MonitorEntryValidationTests(unittest.TestCase):
    def setUp(self):
        self.t = Tables()

    def check(self, **kwargs):
        values = dict(controls=self.t.controls, pc=self.t.pc, sp=self.t.sp,
                      bootargs=self.t.bootargs, base=self.t.base, size=self.t.size,
                      read_page=lambda address: self.t.memory.read(address, PAGE))
        values.update(kwargs)
        return validate_monitor_entry(**values)

    def test_valid_identity_code_nonidentity_stack_and_optional_bootargs(self):
        result = self.check()
        self.assertEqual(result['pc']['pa'], self.t.pc)
        self.assertEqual(result['stack']['pa'], self.t.base+0x83ff0)
        self.assertEqual(result['stack']['bytes'], 16)
        self.assertIn('unmapped', result['bootargs'])

    def test_table_walk_indices_across_both_va_ranges(self):
        offsets = (0, PAGE-1, PAGE, (1 << 25)-1, 1 << 25,
                   (1 << 36)-1, 1 << 36, (1 << 47)-1)
        for high in (0, HIGH):
            for offset in offsets:
                with self.subTest(high=high, offset=offset):
                    va, pa = high+offset, self.t.base+0x800000
                    self.t.map(va, pa)
                    translated = translate(va, self.t.low, self.t.high,
                                           lambda address: self.t.memory.read(address, PAGE))
                    self.assertEqual(translated['pa'], pa+(offset & (PAGE-1)))

    def test_profile_size_and_alignment_checks_happen_before_reads(self):
        cases = [dict(pc=self.t.pc+1), dict(sp=self.t.sp+1), dict(sp=0),
                 dict(sp=1 << 64), dict(base=-PAGE), dict(size=1),
                 dict(base=(1 << 42)-PAGE, size=2*PAGE),
                 dict(controls=dict(self.t.controls, tcr=0))]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.check(**kwargs)
        self.assertEqual(self.t.memory.reads, [])

    def test_table_outside_guest_allocation_is_not_read(self):
        self.t.put(self.t.pc_path[0], 0x4003)
        with self.assertRaisesRegex(ValueError, 'Table walk left'):
            self.check()
        self.assertNotIn((0x4000, PAGE), self.t.memory.reads)

    def test_missing_code_or_stack_cannot_use_bootargs_exception(self):
        for path in (self.t.pc_path, self.t.stack_path):
            location = path[-1]
            original = self.t.get(location)
            self.t.put(location, 0)
            with self.assertRaises(UnmappedAddress):
                self.check()
            self.t.put(location, original)

    def test_malformed_bootargs_mapping_is_fatal(self):
        location = self.t.map(self.t.bootargs, self.t.bootargs)[-1]
        for descriptor in (self.t.bootargs | 0x401, self.t.bootargs | 0x403 | (1 << 42)):
            self.t.put(location, descriptor)
            with self.subTest(descriptor=descriptor), self.assertRaises(ValueError) as error:
                self.check()
            self.assertNotIsInstance(error.exception, UnmappedAddress)

    def test_inaccessible_bootargs_table_is_fatal(self):
        # Put BootArgs in a distinct L2 branch and redirect its table outside RAM.
        bootargs = self.t.base+0x2000000
        path = self.t.map(bootargs, bootargs)
        self.t.put(path[1], 0x4003)
        with self.assertRaisesRegex(ValueError, 'Table walk left'):
            self.check(bootargs=bootargs)

    def test_parent_and_leaf_pxn_block_code(self):
        for index, bit in ((0, 59), (1, 59), (2, 53)):
            self.setUp()
            location = self.t.pc_path[index]
            self.t.put(location, self.t.get(location) | (1 << bit))
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'execute-never'):
                self.check()

    def test_parent_and_leaf_readonly_block_stack(self):
        for index, bit in ((0, 62), (1, 62), (2, 7)):
            self.setUp()
            location = self.t.stack_path[index]
            self.t.put(location, self.t.get(location) | (1 << bit))
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'not writable'):
                self.check()

    def test_el0_writable_code_is_privileged_execute_never(self):
        location = self.t.pc_path[-1]
        self.t.put(location, self.t.get(location) | (1 << 6))
        with self.assertRaisesRegex(ValueError, 'execute-never'):
            self.check()
        parent = self.t.pc_path[0]
        self.t.put(parent, self.t.get(parent) | (1 << 61))
        self.check()  # APTable restricts this mapping to privileged access.

    def test_pan_blocks_user_accessible_stack(self):
        location = self.t.stack_path[-1]
        self.t.put(location, self.t.get(location) | (1 << 6))
        self.check(pan=False)
        with self.assertRaisesRegex(ValueError, 'not writable'):
            self.check(pan=True)

    def test_af_required_for_each_mapped_entry_object(self):
        boot_path = self.t.map(self.t.bootargs, self.t.bootargs)
        for path in (self.t.pc_path, self.t.stack_path, boot_path):
            location = path[-1]
            old = self.t.get(location)
            self.t.put(location, old & ~(1 << 10))
            with self.assertRaisesRegex(ValueError, 'Access flag'):
                self.check()
            self.t.put(location, old)

    def test_pc_and_mapped_bootargs_must_remain_identity(self):
        for address in (self.t.pc, self.t.bootargs):
            self.setUp()
            self.t.map(address, self.t.base+0x800000)
            with self.assertRaisesRegex(ValueError, 'not identity'):
                self.check()

    def test_leaf_outside_owned_memory_and_device_entry_memory_fail(self):
        location = self.t.stack_path[-1]
        original = self.t.get(location)
        self.t.put(location, (original & ~((1 << 42)-PAGE)) | (self.t.base+self.t.size))
        with self.assertRaisesRegex(ValueError, 'leaves guest RAM'):
            self.check()
        # MAIR index 2 in the captured profile is device memory (0x00).
        self.t.put(location, original | (2 << 2))
        with self.assertRaisesRegex(ValueError, 'normal WB memory'):
            self.check()


PPERM = 0x2020a52a302abaf5
UPERM = 0x2010002030100000


class SprrMonitorEntryTests(unittest.TestCase):
    def setUp(self):
        self.t = Tables()
        self.sprr = dict(pperm=PPERM, uperm=UPERM)

    def check(self, **kwargs):
        values = dict(controls=self.t.controls, pc=self.t.pc, sp=self.t.sp,
                      bootargs=self.t.bootargs, base=self.t.base, size=self.t.size,
                      read_page=lambda address: self.t.memory.read(address, PAGE), sprr=self.sprr)
        values.update(kwargs)
        return validate_monitor_entry(**values)

    def test_default_mode_output_has_no_sprr_view(self):
        result = self.check(sprr=None)
        for name in ('pc', 'stack', 'bootargs'):
            self.assertNotIn('sprr', result[name])

    def test_recorded_registers_accept_fixture_and_report_both_views(self):
        result = self.check()
        pc, stack = result['pc'], result['stack']
        self.assertEqual(pc['sprr']['index'], 0)
        self.assertEqual(pc['sprr']['pperm_nibble'], 5)
        self.assertTrue(pc['sprr']['kernel_execute'] and not pc['sprr']['user_read'])
        self.assertFalse(pc['pxn'] or pc['uxn'] or pc['user_access'] or pc['read_only'])
        self.assertEqual(stack['sprr']['index'], 3)
        self.assertTrue(stack['sprr']['kernel_write'] and not stack['sprr']['kernel_execute'])
        self.assertTrue(stack['pxn'] and stack['uxn'])
        self.assertTrue(pc['sprr']['representable_natively'])
        self.assertFalse(pc['sprr']['hardware_validated'])
        self.assertIn('unmapped', result['bootargs'])

    def test_execute_decided_by_nibble_not_native_bits(self):
        location = self.t.pc_path[-1]
        original = self.t.get(location)
        self.t.put(location, original | (1 << 54))  # index 2 -> kernel R only
        self.check(sprr=None)
        with self.assertRaisesRegex(ValueError, 'execute-never: pc'):
            self.check()
        self.t.put(location, original | (1 << 53))  # index 1: natively PXN
        with self.assertRaisesRegex(ValueError, 'execute-never'):
            self.check(sprr=None)
        with self.assertRaisesRegex(ValueError, 'execute-never: pc'):
            self.check()
        executable_index1 = dict(self.sprr, pperm=(PPERM & ~(0xf << 4)) | (5 << 4))
        result = self.check(sprr=executable_index1)
        self.assertTrue(result['pc']['pxn'])
        self.assertTrue(result['pc']['sprr']['kernel_execute'])

    def test_stack_write_and_pan_use_effective_permissions(self):
        location = self.t.stack_path[-1]
        base = self.t.get(location) & ~(3 << 53)
        self.t.put(location, base | (1 << 54))  # index 2 -> kernel R only
        self.check(sprr=None)
        with self.assertRaisesRegex(ValueError, 'stack is not writable'):
            self.check()
        self.t.put(location, base | (3 << 53) | (1 << 6))  # index 7 -> kernel RW, user RW
        self.check(pan=False)
        with self.assertRaisesRegex(ValueError, 'user accessible under PAN'):
            self.check(pan=True)
        self.t.put(location, base | (1 << 7))  # index 8 -> kernel R
        with self.assertRaisesRegex(ValueError, 'stack is not writable'):
            self.check()

    def test_hierarchical_restriction_fails_closed(self):
        # UXNTable never blocks privileged execution natively, but its meaning
        # under SPRR is unknown, so the SPRR mode rejects it.
        parent = self.t.pc_path[0]
        self.t.put(parent, self.t.get(parent) | (1 << 60))
        self.check(sprr=None)
        with self.assertRaisesRegex(ValueError, 'Hierarchical.*pc'):
            self.check()

    def test_unrepresentable_pair_fails_closed(self):
        execute_only = dict(self.sprr, pperm=(PPERM & ~0xf) | 9)
        with self.assertRaisesRegex(ValueError, 'not natively representable: pc'):
            self.check(sprr=execute_only)

    def test_guarded_world_and_malformed_state_rejected_before_reads(self):
        cases = [dict(self.sprr, world='guarded'), dict(pperm=PPERM), dict(pperm=-1, uperm=0),
                 dict(pperm=PPERM, uperm=1 << 64), dict(self.sprr, extra=1), 'state', (PPERM, UPERM)]
        for sprr in cases:
            with self.subTest(sprr=sprr), self.assertRaises(ValueError):
                self.check(sprr=sprr)
        self.assertEqual(self.t.memory.reads, [])

    def test_bootargs_mapping_reports_view_without_access_requirements(self):
        self.t.map(self.t.bootargs, self.t.bootargs, flags=0x403 | (1 << 6) | (1 << 54))  # index 6
        result = self.check()
        view = result['bootargs']['sprr']
        self.assertEqual((view['kernel_rwx'], view['user_rwx']), (0, 0))
        self.assertTrue(view['representable_natively'])
        self.assertIsNone(view['leaf_permission_bits'])
        self.assertTrue(result['bootargs']['user_access'])
