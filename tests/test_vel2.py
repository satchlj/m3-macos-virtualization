"""Tests the experimental C engine on the host; never opens target devices."""
import ctypes as C
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

CHECKOUT = os.environ.get('VEL2_CHECKOUT')
U64 = C.c_uint64


class State(C.Structure):
    _fields_ = [('regs', U64 * 13), ('pstate', U64), ('sp_el2', U64), ('enabled', C.c_bool)]


class Frame(C.Structure):
    _fields_ = [('x', U64 * 32), ('pc', U64), ('pstate', U64), ('sp', U64)]


@unittest.skipUnless(CHECKOUT, 'Set VEL2_CHECKOUT to the patched experimental checkout')
class VirtualEL2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        output = Path(cls.tmp.name) / 'vel2.so'
        compiler = shutil.which('clang') or shutil.which('cc')
        if not compiler:
            raise RuntimeError('A host C compiler is required')
        subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                        str(Path(CHECKOUT) / 'src/vel2_state.c'), '-o', str(output)], check=True)
        cls.lib = C.CDLL(str(output))
        cls.lib.vel2_reset.argtypes = [C.POINTER(State), C.c_bool]
        cls.lib.vel2_handle.argtypes = [C.POINTER(State), C.POINTER(Frame), C.c_uint16]
        cls.lib.vel2_handle.restype = C.c_int
        proxy = str(Path(CHECKOUT) / 'proxyclient')
        sys.path.insert(0, proxy)
        cls.addClassCleanup(lambda: sys.path.remove(proxy))
        spec = importlib.util.spec_from_file_location('m1n1.hv.vel2', Path(proxy) / 'm1n1/hv/vel2.py')
        cls.patch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.patch)

    def setUp(self):
        self.state = State()
        self.frame = Frame(pc=0x1004, pstate=0x3c5, sp=0x8000)
        self.lib.vel2_reset(C.byref(self.state), True)

    def call(self, imm):
        return self.lib.vel2_handle(C.byref(self.state), C.byref(self.frame), imm)

    def reg(self, index, read=False, rt=0):
        return self.call(0x4000 | index << 6 | int(read) << 5 | rt)

    def test_reset_starts_at_virtual_el2(self):
        self.assertEqual(self.reg(0, True), 0)
        self.assertEqual(self.frame.x[0], 8)
        self.assertEqual(self.frame.pstate & 15, 5)

    def test_disabled_rejects_without_changes(self):
        self.lib.vel2_reset(C.byref(self.state), False)
        before = bytes(self.state), bytes(self.frame)
        self.assertEqual(self.reg(0, True), 1)
        self.assertEqual(before, (bytes(self.state), bytes(self.frame)))

    def test_register_round_trip_preserves_full_width(self):
        self.frame.x[3] = 0xfedcba9876543210
        self.assertEqual(self.reg(11, rt=3), 0)
        self.assertEqual(self.reg(11, True, rt=4), 0)
        self.assertEqual(self.frame.x[4], 0xfedcba9876543210)

    def test_xzr_write_is_zero_and_read_is_discarded(self):
        self.frame.x[31] = 0xdead
        self.assertEqual(self.reg(11, rt=31), 0)
        self.assertEqual(self.state.regs[11], 0)
        self.assertEqual(self.reg(0, True, rt=31), 0)
        self.assertEqual(self.frame.x[31], 0xdead)

    def test_read_only_and_unknown_register_rejected(self):
        self.assertEqual(self.reg(0), 2)
        self.assertEqual(self.reg(31, True), 2)

    def test_mmu_enable_rejected_transactionally(self):
        for bit in (1, 4, 4096):
            self.frame.x[0] = bit
            before = bytes(self.state), bytes(self.frame)
            self.assertEqual(self.reg(1), 3)
            self.assertEqual(before, (bytes(self.state), bytes(self.frame)))

    def test_hcr_enable_rejected(self):
        self.frame.x[0] = 1
        self.assertEqual(self.reg(4), 3)
        self.assertEqual(self.state.regs[4], 0)

    def test_vector_alignment_rejected(self):
        self.frame.x[0] = 0x8100
        self.assertEqual(self.reg(5), 2)

    def enter_el1(self):
        self.state.regs[6] = 0x2000
        self.state.regs[7] = 0xa0000005
        self.state.regs[10] = 0x9000
        self.assertEqual(self.call(0x4800), 0)

    def test_eret_switches_stack_and_preserves_flags(self):
        self.enter_el1()
        self.assertEqual(self.frame.pc, 0x2000)
        self.assertEqual(self.frame.sp, 0x9000)
        self.assertEqual(self.state.sp_el2, 0x8000)
        self.assertEqual(self.frame.pstate, 0xa00003c5)
        self.assertEqual(self.reg(0, True), 0)
        self.assertEqual(self.frame.x[0], 4)

    def test_lower_el_cannot_access_el2_register(self):
        self.enter_el1()
        self.assertEqual(self.reg(11, True), 2)
        self.assertEqual(self.call(0x4800), 2)

    def test_hvc_round_trip(self):
        self.state.regs[5] = 0x4000
        self.enter_el1()
        self.frame.pc = 0x2004
        self.frame.sp = 0x8ff0
        self.frame.pstate = 0x600003c5
        self.assertEqual(self.call(0x42), 0)
        self.assertEqual(self.frame.pc, 0x4400)
        self.assertEqual(self.frame.sp, 0x8000)
        self.assertEqual(self.state.regs[8], 0x5a000042)
        self.assertEqual(self.state.regs[7], 0x60000005)
        self.assertEqual(self.state.regs[6], 0x2004)
        self.assertEqual(self.reg(0, True), 0)
        self.assertEqual(self.frame.x[0], 8)
        self.assertEqual(self.call(0x4800), 0)
        self.assertEqual(self.frame.pc, 0x2004)
        self.assertEqual(self.frame.sp, 0x8ff0)

    def test_unsupported_return_mode_leaves_state_unchanged(self):
        self.state.regs[7] = 0xd
        before = bytes(self.state), bytes(self.frame)
        self.assertEqual(self.call(0x4800), 3)
        self.assertEqual(before, (bytes(self.state), bytes(self.frame)))

    def test_unaligned_return_pc_rejected(self):
        self.state.regs[7] = 5
        self.state.regs[6] = 3
        self.assertEqual(self.call(0x4800), 2)

    def test_stop_does_not_reflect_as_guest_exception(self):
        self.enter_el1()
        before = bytes(self.state), bytes(self.frame)
        self.assertEqual(self.call(0x7fff), 3)
        self.assertEqual(before, (bytes(self.state), bytes(self.frame)))

    def test_actual_translator_to_actual_c_engine(self):
        for i, reg in enumerate(self.patch.REGISTERS):
            word = self.patch.sysreg_opcode(reg, True) | 7
            out = self.patch.patch_synthetic_code(struct.pack('<I', word))
            encoded = struct.unpack('<I', out)[0]
            self.assertEqual(encoded & 0xffe0001f, 0xd4000002)
            imm = (encoded >> 5) & 0xffff
            self.assertEqual(imm, 0x4000 | i << 6 | 0x20 | 7)
            self.assertEqual(self.call(imm), 0)

    def test_eret_translation_and_noninstruction_preservation(self):
        code = struct.pack('<II', 0xd69f03e0, 0xd503201f)
        result = self.patch.patch_synthetic_code(code)
        self.assertEqual(struct.unpack('<II', result), (0xd4000002 | 0x4800 << 5, 0xd503201f))
        with self.assertRaises(ValueError):
            self.patch.patch_synthetic_code(b'\0')

    def configure_mmu(self):
        self.state.regs[2] = 0x8083b516
        self.state.regs[3] = 0x10000004000
        self.state.regs[12] = 0xff

    def test_mmu_enable_requires_supported_complete_config(self):
        self.configure_mmu()
        self.frame.x[0] = 1
        self.assertEqual(self.reg(1), 0)
        self.assertEqual(self.state.regs[1], 1)
        self.frame.x[0] = 0
        self.assertEqual(self.reg(1), 0)

    def test_mmu_rejects_invalid_root_and_tcr_without_changes(self):
        for reg, value in [(2, 0), (2, 0x80833516), (3, 0), (3, 0x10000004001),
                           (3, 1 << 42), (12, 0)]:
            self.configure_mmu()
            self.state.regs[reg] = value
            self.frame.x[0] = 1
            before = bytes(self.state), bytes(self.frame)
            self.assertEqual(self.reg(1), 3)
            self.assertEqual(before, (bytes(self.state), bytes(self.frame)))

    def test_mmu_rejects_context_switch_and_live_configuration(self):
        self.configure_mmu()
        self.frame.x[0] = 1
        self.assertEqual(self.reg(1), 0)
        for reg in [2, 3, 12]:
            before = bytes(self.state), bytes(self.frame)
            self.assertEqual(self.reg(reg), 3)
            self.assertEqual(before, (bytes(self.state), bytes(self.frame)))
        self.state.regs[6] = 0x4000
        self.state.regs[7] = 0x3c5
        before = bytes(self.state), bytes(self.frame)
        self.assertEqual(self.call(0x4800), 3)
        self.assertEqual(before, (bytes(self.state), bytes(self.frame)))

    def test_vhe_mmu_requires_vhe_tcr_format(self):
        self.configure_mmu()
        self.frame.x[0] = 0x408000000
        self.assertEqual(self.reg(4), 0)
        self.frame.x[0] = 1
        self.assertEqual(self.reg(1), 3)
        self.state.regs[2] = 0x34096b516
        self.assertEqual(self.reg(1), 0)
        self.frame.x[0] = 0
        self.assertEqual(self.reg(4), 3)
        self.assertEqual(self.state.regs[4], 0x408000000)

    def test_vhe_tge_rejects_lower_el_entry(self):
        self.state.regs[4] = 0x408000000
        self.state.regs[6] = 0x4000
        self.state.regs[7] = 0x3c5
        before = bytes(self.state), bytes(self.frame)
        self.assertEqual(self.call(0x4800), 3)
        self.assertEqual(before, (bytes(self.state), bytes(self.frame)))

    def test_hvc_eret_roundtrips_all_nzcv_and_virtual_interrupt_masks(self):
        for flags in range(16):
            for masks in range(16):
                with self.subTest(flags=flags, masks=masks):
                    self.setUp()
                    target = (flags << 28) | (masks << 6) | 5
                    self.state.regs[5] = 0x4000
                    self.state.regs[6] = 0x2000
                    self.state.regs[7] = target
                    self.state.regs[10] = 0x9000
                    self.frame.x[8] = 0x123456789abcdef0
                    self.assertEqual(self.call(0x4800), 0)
                    self.assertEqual(self.frame.pstate, (flags << 28) | 0x3c5)
                    # Simulate a lower-world instruction changing condition flags.
                    new_flags = (15-flags) << 28
                    self.frame.pstate = new_flags | 0x3c5
                    self.frame.pc, self.frame.sp = 0x2014, 0x8ff0
                    self.assertEqual(self.call(0x1234), 0)
                    self.assertEqual(self.state.regs[6], 0x2014)
                    self.assertEqual(self.state.regs[7], new_flags | (masks << 6) | 5)
                    self.assertEqual(self.state.regs[8], 0x5a001234)
                    self.assertEqual((self.frame.pc, self.frame.sp), (0x4400, 0x8000))
                    self.assertEqual(self.call(0x4800), 0)
                    self.assertEqual((self.frame.pc, self.frame.sp), (0x2014, 0x8ff0))
                    self.assertEqual(self.frame.pstate, new_flags | 0x3c5)
                    self.assertEqual(self.frame.x[8], 0x123456789abcdef0)

    def test_same_level_el2_eret_retains_stack_and_forces_physical_masks(self):
        self.state.regs[6], self.state.regs[7] = 0x3000, 0xb0000009
        self.state.regs[10] = 0xdead0000
        self.assertEqual(self.call(0x4800), 0)
        self.assertEqual((self.frame.pc, self.frame.sp), (0x3000, 0x8000))
        self.assertEqual(self.frame.pstate, 0xb00003c5)
        self.assertEqual(self.reg(0, True, rt=12), 0)
        self.assertEqual(self.frame.x[12], 8)

    def test_eret_rejects_all_unsupported_pstate_fields_transactionally(self):
        allowed = 0xf00003cf
        for bit in range(64):
            if allowed & (1 << bit):
                continue
            self.state.regs[6], self.state.regs[7] = 0x2000, 5 | (1 << bit)
            before = bytes(self.state), bytes(self.frame)
            with self.subTest(bit=bit):
                self.assertEqual(self.call(0x4800), 3)
                self.assertEqual(before, (bytes(self.state), bytes(self.frame)))
        for mode in set(range(16))-{5, 9}:
            self.state.regs[7] = mode
            before = bytes(self.state), bytes(self.frame)
            with self.subTest(mode=mode):
                self.assertEqual(self.call(0x4800), 3)
                self.assertEqual(before, (bytes(self.state), bytes(self.frame)))

    def test_nested_hvc_from_virtual_el2_is_not_injected_into_itself(self):
        self.state.regs[5] = 0x4000
        before = bytes(self.state), bytes(self.frame)
        self.assertEqual(self.call(0x1234), 3)
        self.assertEqual(before, (bytes(self.state), bytes(self.frame)))

    def test_lower_hvc_rejects_absent_or_overflowing_vector_transactionally(self):
        self.enter_el1()
        for vector in (0, (1 << 64)-0x400):
            self.state.regs[5] = vector
            before = bytes(self.state), bytes(self.frame)
            self.assertEqual(self.call(0x1234), 2)
            self.assertEqual(before, (bytes(self.state), bytes(self.frame)))

    def test_repeated_roundtrips_keep_latest_lower_stack(self):
        self.state.regs[5] = 0x4000
        self.enter_el1()
        for index in range(16):
            pc, sp = 0x2004+4*index, 0x9000-16*index
            self.frame.pc, self.frame.sp = pc, sp
            self.assertEqual(self.call(index), 0)
            self.assertEqual(self.frame.sp, 0x8000)
            self.assertEqual(self.call(0x4800), 0)
            self.assertEqual((self.frame.pc, self.frame.sp), (pc, sp))

    def test_reset_discards_translation_and_exception_state(self):
        self.configure_mmu()
        self.frame.x[0] = 1
        self.assertEqual(self.reg(1), 0)
        self.state.sp_el2 = 0xfedcba
        self.lib.vel2_reset(C.byref(self.state), False)
        self.assertFalse(self.state.enabled)
        self.assertEqual(list(self.state.regs), [0]*13)
        self.assertEqual(self.state.sp_el2, 0)
        self.assertEqual(self.state.pstate, 0x3c9)

    def test_native_live_identical_controls_remain_conservatively_unsupported(self):
        self.configure_mmu()
        self.frame.x[0] = 1
        self.assertEqual(self.reg(1), 0)
        for reg in (2, 3, 4, 12):
            self.frame.x[0] = self.state.regs[reg]
            before = bytes(self.state), bytes(self.frame)
            self.assertEqual(self.reg(reg), 3)
            self.assertEqual(before, (bytes(self.state), bytes(self.frame)))
