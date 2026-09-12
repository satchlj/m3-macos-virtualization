import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('guest_payload', Path(__file__).resolve().parents[1] / 'scripts/inspect_guest_payload.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(name='__TEXT', entry=0x1000):
    segment = struct.pack('<II16s4Q4I', 0x19, 72, name.encode(), 0x1000, 0x1000, 0, 0, 5, 5, 0, 0)
    state = bytearray(272)
    struct.pack_into('<Q', state, 256, entry)
    thread = struct.pack('<4I', 5, 288, 6, 68) + state
    commands = segment + thread
    return struct.pack('<8I', 0xfeedfacf, 0x100000c, 2, 12, 2, len(commands), 0, 0) + commands


class PayloadTests(unittest.TestCase):
    def test_ordinary_entry_is_unknown_not_ready(self):
        result = module.inspect(fixture())
        self.assertEqual(result['direct_loader_contract'], 'unknown')
        self.assertFalse(result['guest_boot_verified'])

    def test_boot_exec_marker_blocks_direct_entry(self):
        result = module.inspect(fixture('__TEXT_BOOT_EXEC'))
        self.assertEqual(result['direct_loader_contract'], 'blocked-pending-monitor-contract')

    def test_sptm_data_marker_blocks_direct_entry(self):
        self.assertTrue(module.inspect(fixture('__DATA_SPTM'))['sptm_data_segment_present'])

    def test_entry_outside_segments_rejected(self):
        with self.assertRaises(ValueError):
            module.inspect(fixture(entry=0x3000))

    def test_truncated_commands_rejected(self):
        with self.assertRaises(ValueError):
            module.inspect(fixture()[:-1])

    def test_zero_command_length_rejected(self):
        data = bytearray(fixture())
        struct.pack_into('<I', data, 36, 0)
        with self.assertRaises(ValueError):
            module.inspect(data)

    def test_invalid_thread_state_size_rejected(self):
        data = bytearray(fixture())
        struct.pack_into('<I', data, 116, 67)
        with self.assertRaises(ValueError):
            module.inspect(data)

    def test_unconsumed_commands_rejected(self):
        data = bytearray(fixture())
        struct.pack_into('<I', data, 16, 1)
        with self.assertRaises(ValueError):
            module.inspect(data)
