from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from free_run_watchdog import FreeRunWatchdog, GuestUnresponsive, CallbackUnresponsive


class WatchdogTests(unittest.TestCase):
    def fixture(self):
        now = [0.0]
        writes = []
        def read(size):
            now[0] += 0.25
            return b''
        iface = SimpleNamespace(dev=SimpleNamespace(read=read, write=writes.append, timeout=3),
                                handle_boot=lambda data: None)
        return now, writes, iface, FreeRunWatchdog(iface, 1, grace=1, clock=lambda: now[0])

    def test_no_response_kicks_once_then_abandons_and_restores(self):
        now, writes, iface, watchdog = self.fixture()
        original = iface.dev.read
        with self.assertRaises(GuestUnresponsive):
            watchdog.run(lambda: iface.dev.read(1))
        self.assertEqual(writes, [b'!'])
        self.assertIs(iface.dev.read, original)
        self.assertEqual(iface.dev.timeout, 3)
        self.assertFalse(watchdog.returned)

    def test_callback_transactions_are_never_kicked_after_guest_deadline(self):
        now, writes, iface, watchdog = self.fixture()
        def read(size):
            self.assertEqual(iface.dev.timeout, 0.25)
            return b'reply'
        iface.dev.read = read
        def handler(data):
            now[0] = 4
            self.assertEqual(iface.dev.timeout, 3)
            self.assertEqual(iface.dev.read(10), b'reply')
            self.assertEqual(iface.dev.timeout, 3)
        iface.handle_boot = handler
        watchdog.run(lambda: iface.handle_boot(b'callback'))
        self.assertEqual(writes, [])
        self.assertTrue(watchdog.returned)

    def test_callback_infinite_timeout_is_bounded_and_wrappers_restored(self):
        now, writes, iface, watchdog = self.fixture()
        iface.dev.timeout = None  # hv_start may leave nested callback reads infinite
        original_read, original_write = iface.dev.read, iface.dev.write
        iface.handle_boot = lambda data: iface.dev.read(24)
        original_boot = iface.handle_boot
        with self.assertRaises(CallbackUnresponsive):
            watchdog.run(lambda: iface.handle_boot(b'callback'))
        self.assertEqual(now[0], 3)
        self.assertEqual(writes, [])
        self.assertIsNone(iface.dev.timeout)
        self.assertIs(iface.dev.read, original_read)
        self.assertIs(iface.dev.write, original_write)
        self.assertIs(iface.handle_boot, original_boot)
        self.assertFalse(watchdog.returned)
        self.assertTrue(watchdog.status()['callback_read_timed_out'])

    def test_caught_callback_timeout_blocks_cleanup_commands_and_still_escapes(self):
        now, writes, iface, watchdog = self.fixture()
        def handler(data):
            try:
                iface.dev.read(24)
            except Exception:
                # Model stopped() attempting batch.disable() and p.exit() in
                # its finally block after a failed guarded-bank read.
                for command in (b'batch-disable', b'exit-guest'):
                    with self.assertRaises(CallbackUnresponsive):
                        iface.dev.write(command)
                with self.assertRaises(CallbackUnresponsive):
                    iface.dev.read(1)
        iface.handle_boot = handler
        with self.assertRaises(CallbackUnresponsive):
            watchdog.run(lambda: iface.handle_boot(b'callback'))
        self.assertEqual(writes, [])
        self.assertFalse(watchdog.kicked)
        self.assertFalse(watchdog.returned)

    def test_callback_partial_response_preserves_progress_without_kick(self):
        now, writes, iface, watchdog = self.fixture()
        pieces = iter((b'', b'ab', b'', b'cd'))
        def read(size):
            now[0] += 0.25
            return next(pieces)
        iface.dev.read = read
        iface.handle_boot = lambda data: iface.dev.read(4) + iface.dev.read(2)
        self.assertEqual(watchdog.run(lambda: iface.handle_boot(b'callback')), b'abcd')
        self.assertEqual(writes, [])

    def test_clean_response_after_kick(self):
        now, writes, iface, watchdog = self.fixture()
        def read(size):
            now[0] += 0.25
            return b'x' if writes else b''
        iface.dev.read = read
        self.assertEqual(watchdog.run(lambda: iface.dev.read(1)), b'x')
        self.assertEqual(writes, [b'!'])
        self.assertTrue(watchdog.returned)

    def test_busy_output_still_obeys_deadline(self):
        now, writes, iface, watchdog = self.fixture()
        def read(size):
            now[0] += 0.25
            return b'x'
        iface.dev.read = read
        def launch():
            while True:
                iface.dev.read(1)
        with self.assertRaises(GuestUnresponsive):
            watchdog.run(launch)
        self.assertEqual(writes, [b'!'])
