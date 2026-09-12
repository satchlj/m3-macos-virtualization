from pathlib import Path
from datetime import datetime, timezone
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from fresh_gate_receipt import (  # noqa: E402
    ReceiptError, acquire_device_lock, consume_receipt, create_key, issue_receipt,
)
from run_manifest import file_identity  # noqa: E402
import run_fresh_gate as fresh_gate_runner  # noqa: E402
from run_fresh_gate import gate_commands  # noqa: E402
from run_probe_pipeline import consume_pipeline_receipt, validate_gate_selection  # noqa: E402


class FreshGateReceiptTests(unittest.TestCase):
    NOW = 1_800_000_000
    NONCE = '31' * 32

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root/'key'
        create_key(self.key)
        (self.root/'build').mkdir()
        self.image = self.root/'build/m1n1.bin'
        self.elf = self.root/'build/m1n1-raw.elf'
        self.image.write_bytes(b'runtime-image')
        self.elf.write_bytes(b'runtime-elf')
        capture = self.root/'boot-data-0.bin'
        capture.write_bytes(b'[AFK preserved boot inputs')
        self.chainload = self.root/'chainload.json'
        self.transition = self.root/'transition.json'
        self.batch = self.root/'batch.json'
        self._write(self.chainload, {
            'scope': 'fresh-baseline-ram-chainload',
            'phase': 'proxy-returned',
            'fresh_gate_nonce': self.NONCE,
            'installed_boot_object_changed': False,
            'image': file_identity(self.image),
            'boot_copies': {
                'entries': [{'name': 'RTBuddySeg'}],
                'spans': [{'capture': file_identity(capture)}],
            },
        })
        self._write(self.transition, {
            'case': 'transition', 'hardware_executed': True, 'passed': True,
            'proxy_alive_after_exit': True, 'fresh_gate_nonce': self.NONCE,
            'image_sections': {'.init': True, '.text': True, '.rodata': True},
            'checks': {'stop': True, **{
                'x{}'.format(index): True for index in range(10, 21)}},
        })
        self._write(self.batch, {
            'scope': 'synthetic-native-step-batch', 'capacity': 256,
            'hardware_executed': True, 'passed': True,
            'proxy_alive_after_exit': True, 'fresh_gate_nonce': self.NONCE,
            'image_sections': {'.init': True, '.text': True, '.rodata': True},
            'checks': {name: True for name in (
                'step_count', 'step_pcs', 'step_values', 'terminal_hvc',
                'terminal_value', 'native_capture', 'clean_return')},
        })
        self._set_report_times(self.NOW)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _write(path, value):
        path.write_text(json.dumps(value)+'\n')

    @staticmethod
    def _timestamp(value):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()

    def _set_report_times(self, now):
        for path, start, end in (
                (self.chainload, now-6, now-5),
                (self.transition, now-4, now-3),
                (self.batch, now-2, now-1)):
            report = json.loads(path.read_text())
            report.update(started_at=self._timestamp(start),
                          ended_at=self._timestamp(end))
            self._write(path, report)

    def _issue(self, name='receipt.json', refresh_times=True, **changes):
        args = dict(
            output=self.root/name, key_path=self.key, nonce=self.NONCE,
            device='/dev/test', chainload_report=self.chainload,
            transition_report=self.transition, batch_report=self.batch,
            runtime_image=self.image, runtime_elf=self.elf,
            ttl_seconds=600, now=self.NOW)
        args.update(changes)
        if refresh_times:
            self._set_report_times(args['now'])
        issue_receipt(**args)
        return args['output']

    def _consume(self, receipt, **changes):
        args = dict(
            receipt_path=receipt, key_path=self.key,
            expected_device='/dev/test',
            expected_runtime_image=self.image, expected_runtime_elf=self.elf,
            now=self.NOW + 1)
        args.update(changes)
        return consume_receipt(**args)

    def test_valid_receipt_is_authenticated_and_one_use(self):
        receipt = self._issue()
        record = self._consume(receipt)
        self.assertEqual(record['nonce'], self.NONCE)
        self.assertEqual(record['receipt_sha256'], file_identity(receipt)['sha256'])
        marker = self.key.with_name(self.key.name+'.used')/(self.NONCE+'.json')
        self.assertTrue(marker.is_file())
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ReceiptError, 'already consumed'):
            self._consume(receipt)

    def test_copy_cannot_bypass_global_consumption_ledger(self):
        receipt = self._issue()
        copied = self.root/'copied.json'
        copied.write_bytes(receipt.read_bytes())
        self._consume(receipt)
        with self.assertRaisesRegex(ReceiptError, 'already consumed'):
            self._consume(copied)

    def test_tamper_wrong_device_expiry_and_runtime_drift_fail_closed(self):
        receipt = self._issue()
        changed = json.loads(receipt.read_text())
        changed['device'] = '/dev/other'
        self._write(receipt, changed)
        with self.assertRaisesRegex(ReceiptError, 'authentication failed'):
            self._consume(receipt)

        receipt = self._issue('device.json')
        with self.assertRaisesRegex(ReceiptError, 'device mismatch'):
            self._consume(receipt, expected_device='/dev/other')
        receipt = self._issue('expired.json')
        with self.assertRaisesRegex(ReceiptError, 'not currently valid'):
            self._consume(receipt, now=self.NOW + 601)
        receipt = self._issue('drift.json')
        self.elf.write_bytes(b'changed-after-gate')
        with self.assertRaisesRegex(ReceiptError, 'runtime_elf mismatch'):
            self._consume(receipt)
        marker = self.key.with_name(self.key.name+'.used')/(self.NONCE+'.json')
        self.assertFalse(marker.exists())

    def test_evidence_must_share_nonce_and_pass_every_gate(self):
        report = json.loads(self.transition.read_text())
        report['fresh_gate_nonce'] = '42' * 32
        self._write(self.transition, report)
        with self.assertRaisesRegex(ReceiptError, 'current gate nonce'):
            self._issue()
        report['fresh_gate_nonce'] = self.NONCE
        report['checks']['x10'] = False
        self._write(self.transition, report)
        with self.assertRaisesRegex(ReceiptError, 'every required gate'):
            self._issue()

    def test_evidence_timestamps_must_be_recent_ordered_and_bounded(self):
        self._set_report_times(self.NOW-1000)
        with self.assertRaisesRegex(ReceiptError, 'stale'):
            self._issue(refresh_times=False)
        self._set_report_times(self.NOW)
        report = json.loads(self.transition.read_text())
        report['started_at'], report['ended_at'] = (
            report['ended_at'], report['started_at'])
        self._write(self.transition, report)
        with self.assertRaisesRegex(ReceiptError, 'reversed'):
            self._issue(refresh_times=False)

    def test_transition_shape_is_exact_but_batch_allows_future_true_checks(self):
        transition = json.loads(self.transition.read_text())
        del transition['checks']['x20']
        self._write(self.transition, transition)
        with self.assertRaisesRegex(ReceiptError, 'Transition smoke'):
            self._issue()
        transition['checks']['x20'] = True
        self._write(self.transition, transition)
        batch = json.loads(self.batch.read_text())
        batch['checks']['future_integrity_check'] = True
        self._write(self.batch, batch)
        self._issue()

    def test_key_is_private_and_never_replaced(self):
        original = self.key.read_bytes()
        self.assertEqual(create_key(self.key), original)
        self.assertEqual(self.key.read_bytes(), original)
        os.chmod(self.key, 0o644)
        with self.assertRaisesRegex(ReceiptError, 'group/world'):
            self._issue()

    def test_concurrent_consumers_have_exactly_one_winner(self):
        receipt = self._issue()
        barrier = threading.Barrier(2)
        results = []

        def consume():
            barrier.wait()
            try:
                self._consume(receipt)
                results.append('ok')
            except ReceiptError as error:
                results.append(str(error))

        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count('ok'), 1)
        self.assertEqual(sum('already consumed' in item for item in results), 1)

    def test_pipeline_retains_receipt_and_consumes_it_once(self):
        receipt = self._issue(now=time.time())
        output = self.root/'attempt'
        output.mkdir()
        result = consume_pipeline_receipt(
            receipt, self.key,
            {'device': '/dev/test', 'checkout': str(self.root)}, output)
        self.assertEqual(result['mode'], 'authenticated-one-use')
        self.assertEqual((output/'fresh-gate-receipt.json').read_bytes(),
                         receipt.read_bytes())
        self.assertEqual(json.loads(
            (output/'fresh-gate-consumption.json').read_text())['nonce'], self.NONCE)
        retry = self.root/'attempt-retry'
        retry.mkdir()
        with self.assertRaisesRegex(ReceiptError, 'already consumed'):
            consume_pipeline_receipt(
                receipt, self.key,
                {'device': '/dev/test', 'checkout': str(self.root)}, retry)
        self.assertFalse((retry/'fresh-gate-receipt.json').exists())

    def test_accelerated_orchestrator_skips_only_short_probe(self):
        commands = gate_commands(
            output=self.root/'gate', checkout=self.root, device='/dev/test',
            nonce=self.NONCE)
        self.assertEqual(len(commands), 3)
        self.assertIn('chainload_preserve_boot.py', commands[0][1])
        self.assertIn('vel2_smoke.py', commands[1][1])
        self.assertIn('step_batch_smoke.py', commands[2][1])
        self.assertTrue(all('--fresh-gate-nonce='+self.NONCE in command
                            for command in commands))
        self.assertFalse(any('sptm_entry_probe.py' in part
                             for command in commands for part in command))
        legacy = gate_commands(
            output=self.root/'gate', checkout=self.root, device='/dev/test',
            nonce=self.NONCE, legacy_short_probe=True, payload=self.root/'payload')
        self.assertEqual(len(legacy), 4)
        self.assertTrue(any('sptm_entry_probe.py' in part for part in legacy[-1]))
        self.assertIn('--checkout='+str(self.root), legacy[-1])

    def test_pipeline_gate_selection_is_fail_closed_only_for_execute(self):
        validate_gate_selection(False, None, False)
        validate_gate_selection(True, self.root/'receipt.json', False)
        validate_gate_selection(True, None, True)
        for execute, receipt, legacy in (
                (True, None, False),
                (True, self.root/'receipt.json', True),
                (False, self.root/'receipt.json', False),
                (False, None, True)):
            with self.subTest(execute=execute, receipt=receipt, legacy=legacy):
                with self.assertRaises(ValueError):
                    validate_gate_selection(execute, receipt, legacy)

    def test_gate_and_pipeline_share_exclusive_device_lock(self):
        device = '/dev/test-'+self.root.name
        first = acquire_device_lock(device)
        try:
            with self.assertRaises(BlockingIOError):
                acquire_device_lock(device)
        finally:
            first.close()
        second = acquire_device_lock(device)
        second.close()
        alias = acquire_device_lock('/dev/cu.TEST-M3')
        try:
            with self.assertRaises(BlockingIOError):
                acquire_device_lock('/dev/tty.TEST-M3')
        finally:
            alias.close()

    def test_orchestrator_holds_device_lock_through_receipt_issue(self):
        events = []

        class Lock:
            def close(self):
                events.append('close')

        class Completed:
            returncode = 0

        def acquire(device):
            events.append('acquire:'+device)
            return Lock()

        def run(command, **kwargs):
            self.assertEqual(events[0], 'acquire:/dev/test')
            self.assertNotIn('close', events)
            events.append('run:'+Path(command[1]).name)
            return Completed()

        def issue(**kwargs):
            self.assertNotIn('close', events)
            events.append('issue')
            return {'expires_at': '2027-01-01T00:00:00+00:00'}

        output = self.root/'orchestrated-gate'
        with patch.object(fresh_gate_runner, 'FRESH_GATE_KEY', self.key), \
                patch.object(fresh_gate_runner, 'acquire_device_lock', acquire), \
                patch.object(fresh_gate_runner.subprocess, 'run', run), \
                patch.object(fresh_gate_runner, 'issue_receipt', issue), \
                patch.object(fresh_gate_runner, 'new_nonce', return_value=self.NONCE), \
                patch('builtins.print'):
            fresh_gate_runner.main([
                '--checkout', str(self.root), '--device', '/dev/test',
                '--output', str(output), '--execute',
                '--accelerated'])
        self.assertEqual(events, [
            'acquire:/dev/test', 'run:chainload_preserve_boot.py',
            'run:vel2_smoke.py', 'run:step_batch_smoke.py', 'issue', 'close'])
        gate_report = json.loads((output/'gate.json').read_text())
        self.assertTrue(gate_report['hardware_executed'])
        self.assertEqual(set(gate_report['phase_durations_seconds']), {
            'acquire-device-lock', 'chainload', 'transition-smoke',
            'batch-smoke', 'issue-receipt'})

    def test_orchestrator_requires_mode_and_lock_failure_is_not_hardware_execution(self):
        with self.assertRaises(SystemExit):
            fresh_gate_runner.main([
                '--checkout', str(self.root), '--device', '/dev/test',
                '--output', str(self.root/'no-mode')])
        output = self.root/'locked-gate'
        with patch.object(fresh_gate_runner, 'FRESH_GATE_KEY', self.key), \
                patch.object(fresh_gate_runner, 'acquire_device_lock',
                             side_effect=BlockingIOError('busy')):
            with self.assertRaises(BlockingIOError):
                fresh_gate_runner.main([
                    '--checkout', str(self.root), '--device', '/dev/test',
                    '--output', str(output), '--execute',
                    '--accelerated'])
        report = json.loads((output/'gate.json').read_text())
        self.assertFalse(report['hardware_executed'])


if __name__ == '__main__':
    unittest.main()
