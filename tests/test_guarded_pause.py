import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guarded_pause', Path(__file__).resolve().parents[1] / 'scripts/guarded_pause.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class GuardedPauseTests(unittest.TestCase):
    def test_resume_preserves_context_and_does_not_apply_policy(self):
        with tempfile.TemporaryDirectory() as root:
            policies = {'allow_live_ttbr': False}
            context = {'pc': 0x1234, 'register': 'TTBR0_EL2'}
            def ready(directory, status):
                self.assertEqual(status['context'], context)
                m.submit(directory, 'resume', {'allow_live_ttbr': True})
            result = m.GuardedPause(root).wait('guard', context, policies,
                    allowed_flags=['allow_live_ttbr'], on_pause=ready)
            self.assertEqual(result['action'], 'resume')
            self.assertFalse(policies['allow_live_ttbr'])
            status = m.read_json(Path(root) / result['pause_id'] / 'status.json')
            self.assertEqual(status['decision'], result)
            self.assertEqual(status['state'], 'decided')

    def test_invalid_then_valid_command_is_preserved_and_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            def ready(directory, status):
                m.atomic_json(directory / 'commands' / ('0'*32+'.json'), {'action': 'execute_python'})
                m.submit(directory, 'exit')
            result = m.GuardedPause(root).wait('guard', {}, {}, on_pause=ready)
            self.assertEqual(result['action'], 'exit')
            self.assertEqual(len(list(Path(root).glob('*/rejected-*.json'))), 1)

    def test_strict_protocol(self):
        good = dict(version=1, pause_id='pause', request_id='1'*32, action='resume', changes={'allow_live_ttbr': True})
        for delta in ({'pause_id': 'old'}, {'version': True}, {'action': 'exec'},
                      {'changes': {'allow_live_ttbr': 1}}, {'changes': {'disable_validation': True}},
                      {'request_id': '../escape'}, {'extra': 1}, {'action': 'exit'}):
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                m.validate_command(dict(good, **delta), 'pause', {'allow_live_ttbr'})
        with self.assertRaises(ValueError):
            m.validate_command(good, 'pause', set())

    def test_timeout_and_interruption_choose_exit(self):
        with tempfile.TemporaryDirectory() as root:
            result = m.GuardedPause(root, timeout_seconds=.001, poll_seconds=.001).wait('guard', {}, {})
            self.assertEqual(result['reason'], 'timeout')
            with patch.object(m.time, 'sleep', side_effect=KeyboardInterrupt):
                result2 = m.GuardedPause(root).wait('guard', {}, {})
            self.assertEqual(result2['reason'], 'interrupted')
            self.assertNotEqual(result['pause_id'], result2['pause_id'])
            with self.assertRaises(ValueError):
                m.submit(Path(root) / result2['pause_id'], 'resume')

    def test_stale_request_does_not_resume_next_pause(self):
        with tempfile.TemporaryDirectory() as root:
            old = m.GuardedPause(root, timeout_seconds=.001).wait('old', {}, {})
            def ready(directory, status):
                request = dict(version=1, pause_id=old['pause_id'], request_id='0'*32, action='resume', changes={})
                m.atomic_json(directory / 'commands' / ('0'*32+'.json'), request)
            result = m.GuardedPause(root, max_commands=1).wait('new', {}, {}, on_pause=ready)
            self.assertEqual(result['action'], 'exit')
            self.assertEqual(result['reason'], 'command-limit')

    def test_oversized_and_mismatched_requests_rejected(self):
        for oversized in [True, False]:
            with self.subTest(oversized=oversized), tempfile.TemporaryDirectory() as root:
                def ready(directory, status):
                    path = directory / 'commands' / ('0'*32 + '.json')
                    if oversized:
                        path.write_text(' ' * (m.MAX_BYTES + 1))
                    else:
                        m.atomic_json(path, dict(version=1, pause_id=status['pause_id'], request_id='1'*32, action='resume', changes={}))
                result = m.GuardedPause(root, max_commands=1).wait('guard', {}, {}, on_pause=ready)
                self.assertEqual(result['reason'], 'command-limit')

    def test_pause_callback_failure_finalizes_status(self):
        with tempfile.TemporaryDirectory() as root:
            def fail(*args):
                raise OSError('save failed')
            with self.assertRaises(OSError):
                m.GuardedPause(root).wait('guard', {}, {}, on_pause=fail)
            status = m.read_json(next(Path(root).glob('*/status.json')))
            self.assertEqual(status['decision']['reason'], 'pause-error')

    def test_invalid_poll_bounds(self):
        for options in [{'timeout_seconds': float('nan')}, {'timeout_seconds': 0},
                        {'poll_seconds': 60}, {'max_commands': True}]:
            with self.assertRaises(ValueError):
                m.GuardedPause('/unused', **options)
