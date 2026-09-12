#!/usr/bin/env python3
"""Local, typed decisions for a device-owning process paused at a policy guard."""
import argparse
import json
import math
import os
from pathlib import Path
import time
import uuid

FLAGS = frozenset({'allow_live_ttbr', 'allow_monitor_mmu'})
MAX_BYTES = 65536


def atomic_json(path, value):
    """Publish complete JSON; exclusive temporary files prevent partial reads."""
    path = Path(path)
    temp = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    try:
        with temp.open('x') as stream:
            os.chmod(temp, 0o600)
            json.dump(value, stream, sort_keys=True, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def read_json(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Command/status exceeds size limit')
    return json.loads(data)


def validate_command(command, pause_id, allowed_flags):
    if not isinstance(command, dict) or set(command) != {'version', 'pause_id', 'request_id', 'action', 'changes'}:
        raise ValueError('Command fields do not match protocol')
    if type(command['version']) is not int or command['version'] != 1:
        raise ValueError('Unsupported command version')
    if command['pause_id'] != pause_id:
        raise ValueError('Stale or foreign pause ID')
    request = command['request_id']
    if not isinstance(request, str) or len(request) != 32 or uuid.UUID(hex=request).hex != request:
        raise ValueError('Invalid request ID')
    changes = command['changes']
    if not isinstance(changes, dict) or any(k not in FLAGS or k not in allowed_flags or type(v) is not bool for k, v in changes.items()):
        raise ValueError('Unapproved policy flag or non-boolean value')
    if command['action'] not in ('resume', 'exit'):
        raise ValueError('Only resume and exit are supported')
    if command['action'] == 'exit' and changes:
        raise ValueError('Exit cannot change policy')
    return command


class GuardedPause:
    """Wait without touching a target; caller retains pending trap and applies decision.

    Use a directory within the unique attempt bundle. Each wait creates a distinct
    pause directory. The returned changes are requests, never validation bypasses.
    """
    def __init__(self, root, timeout_seconds=3600, poll_seconds=0.25, max_commands=64):
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 86400:
            raise ValueError('Timeout must be finite and in (0, 86400] seconds')
        if not math.isfinite(poll_seconds) or not 0 < poll_seconds <= 1:
            raise ValueError('Poll interval must be in (0, 1] seconds')
        if type(max_commands) is not int or not 1 <= max_commands <= 1024:
            raise ValueError('Command limit must be 1..1024')
        self.root = Path(root)
        self.timeout_seconds = timeout_seconds
        self.poll_seconds = poll_seconds
        self.max_commands = max_commands

    def wait(self, reason, context, policies, *, allowed_flags=(), on_pause=None):
        allowed_flags = set(allowed_flags)
        if not allowed_flags <= FLAGS:
            raise ValueError('Unknown allowed policy flag')
        if any(k not in FLAGS or type(v) is not bool for k, v in policies.items()):
            raise ValueError('Policies must be enumerated boolean flags')
        pause_id = uuid.uuid4().hex
        directory = self.root / pause_id
        (directory / 'commands').mkdir(parents=True, mode=0o700)
        started = time.monotonic()
        status = dict(version=1, pause_id=pause_id, state='paused', reason=reason,
                      context=context, policies=dict(policies), allowed_flags=sorted(allowed_flags),
                      owner_pid=os.getpid(), created_unix=time.time(), timeout_seconds=self.timeout_seconds,
                      continuation_only=True)
        atomic_json(directory / 'status.json', status)
        seen = set()
        decision = dict(action='exit', changes={}, pause_id=pause_id, request_id=None, reason='timeout')
        try:
            if on_pause:
                on_pause(directory, dict(status))
            while time.monotonic() - started < self.timeout_seconds:
                for path in sorted((directory / 'commands').glob('*.json')):
                    if path.name in seen:
                        continue
                    seen.add(path.name)
                    try:
                        command = validate_command(read_json(path), pause_id, allowed_flags)
                        if path.stem != command['request_id']:
                            raise ValueError('Filename and request ID differ')
                    except (ValueError, TypeError, OSError, AttributeError) as error:
                        atomic_json(directory / ('rejected-' + path.name), {'error': str(error)})
                    else:
                        decision = dict(command, reason='command')
                        return decision
                    if len(seen) >= self.max_commands:
                        decision['reason'] = 'command-limit'
                        return decision
                time.sleep(min(self.poll_seconds, max(0, self.timeout_seconds - (time.monotonic() - started))))
            return decision
        except KeyboardInterrupt:
            decision['reason'] = 'interrupted'
            return decision
        except BaseException:
            decision['reason'] = 'pause-error'
            raise
        finally:
            status.update(state='decided', decision=decision, elapsed_seconds=time.monotonic()-started)
            atomic_json(directory / 'status.json', status)


def submit(directory, action, changes=None):
    """Submit a request, not an acknowledgement. Owner's status is authoritative."""
    directory = Path(directory)
    status = read_json(directory / 'status.json')
    if status['state'] != 'paused':
        raise ValueError('Pause already decided')
    command = dict(version=1, pause_id=status['pause_id'], request_id=uuid.uuid4().hex,
                   action=action, changes={} if changes is None else changes)
    validate_command(command, status['pause_id'], status['allowed_flags'])
    atomic_json(directory / 'commands' / (command['request_id'] + '.json'), command)
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='Unique pause directory printed by probe')
    parser.add_argument('action', choices=['status', 'resume', 'exit'])
    parser.add_argument('--enable', choices=sorted(FLAGS), action='append', default=[])
    parser.add_argument('--disable', choices=sorted(FLAGS), action='append', default=[])
    args = parser.parse_args()
    if set(args.enable) & set(args.disable):
        parser.error('A flag cannot be both enabled and disabled')
    changes = {**dict.fromkeys(args.enable, True), **dict.fromkeys(args.disable, False)}
    if args.action == 'status':
        if changes:
            parser.error('Status does not change policy')
        result = read_json(args.directory / 'status.json')
    else:
        result = submit(args.directory, args.action, changes)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
