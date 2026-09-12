#!/usr/bin/env python3
"""Issue and atomically consume authenticated fresh-boot gate receipts.

This module is host-only.  It does not touch the target.  A receipt binds one
gate nonce, the exact runtime files, and the reports produced by the preserving
chainload, transition smoke, and native batch smoke.  Consumption is recorded
with O_EXCL in a key-adjacent state directory so copying a receipt cannot make
it reusable.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile

from run_manifest import file_identity


SCHEMA_VERSION = 1
KEY_BYTES = 32
DEFAULT_KEY = Path(__file__).resolve().parents[1]/'artifacts/.fresh-gate-receipt.key'
DEFAULT_TTL_SECONDS = 2 * 60 * 60
MAX_EVIDENCE_AGE_SECONDS = 15 * 60
MAX_GATE_DURATION_SECONDS = 30 * 60
REQUIRED_SECTIONS = {'.init', '.text', '.rodata'}
REQUIRED_TRANSITION_CHECKS = {'stop'} | {'x{}'.format(index) for index in range(10, 21)}
REQUIRED_BATCH_CHECKS = {
    'step_count', 'step_pcs', 'step_values', 'terminal_hvc', 'terminal_value',
    'native_capture', 'clean_return',
}


class ReceiptError(ValueError):
    pass


def device_lock_path(device):
    resolved = Path(os.path.realpath(device))
    name = resolved.name
    if resolved.parent == Path('/dev') and (name.startswith('cu.') or name.startswith('tty.')):
        name = name.split('.', 1)[1]
        identity = '/dev/serial.'+name
    else:
        identity = str(resolved)
    token = hashlib.sha256(identity.encode()).hexdigest()[:24]
    return Path(tempfile.gettempdir())/('m3-probe-'+token+'.lock')


def acquire_device_lock(device):
    """Acquire the lock shared by fresh-gate and probe pipeline processes."""
    lock = device_lock_path(device).open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        lock.close()
        raise
    return lock


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def _utc_timestamp(now=None):
    if now is None:
        now = datetime.now(timezone.utc).timestamp()
    return datetime.fromtimestamp(now, timezone.utc).isoformat()


def _parse_timestamp(value):
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise ReceiptError('Invalid receipt timestamp') from error
    if parsed.tzinfo is None:
        raise ReceiptError('Receipt timestamp must include a timezone')
    return parsed.timestamp()


def create_key(path):
    """Create one local HMAC key without replacing an existing key."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return load_key(path)
    key = secrets.token_bytes(KEY_BYTES)
    try:
        _write_all(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    return key


def load_key(path):
    path = Path(path)
    key = path.read_bytes()
    if len(key) != KEY_BYTES:
        raise ReceiptError('Fresh-gate HMAC key must be exactly 32 bytes')
    if path.stat().st_mode & 0o077:
        raise ReceiptError('Fresh-gate HMAC key must not be group/world accessible')
    return key


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if not written:
            raise OSError('Short write')
        view = view[written:]


def _exclusive_json(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        _write_all(fd, json.dumps(value, indent=2, allow_nan=False).encode()+b'\n')
        os.fsync(fd)
    finally:
        os.close(fd)


def new_nonce():
    return secrets.token_hex(32)


def _read_report(path):
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ReceiptError('Cannot read gate report: '+str(path)) from error
    if not isinstance(value, dict):
        raise ReceiptError('Gate report must be a JSON object: '+str(path))
    return value


def _require_nonce(report, nonce, label):
    if report.get('fresh_gate_nonce') != nonce:
        raise ReceiptError(label+' report does not bind the current gate nonce')


def _report_interval(report, label):
    started = _parse_timestamp(report.get('started_at'))
    ended = _parse_timestamp(report.get('ended_at'))
    if ended < started:
        raise ReceiptError(label+' report timestamps are reversed')
    return started, ended


def _all_true(value, *, exact_keys=None):
    return (isinstance(value, dict) and bool(value)
            and all(item is True for item in value.values())
            and (exact_keys is None or set(value) == exact_keys))


def validate_evidence(*, nonce, chainload_report, transition_report,
                      batch_report, runtime_image, runtime_elf, now=None):
    """Strictly validate the three hardware reports before signing them."""
    if not isinstance(nonce, str) or len(nonce) != 64:
        raise ReceiptError('Gate nonce must be 32-byte lowercase hex')
    try:
        int(nonce, 16)
    except ValueError as error:
        raise ReceiptError('Gate nonce must be 32-byte lowercase hex') from error
    if nonce.lower() != nonce:
        raise ReceiptError('Gate nonce must be 32-byte lowercase hex')

    chainload_path = Path(chainload_report)
    transition_path = Path(transition_report)
    batch_path = Path(batch_report)
    chainload = _read_report(chainload_path)
    transition = _read_report(transition_path)
    batch = _read_report(batch_path)
    for label, report in (('chainload', chainload), ('transition', transition),
                          ('batch', batch)):
        _require_nonce(report, nonce, label)
    intervals = [_report_interval(report, label) for label, report in (
        ('chainload', chainload), ('transition', transition), ('batch', batch))]
    if not (intervals[0][1] <= intervals[1][0]
            and intervals[1][1] <= intervals[2][0]):
        raise ReceiptError('Fresh-gate report timestamps overlap or are out of order')
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    if (now < intervals[2][1] - 5
            or now - intervals[2][1] > MAX_EVIDENCE_AGE_SECONDS
            or intervals[2][1] - intervals[0][0] > MAX_GATE_DURATION_SECONDS):
        raise ReceiptError('Fresh-gate evidence is stale or exceeded its duration bound')

    image_identity = file_identity(runtime_image)
    elf_identity = file_identity(runtime_elf)
    if (chainload.get('scope') != 'fresh-baseline-ram-chainload'
            or chainload.get('phase') != 'proxy-returned'
            or chainload.get('installed_boot_object_changed') is not False
            or chainload.get('image', {}).get('sha256') != image_identity['sha256']
            or chainload.get('image', {}).get('size') != image_identity['size']):
        raise ReceiptError('Preserving chainload report failed its identity/state gates')
    entries = chainload.get('boot_copies', {}).get('entries', [])
    spans = chainload.get('boot_copies', {}).get('spans', [])
    if not any(entry.get('name') == 'RTBuddySeg' for entry in entries) or not spans:
        raise ReceiptError('Preserving chainload report lacks RTBuddySeg evidence')
    for span in spans:
        capture = span.get('capture') or {}
        capture_path = capture.get('path')
        if not capture_path:
            raise ReceiptError('Preserving chainload report lacks a boot-data capture')
        actual = file_identity(capture_path)
        if (actual['sha256'], actual['size']) != (capture.get('sha256'), capture.get('size')):
            raise ReceiptError('Preserved boot-data capture identity mismatch')

    if (transition.get('case') != 'transition'
            or transition.get('hardware_executed') is not True
            or transition.get('passed') is not True
            or transition.get('proxy_alive_after_exit') is not True
            or not _all_true(transition.get('image_sections'), exact_keys=REQUIRED_SECTIONS)
            or not _all_true(transition.get('checks'),
                             exact_keys=REQUIRED_TRANSITION_CHECKS)
            or transition.get('error') or transition.get('cleanup_error')):
        raise ReceiptError('Transition smoke report did not pass every required gate')

    if (batch.get('scope') != 'synthetic-native-step-batch'
            or batch.get('capacity') != 256
            or batch.get('hardware_executed') is not True
            or batch.get('passed') is not True
            or batch.get('proxy_alive_after_exit') is not True
            or not _all_true(batch.get('image_sections'), exact_keys=REQUIRED_SECTIONS)
            or not _all_true(batch.get('checks'))
            or not REQUIRED_BATCH_CHECKS <= set(batch.get('checks', {}))
            or batch.get('error') or batch.get('cleanup_error')):
        raise ReceiptError('Native batch smoke report did not pass every required gate')

    return {
        'runtime_image': image_identity,
        'runtime_elf': elf_identity,
        'reports': {
            'chainload': file_identity(chainload_path),
            'transition': file_identity(transition_path),
            'batch': file_identity(batch_path),
        },
        'preserved_boot_data': [
            {'sha256': span['capture']['sha256'], 'size': span['capture']['size']}
            for span in spans
        ],
        'report_intervals': {
            label: {'started_at': report['started_at'], 'ended_at': report['ended_at']}
            for label, report in (('chainload', chainload),
                                  ('transition', transition), ('batch', batch))
        },
    }


def issue_receipt(*, output, key_path, nonce, device, chainload_report,
                  transition_report, batch_report, runtime_image, runtime_elf,
                  ttl_seconds=DEFAULT_TTL_SECONDS, now=None):
    if not isinstance(device, str) or not device:
        raise ReceiptError('Receipt device must be nonempty')
    if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 24 * 60 * 60:
        raise ReceiptError('Receipt TTL must be an integer from 60 to 86400 seconds')
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    evidence = validate_evidence(
        nonce=nonce, chainload_report=chainload_report,
        transition_report=transition_report, batch_report=batch_report,
        runtime_image=runtime_image, runtime_elf=runtime_elf, now=now)
    payload = {
        'schema_version': SCHEMA_VERSION,
        'kind': 'm3-fresh-gate-receipt',
        'nonce': nonce,
        'device': device,
        'issued_at': _utc_timestamp(now),
        'expires_at': _utc_timestamp(now + ttl_seconds),
        'evidence': evidence,
    }
    signature = hmac.new(load_key(key_path), _canonical(payload), hashlib.sha256).hexdigest()
    receipt = dict(payload, hmac_sha256=signature)
    output = Path(output)
    try:
        _exclusive_json(output, receipt)
    except FileExistsError as error:
        raise ReceiptError('Refusing to replace an existing fresh-gate receipt') from error
    return receipt


def consume_receipt(*, receipt_path, key_path, expected_device,
                    expected_runtime_image, expected_runtime_elf, now=None):
    """Verify and consume a receipt before the first target-touching probe."""
    receipt_path = Path(receipt_path)
    receipt = _read_report(receipt_path)
    signature = receipt.pop('hmac_sha256', None)
    expected = hmac.new(load_key(key_path), _canonical(receipt), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise ReceiptError('Fresh-gate receipt authentication failed')
    if (receipt.get('schema_version') != SCHEMA_VERSION
            or receipt.get('kind') != 'm3-fresh-gate-receipt'):
        raise ReceiptError('Unsupported fresh-gate receipt schema')
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    issued = _parse_timestamp(receipt.get('issued_at'))
    expires = _parse_timestamp(receipt.get('expires_at'))
    if issued > now + 5 or expires <= now or expires <= issued:
        raise ReceiptError('Fresh-gate receipt is not currently valid')
    if receipt.get('device') != expected_device:
        raise ReceiptError('Fresh-gate receipt device mismatch')
    evidence = receipt.get('evidence') or {}
    for label, path in (('runtime_image', expected_runtime_image),
                        ('runtime_elf', expected_runtime_elf)):
        actual = file_identity(path)
        recorded = evidence.get(label) or {}
        if (actual['sha256'], actual['size']) != (recorded.get('sha256'), recorded.get('size')):
            raise ReceiptError('Fresh-gate receipt '+label+' mismatch')

    nonce = receipt.get('nonce')
    if not isinstance(nonce, str) or len(nonce) != 64:
        raise ReceiptError('Fresh-gate receipt nonce is invalid')
    key_path = Path(key_path)
    state_dir = key_path.with_name(key_path.name+'.used')
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_dir.stat().st_mode & 0o077:
        raise ReceiptError('Fresh-gate consumption state must not be group/world accessible')
    marker = state_dir/(nonce+'.json')
    record = {
        'schema_version': SCHEMA_VERSION,
        'nonce': nonce,
        'receipt_sha256': file_identity(receipt_path)['sha256'],
        'consumed_at': _utc_timestamp(now),
        'device': expected_device,
    }
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ReceiptError('Fresh-gate receipt was already consumed') from error
    try:
        data = _canonical(record)+b'\n'
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return record


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='command', required=True)
    keygen = sub.add_parser('keygen')
    keygen.add_argument('--key', type=Path, required=True)
    nonce = sub.add_parser('nonce')
    issue = sub.add_parser('issue')
    issue.add_argument('--key', type=Path, required=True)
    issue.add_argument('--output', type=Path, required=True)
    issue.add_argument('--nonce', required=True)
    issue.add_argument('--device', required=True)
    issue.add_argument('--chainload-report', type=Path, required=True)
    issue.add_argument('--transition-report', type=Path, required=True)
    issue.add_argument('--batch-report', type=Path, required=True)
    issue.add_argument('--runtime-image', type=Path, required=True)
    issue.add_argument('--runtime-elf', type=Path, required=True)
    issue.add_argument('--ttl-seconds', type=int, default=DEFAULT_TTL_SECONDS)
    consume = sub.add_parser('consume')
    consume.add_argument('--key', type=Path, required=True)
    consume.add_argument('--receipt', type=Path, required=True)
    consume.add_argument('--device', required=True)
    consume.add_argument('--runtime-image', type=Path, required=True)
    consume.add_argument('--runtime-elf', type=Path, required=True)
    a = ap.parse_args(argv)
    if a.command == 'keygen':
        create_key(a.key)
        print(a.key)
    elif a.command == 'nonce':
        print(new_nonce())
    elif a.command == 'issue':
        receipt = issue_receipt(
            output=a.output, key_path=a.key, nonce=a.nonce, device=a.device,
            chainload_report=a.chainload_report,
            transition_report=a.transition_report, batch_report=a.batch_report,
            runtime_image=a.runtime_image, runtime_elf=a.runtime_elf,
            ttl_seconds=a.ttl_seconds)
        print(json.dumps(receipt, indent=2))
    else:
        record = consume_receipt(
            receipt_path=a.receipt, key_path=a.key,
            expected_device=a.device, expected_runtime_image=a.runtime_image,
            expected_runtime_elf=a.runtime_elf)
        print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
