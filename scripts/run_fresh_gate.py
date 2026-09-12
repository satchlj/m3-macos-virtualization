#!/usr/bin/env python3
"""Run the nonce-bound fresh gate and issue an authenticated one-use receipt."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from fresh_gate_receipt import (DEFAULT_KEY as FRESH_GATE_KEY,
                                acquire_device_lock, create_key, issue_receipt, new_nonce)
from run_manifest import atomic_json, utc


REPO = Path(__file__).resolve().parents[1]


def gate_commands(*, output, checkout, device, nonce, legacy_short_probe=False,
                  payload=None):
    output = Path(output)
    checkout = Path(checkout)
    common = ['--fresh-gate-nonce='+nonce]
    commands = [
        [sys.executable, str(REPO/'scripts/chainload_preserve_boot.py'),
         '--checkout='+str(checkout), '--image='+str(checkout/'build/m1n1.bin'),
         '--device='+device, '--output='+str(output/'preserved-chainload'), *common],
        [sys.executable, str(REPO/'scripts/vel2_smoke.py'),
         '--checkout='+str(checkout), '--execute', '--device='+device,
         '--case=transition', '--report='+str(output/'transition.json'), *common],
        [sys.executable, str(REPO/'scripts/step_batch_smoke.py'),
         '--checkout='+str(checkout), '--execute', '--device='+device,
         '--capacity=256', '--report='+str(output/'synthetic.json'), *common],
    ]
    if legacy_short_probe:
        if payload is None:
            raise ValueError('Legacy short probe requires --payload')
        commands.append([
            sys.executable, str(REPO/'scripts/sptm_entry_probe.py'),
            '--checkout='+str(checkout), '--payload='+str(payload),
            '--device='+device, '--execute',
            '--relocate-boot-data', '--allow-monitor-mmu', '--emulate-zero-loops',
            '--steps=4096', '--step-batch=256',
            '--report='+str(output/'short.json')])
    return commands


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--checkout', type=Path, default=os.environ.get('VEL2_CHECKOUT'))
    ap.add_argument('--device', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--execute', action='store_true')
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--accelerated', action='store_true',
                      help='Explicitly omit the legacy 4096-event short probe')
    mode.add_argument('--legacy-short-probe', action='store_true',
                      help='Qualification mode: retain the old 4096-event fourth stage')
    ap.add_argument('--payload', type=Path,
                    help='Guest payload directory, required only for legacy qualification')
    a = ap.parse_args(argv)
    if a.checkout is None:
        ap.error('Set VEL2_CHECKOUT or --checkout')
    if a.legacy_short_probe and a.payload is None:
        ap.error('--legacy-short-probe requires --payload')
    checkout = a.checkout.resolve()
    for path in (checkout/'build/m1n1.bin', checkout/'build/m1n1-raw.elf'):
        if not path.is_file():
            ap.error('Missing built runtime: '+str(path))
    nonce = new_nonce()
    commands = gate_commands(
        output=a.output.resolve(), checkout=checkout, device=a.device, nonce=nonce,
        legacy_short_probe=a.legacy_short_probe, payload=a.payload)
    if not a.execute:
        print(json.dumps({'hardware_executed': False, 'commands': commands}, indent=2))
        return

    output = a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    create_key(FRESH_GATE_KEY)
    report = {
        'schema_version': 1, 'hardware_executed': False, 'started_at': utc(),
        'ended_at': None, 'phase': 'starting', 'fresh_gate_nonce': nonce,
        'accelerated': a.accelerated, 'legacy_short_probe': a.legacy_short_probe,
        'commands': commands, 'phase_durations_seconds': {},
    }
    atomic_json(output/'gate.json', report)
    phases = ['chainload', 'transition-smoke', 'batch-smoke']
    if a.legacy_short_probe:
        phases.append('legacy-short-probe')
    lock = None
    total_started = time.monotonic()
    try:
        report['phase'] = 'acquire-device-lock'
        atomic_json(output/'gate.json', report)
        phase_started = time.monotonic()
        try:
            lock = acquire_device_lock(a.device)
        finally:
            report['phase_durations_seconds']['acquire-device-lock'] = (
                time.monotonic()-phase_started)
        for phase, command in zip(phases, commands):
            report['phase'] = phase
            atomic_json(output/'gate.json', report)
            phase_started = time.monotonic()
            with (output/(phase+'.log')).open('x') as log:
                try:
                    if not report['hardware_executed']:
                        report['hardware_executed'] = True
                        report['hardware_started_at'] = utc()
                        atomic_json(output/'gate.json', report)
                    code = subprocess.run(
                        command, stdout=log, stderr=subprocess.STDOUT).returncode
                finally:
                    report['phase_durations_seconds'][phase] = (
                        time.monotonic()-phase_started)
            if code:
                raise RuntimeError('{} failed with exit {}'.format(phase, code))
        report['phase'] = 'issue-receipt'
        atomic_json(output/'gate.json', report)
        phase_started = time.monotonic()
        receipt_path = output/'fresh-gate-receipt.json'
        try:
            receipt = issue_receipt(
                output=receipt_path, key_path=FRESH_GATE_KEY, nonce=nonce, device=a.device,
                chainload_report=output/'preserved-chainload/report.json',
                transition_report=output/'transition.json',
                batch_report=output/'synthetic.json',
                runtime_image=checkout/'build/m1n1.bin',
                runtime_elf=checkout/'build/m1n1-raw.elf')
        finally:
            report['phase_durations_seconds']['issue-receipt'] = (
                time.monotonic()-phase_started)
        report.update(phase='done', passed=True, receipt=str(receipt_path),
                      receipt_expires_at=receipt['expires_at'])
    except BaseException as error:
        report.update(phase='failed', passed=False, error=str(error))
        raise
    finally:
        if lock is not None:
            lock.close()
        report['ended_at'] = utc()
        report['total_duration_seconds'] = time.monotonic()-total_started
        atomic_json(output/'gate.json', report)
    print(receipt_path)


if __name__ == '__main__':
    main()
