#!/usr/bin/env python3
"""Reproduce pinned source trees and Python environments; never reset existing work."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

def run(*args, cwd=None):
    subprocess.run([str(a) for a in args], cwd=cwd, check=True)

def matches(root, entries):
    return all((root / p).is_file() and hashlib.sha256((root / p).read_bytes()).hexdigest() == h
               for p, h in entries.items())

def checkout(root, name, lockname):
    lock = json.loads((REPO / lockname).read_text())
    if not matches(REPO, lock['patches']):
        raise RuntimeError('Patch checksum mismatch: ' + lockname)
    dest = root / name
    if not dest.exists():
        run('git', 'clone', '--no-checkout', lock['repository'], dest)
        run('git', 'checkout', '--detach', lock['commit'], cwd=dest)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=dest, text=True).strip()
    if head != lock['commit']:
        raise RuntimeError(f'{dest}: unexpected HEAD; preserve work and choose another --root')
    if not matches(dest, lock['files']):
        if not matches(dest, lock['base_files']):
            raise RuntimeError(f'{dest}: source drift; refusing to overwrite')
        for patch in lock['patches']:
            run('git', 'apply', '--check', REPO / patch, cwd=dest)
            run('git', 'apply', REPO / patch, cwd=dest)
        if not matches(dest, lock['files']):
            raise RuntimeError(f'{dest}: patched checksums differ')
    run('git', 'submodule', 'update', '--init', '--recursive', cwd=dest)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=REPO / 'local')
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    checkout(root, 'm1n1', 'upstream.lock')
    checkout(root, 'm1n1-vel2', 'upstream-vel2.lock')
    for name, requirements in [('venv', 'python-requirements.lock'), ('payload-venv', 'payload-requirements.lock')]:
        dest = root / name
        if not (dest / 'bin/python').exists():
            run(sys.executable, '-m', 'venv', dest)
        run(dest / 'bin/python', '-m', 'pip', 'install', '-r', REPO / 'setup' / requirements)
    print(f'Ready. Set ASAHI_ROOT={root} and source setup/activate.sh')

if __name__ == '__main__':
    main()
