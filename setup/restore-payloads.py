#!/usr/bin/env python3
"""Verify retained originals and recreate disposable extracted payloads."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--root', type=Path, default=repo / 'local')
p.add_argument('--evidence', type=Path, default=repo / 'artifacts/evidence/2026-09-09',
               help='Local checksum-manifested evidence directory')
a = p.parse_args()
root = a.root.resolve()
evidence = a.evidence.resolve()
if not (evidence / 'sha256.json').is_file():
    raise SystemExit('Local evidence is unavailable. Pass --evidence PATH; see docs/artifact-storage.md.')
for name, digest in json.loads((evidence / 'sha256.json').read_text()).items():
    if hashlib.sha256((evidence / name).read_bytes()).hexdigest() != digest:
        raise SystemExit('Evidence checksum mismatch: ' + name)
out = root / 'payload'
out.mkdir(parents=True, exist_ok=True)
tool = root / 'payload-venv/bin/pyimg4'
def run(*args):
    subprocess.run([str(tool), *map(str, args)], check=True)
run('img4', 'extract', '-i', evidence / 'payload/kernelcache', '-p', out / 'kernelcache.im4p')
for name, source in [('kernelcache', out / 'kernelcache.im4p'),
                     ('sptm', evidence / 'payload/sptm.t8122.release.im4p'),
                     ('txm', evidence / 'payload/txm.macosx.release.im4p')]:
    run('im4p', 'extract', '-i', source, '-o', out / (name + '.macho'))
print(out)
