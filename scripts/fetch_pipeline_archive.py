#!/usr/bin/env python3
"""Copy a closed pipeline archive from a USB host, then import it locally."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from experiment_store import Catalog
from import_probe_pipeline import MAX_EXPANDED_BYTES, extract_verified, register_pipeline
from run_manifest import atomic_json, file_identity
from trace_diff import load_report

REPO = Path(__file__).resolve().parents[1]
SIDECAR_SUFFIX = '.identity.json'
MAX_SIDECAR_BYTES = 64 * 1024
DEFAULT_SCP_TIMEOUT = 3600
_NAME = r'[A-Za-z0-9][A-Za-z0-9._-]*'
_REMOTE = re.compile(rf'^(?P<host>(?:{_NAME}@)?{_NAME}):(?P<path>/?(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.tar\.gz)$')


def parse_remote_spec(spec):
    """Accept only HOST:PATH/ATTEMPT.tar.gz built from a conservative character set."""
    if not isinstance(spec, str) or len(spec) > 4096:
        raise ValueError('Remote spec must be a short string')
    match = _REMOTE.fullmatch(spec)
    if not match:
        raise ValueError('Remote spec must be HOST:PATH/ATTEMPT.tar.gz without spaces or shell metacharacters')
    host, path = match.group('host'), match.group('path')
    parts = path.lstrip('/').split('/')
    name = parts[-1]
    if any(p in ('.', '..') for p in parts) or name == '.tar.gz' or name.startswith('-'):
        raise ValueError('Remote spec contains a reserved path segment or option-like name')
    return host, path, name


def _scp(host, remote_path, local, timeout):
    # Host and path are validated above; the argv list never passes through a shell.
    argv = ['scp', '-q', f'{host}:{remote_path}', str(local)]
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL, timeout=timeout)


def _expected(identity):
    digest, size = identity.get('sha256'), identity.get('size')
    if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or type(size) is not int or size < 0:
        raise ValueError('Invalid transfer identity sidecar')
    return digest, size


def _matches(path, expected):
    actual = file_identity(path)
    return (actual['sha256'], actual['size']) == expected


def _install(temp, final):
    """Link a verified temporary file into place; never replace an existing file."""
    try:
        os.link(temp, final)
    except FileExistsError:
        return False
    return True


def fetch_archive(remote, archives, *, timeout=DEFAULT_SCP_TIMEOUT):
    """Return (archive path, sidecar identity, copied) after verifying digest and size."""
    host, remote_path, name = parse_remote_spec(remote)
    archives = Path(archives)
    archives.mkdir(parents=True, exist_ok=True)
    archive, sidecar = archives/name, archives/(name+SIDECAR_SUFFIX)
    temps = [archives/f'.{name}{suffix}.fetch-{os.getpid()}' for suffix in (SIDECAR_SUFFIX, '')]
    for temp in temps:
        if temp.exists():
            raise ValueError(f'Stale partial transfer present; remove {temp} first')
    try:
        _scp(host, remote_path+SIDECAR_SUFFIX, temps[0], timeout)
        if temps[0].stat().st_size > MAX_SIDECAR_BYTES:
            raise ValueError('Identity sidecar is unexpectedly large')
        identity = load_report(temps[0])
        expected = _expected(identity)
        if sidecar.exists() and _expected(load_report(sidecar)) != expected:
            raise ValueError('Existing local sidecar records a different identity; refusing to overwrite')
        copied = False
        if archive.exists():
            if not _matches(archive, expected):
                raise ValueError('Existing local archive differs from the remote identity; refusing to overwrite')
        else:
            _scp(host, remote_path, temps[1], timeout)
            if not _matches(temps[1], expected):
                raise ValueError('Transferred archive does not match its identity sidecar; nothing imported')
            if not _install(temps[1], archive):
                if not _matches(archive, expected):
                    raise ValueError('Concurrent archive with a different identity appeared; refusing to overwrite')
            else:
                copied = True
        if not sidecar.exists():
            _install(temps[0], sidecar)
        return archive, identity, copied
    finally:
        for temp in temps:
            temp.unlink(missing_ok=True)


def fetch_and_import(experiment, remote, *, destination=None, archives=None, store=None,
                     max_bytes=MAX_EXPANDED_BYTES, timeout=DEFAULT_SCP_TIMEOUT):
    archives = Path(archives if archives is not None else REPO/'artifacts/transfers/archives')
    store = Path(store if store is not None else REPO/'artifacts/catalog')
    name = parse_remote_spec(remote)[2]
    destination = Path(destination if destination is not None else REPO/'artifacts/runs/imports'/name[:-len('.tar.gz')])
    if destination.exists():
        raise FileExistsError(f'Destination already exists: {destination}')
    with Catalog(store) as catalog:
        archive, identity, copied = fetch_archive(remote, archives, timeout=timeout)
        root = extract_verified(archive, identity, destination, max_bytes=max_bytes)
        result = register_pipeline(catalog, experiment, root, identity)
    result['extracted'] = str(root.resolve())
    result['transfer'] = dict(remote=remote, archive=str(archive.resolve()),
                              sidecar=str(archive.with_name(archive.name+SIDECAR_SUFFIX).resolve()),
                              sha256=identity['sha256'], size=identity['size'], copied=copied)
    atomic_json(destination/'import-receipt.json', result)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('experiment')
    ap.add_argument('remote', help='HOST:PATH/ATTEMPT.tar.gz using an ssh/scp alias')
    ap.add_argument('--destination', type=Path, help='New directory; defaults under artifacts/runs/imports')
    ap.add_argument('--archives', type=Path, default=REPO/'artifacts/transfers/archives')
    ap.add_argument('--store', type=Path, default=REPO/'artifacts/catalog')
    ap.add_argument('--max-expanded-bytes', type=int, default=MAX_EXPANDED_BYTES)
    ap.add_argument('--scp-timeout', type=int, default=DEFAULT_SCP_TIMEOUT, help='Seconds per scp call')
    a = ap.parse_args()
    if a.scp_timeout <= 0:
        raise ValueError('scp timeout must be positive')
    result = fetch_and_import(a.experiment, a.remote, destination=a.destination, archives=a.archives,
                              store=a.store, max_bytes=a.max_expanded_bytes, timeout=a.scp_timeout)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
