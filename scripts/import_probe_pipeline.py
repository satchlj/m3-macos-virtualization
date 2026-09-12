#!/usr/bin/env python3
"""Verify and import a downloaded pipeline archive without target access."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile

from experiment_store import Catalog
from ingest_probe_bundle import ingest_bundle
from run_manifest import atomic_json
from trace_diff import load_report

REPO = Path(__file__).resolve().parents[1]
MAX_EXPANDED_BYTES = 16 * 1024**3


def extract_verified(archive, identity, destination, *, max_bytes=MAX_EXPANDED_BYTES):
    """Extract regular files/directories only, into an exclusively new directory."""
    digest = identity.get('sha256')
    size = identity.get('size')
    if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or type(size) is not int or size < 0:
        raise ValueError('Invalid transfer identity')
    destination = Path(destination)
    with open(archive, 'rb') as source:
        actual = hashlib.sha256()
        count = 0
        for block in iter(lambda: source.read(1024 * 1024), b''):
            actual.update(block)
            count += len(block)
        if (actual.hexdigest(), count) != (digest, size):
            raise ValueError('Transfer identity mismatch; nothing extracted')
        source.seek(0)
        destination.mkdir(parents=True, exist_ok=False)
        try:
            seen = set()
            expanded = 0
            with tarfile.open(fileobj=source, mode='r|gz') as contents:
                for member in contents:
                    raw = member.name.rstrip('/')
                    parts = raw.split('/')
                    if not raw or raw.startswith('/') or any(p in ('', '.', '..') for p in parts) or '\\' in raw:
                        raise ValueError('Unsafe archive path')
                    if raw in seen or len(seen) >= 100000:
                        raise ValueError('Duplicate path or excessive archive entries')
                    seen.add(raw)
                    if not (member.isfile() or member.isdir()) or member.issparse():
                        raise ValueError('Archive permits only regular files and directories')
                    if member.size < 0 or member.isdir() and member.size != 0:
                        raise ValueError('Invalid archive member size')
                    expanded += member.size
                    if expanded > max_bytes:
                        raise ValueError('Archive expanded byte limit exceeded')
                    target = destination.joinpath(*PurePosixPath(raw).parts)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with contents.extractfile(member) as data, target.open('xb') as output:
                            shutil.copyfileobj(data, output, length=1024 * 1024)
                        if target.stat().st_size != member.size:
                            raise ValueError('Truncated archive member')
            roots = list(destination.iterdir())
            if len(roots) != 1 or not roots[0].is_dir():
                raise ValueError('Expected one pipeline directory')
            return roots[0]
        except BaseException:
            shutil.rmtree(destination)
            raise


def register_pipeline(catalog, experiment, root, identity):
    """Keep producer run identity separate from immutable post-run attachments."""
    root = Path(root)
    pipeline = load_report(root/'pipeline.json')
    load_report(root/'config.json')
    if pipeline.get('phase') not in ('finished', 'failed') or not pipeline.get('ended_at'):
        raise ValueError('Pipeline is not finalized')
    manifests = sorted((root/'runs').glob('*/manifest.json'))
    if len(manifests) > 1:
        raise ValueError('Expected at most one probe attempt per pipeline')
    probe_id = None
    probe_state = 'missing'
    bundle = None
    if manifests:
        bundle = manifests[0].parent
        manifest = load_report(manifests[0])
        probe_state = manifest.get('status')
        report = load_report(bundle/'report.json')
        if pipeline.get('run_id') and pipeline['run_id'] != manifest.get('run_id'):
            raise ValueError('Pipeline/probe run identity mismatch')
        if report.get('run_id') != manifest.get('run_id'):
            raise ValueError('Manifest/report run identity mismatch')
        if probe_state in ('finished', 'failed', 'interrupted') and manifest.get('ended_at'):
            probe_id = ingest_bundle(catalog, experiment, bundle)
    # A pipeline record is evidence about orchestration, never a claimed guest run.
    attachments = {}
    for path in sorted(root.rglob('*')):
        if path.is_file() and path != root/'pipeline.json':
            if bundle is None or not path.is_relative_to(bundle):
                attachments['pipeline/'+path.relative_to(root).as_posix()] = path
    pipeline_id = 'pipeline:' + identity['sha256']
    catalog.ingest(experiment, root/'pipeline.json', run_id=pipeline_id,
                   provenance={'kind': 'pipeline-import-v1', 'probe_run_id': probe_id,
                               'probe_state': probe_state,
                               'transfer': {k: identity[k] for k in ('sha256', 'size')}},
                   artifacts=attachments)
    return {'pipeline_record': pipeline_id, 'probe_run_id': probe_id,
            'probe_state': probe_state, 'probe_registered': probe_id is not None}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('experiment')
    ap.add_argument('archive', type=Path)
    ap.add_argument('--identity', type=Path, help='Defaults to ARCHIVE.identity.json')
    ap.add_argument('--destination', type=Path, required=True, help='New ignored artifact directory')
    ap.add_argument('--store', type=Path, default=REPO/'artifacts/catalog')
    ap.add_argument('--max-expanded-bytes', type=int, default=MAX_EXPANDED_BYTES)
    a = ap.parse_args()
    identity = load_report(a.identity or a.archive.with_name(a.archive.name+'.identity.json'))
    root = extract_verified(a.archive, identity, a.destination, max_bytes=a.max_expanded_bytes)
    with Catalog(a.store) as catalog:
        result = register_pipeline(catalog, a.experiment, root, identity)
    result['extracted'] = str(root.resolve())
    atomic_json(a.destination/'import-receipt.json', result)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
