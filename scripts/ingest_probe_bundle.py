#!/usr/bin/env python3
"""Register a finalized probe bundle and optional console log, without device access."""
import argparse
from pathlib import Path
from experiment_store import Catalog, digest_file
from trace_diff import load_report


def ingest_bundle(catalog, experiment, bundle, console=None):
    bundle = Path(bundle)
    manifest = load_report(bundle/'manifest.json')
    report = load_report(bundle/'report.json')
    run_id = manifest.get('run_id')
    if not run_id or run_id != report.get('run_id'):
        raise ValueError('Manifest/report run identity mismatch')
    if manifest.get('schema_version') != 1 or manifest.get('status') not in ('finished', 'failed', 'interrupted') or not manifest.get('ended_at'):
        raise ValueError('Bundle is not finalized; preserve it without registering a terminal attempt')
    if manifest.get('capture', {}).get('checkpoint_events') != len(report.get('trace', [])):
        raise ValueError('Manifest/report checkpoint mismatch')
    total = report.get('trace_total_events', len(report.get('trace', [])))
    if manifest.get('capture', {}).get('total_events', total) != total:
        raise ValueError('Manifest/report total event count mismatch')
    attachments = {'manifest': bundle/'manifest.json'}
    for name, expected in manifest.get('captured_inputs', {}).items():
        if not name or Path(name).name != name or name in ('.', '..'):
            raise ValueError('Invalid captured input name')
        path = bundle/'inputs'/name
        if digest_file(path) != (expected.get('sha256'), expected.get('size')):
            raise ValueError('Captured input identity mismatch')
        attachments['input/'+name] = path
    if manifest.get('capture', {}).get('event_archive') == 'events.jsonl':
        archive = bundle/'events.jsonl'
        expected = manifest['capture'].get('event_archive_identity', {})
        if digest_file(archive) != (expected.get('sha256'), expected.get('size')):
            raise ValueError('Event archive identity mismatch or missing final digest')
        attachments['events'] = archive
    if console is not None:
        attachments['console'] = Path(console)
    return catalog.ingest(experiment, bundle/'report.json', run_id=run_id,
                          provenance=manifest, artifacts=attachments)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('experiment')
    p.add_argument('bundle', type=Path)
    p.add_argument('--console', type=Path)
    p.add_argument('--store', type=Path, default=Path(__file__).resolve().parents[1]/'artifacts/catalog')
    a = p.parse_args()
    with Catalog(a.store) as c:
        print(ingest_bundle(c, a.experiment, a.bundle, a.console))


if __name__ == '__main__':
    main()
