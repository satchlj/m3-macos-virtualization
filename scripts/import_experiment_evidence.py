#!/usr/bin/env python3
"""Import checksum-verified historical SPTM reports without inventing provenance."""
import argparse
import json
from pathlib import Path

from experiment_store import Catalog, digest_file
from trace_diff import load_report

REPO = Path(__file__).resolve().parents[1]
EXPERIMENT = 'archive/2026-09-09/sptm-entry'


def import_evidence(store, evidence):
    evidence = Path(evidence).resolve()
    manifest_path = evidence/'sha256.json'
    checksums = load_report(manifest_path)
    manifest_digest, _ = digest_file(manifest_path)
    selected = []
    # Verify the whole evidence bundle before registering anything.
    for name, expected in sorted(checksums.items()):
        path = (evidence/name).resolve()
        if not path.is_relative_to(evidence) or digest_file(path)[0] != expected:
            raise ValueError('Evidence checksum/path mismatch: '+name)
        if name.endswith(('.json', '.json.gz')):
            report = load_report(path)
            if report.get('scope') == 'bounded-sptm-entry':
                selected.append((name, path, expected))
    store.define(EXPERIMENT, dict(schema_version=1, kind='historical-collection',
        target_os='Tahoe', description='Retained September 9 SPTM probe reports; parameters vary by run'))
    runs = []
    for name, path, digest in selected:
        run_id = 'evidence/2026-09-09/'+name
        runs.append(store.ingest(EXPERIMENT, path, run_id=run_id, provenance=dict(
            kind='historical-import', source_path=run_id, source_sha256=digest,
            evidence_manifest_sha256=manifest_digest,
            original_execution_provenance='Only what is present in the retained report; otherwise unknown')))
    return {'experiment': EXPERIMENT, 'imported_or_existing_runs': runs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', type=Path, default=REPO/'artifacts/catalog')
    parser.add_argument('--evidence', type=Path, default=REPO/'artifacts/evidence/2026-09-09')
    args = parser.parse_args()
    with Catalog(args.store) as catalog:
        print(json.dumps(import_evidence(catalog, args.evidence), indent=2))


if __name__ == '__main__':
    main()
