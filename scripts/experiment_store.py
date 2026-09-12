#!/usr/bin/env python3
"""Local immutable experiment catalog; ingestion and comparison never run a target."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import uuid

from trace_diff import load_report, compare_reports, iter_event_archive, compare_event_streams

SCHEMA = '''
CREATE TABLE IF NOT EXISTS experiments (
 id TEXT PRIMARY KEY, definition TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS blobs (
 sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL CHECK(size >= 0));
CREATE TABLE IF NOT EXISTS runs (
 id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
 record TEXT NOT NULL, summary TEXT NOT NULL, imported_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (
 run_id TEXT NOT NULL REFERENCES runs(id), name TEXT NOT NULL,
 sha256 TEXT NOT NULL REFERENCES blobs(sha256), PRIMARY KEY(run_id, name));
CREATE INDEX IF NOT EXISTS runs_experiment ON runs(experiment_id);
PRAGMA user_version=1;
'''


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def now():
    return datetime.now(timezone.utc).isoformat()


def digest_file(path):
    digest, size = hashlib.sha256(), 0
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


class Catalog:
    def __init__(self, root, *, create=False):
        self.root = Path(root).resolve()
        dbpath = self.root/'index.sqlite3'
        if create:
            self.root.mkdir(parents=True, exist_ok=True)
        elif not dbpath.is_file():
            raise ValueError('Catalog does not exist; run init first')
        self.db = sqlite3.connect(dbpath, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA synchronous=FULL')
        version = self.db.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0, 1) or (version == 0 and not create):
            self.close()
            raise ValueError('Unsupported catalog schema version')
        if version == 0:
            if self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                self.close()
                raise ValueError('Refusing to initialize an unknown database')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.executescript('BEGIN IMMEDIATE;\n'+SCHEMA+'\nCOMMIT;')
        (self.root/'objects').mkdir(exist_ok=True)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def object_path(self, digest):
        if not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Invalid object digest')
        return self.root/'objects'/digest[:2]/digest

    def put_file(self, path):
        # Hash the copied snapshot, not an earlier read of a possibly live file.
        with tempfile.NamedTemporaryFile(dir=self.root/'objects', delete=False) as tmp:
            name = Path(tmp.name)
            try:
                with open(path, 'rb') as source:
                    shutil.copyfileobj(source, tmp, length=1024*1024)
                tmp.flush()
                os.fsync(tmp.fileno())
            except BaseException:
                name.unlink()
                raise
        try:
            digest, size = digest_file(name)
            dest = self.object_path(digest)
            dest.parent.mkdir(exist_ok=True)
            os.chmod(name, 0o444)
            try:
                os.link(name, dest)  # Publish without overwriting another worker's object.
            except FileExistsError:
                if digest_file(dest) != (digest, size):
                    raise ValueError('Existing content object is corrupt: '+digest)
            fd = os.open(dest.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            fd = os.open(self.root/'objects', os.O_RDONLY)
            try:
                os.fsync(fd)  # Persist a newly created digest-prefix directory too.
            finally:
                os.close(fd)
            return {'sha256': digest, 'size': size}
        finally:
            name.unlink(missing_ok=True)

    def define(self, experiment_id, definition):
        if not experiment_id or not isinstance(definition, dict):
            raise ValueError('Experiment needs an ID and JSON object definition')
        encoded = canonical(definition)
        with self.transaction():
            row = self.db.execute('SELECT definition FROM experiments WHERE id=?', (experiment_id,)).fetchone()
            if row and row['definition'] != encoded:
                raise ValueError('Experiment definition is immutable; use a new ID')
            self.db.execute('INSERT OR IGNORE INTO experiments VALUES (?,?,?)', (experiment_id, encoded, now()))
        return experiment_id

    def ingest(self, experiment_id, report_path, *, run_id=None, provenance=None, artifacts=None):
        if self.db.execute('SELECT 1 FROM experiments WHERE id=?', (experiment_id,)).fetchone() is None:
            raise ValueError('Unknown experiment')
        run_id = str(uuid.uuid4()) if run_id is None else run_id
        if not isinstance(run_id, str) or not run_id:
            raise ValueError('Run ID must be a nonempty string')
        provenance = {} if provenance is None else provenance
        if not isinstance(provenance, dict):
            raise ValueError('Provenance must be a JSON object')
        attachments = dict(artifacts or {})
        if 'report' in attachments:
            raise ValueError('The report artifact name is reserved')
        attachments['report'] = report_path
        if any(not isinstance(n, str) or not n for n in attachments):
            raise ValueError('Artifact names must be nonempty strings')
        objects = {name: self.put_file(path) for name, path in sorted(attachments.items())}
        report = load_report(self.object_path(objects['report']['sha256']))
        # These flags are producer claims, not independently verified boot outcomes.
        summary = {key: report[key] for key in ('scope', 'stop_reason', 'error', 'cleanup_error',
                   'hardware_executed', 'guest_boot_verified', 'proxy_alive_after_exit', 'passed') if key in report}
        summary['trace_events'] = len(report['trace']) if 'trace' in report else None
        summary['trace_total_events'] = report.get('trace_total_events', summary['trace_events'])
        summary['trace_start_index'] = report.get('trace_start_index', 0)
        record = dict(schema_version=1, experiment_id=experiment_id, provenance=provenance,
                      artifacts=objects, report_reader='bounded-json-v1')
        encoded = canonical(record)
        with self.transaction():
            old = self.db.execute('SELECT record FROM runs WHERE id=?', (run_id,)).fetchone()
            if old:
                if old['record'] != encoded:
                    raise ValueError('Run ID already exists with different immutable data')
                return run_id
            for obj in objects.values():
                self.db.execute('INSERT OR IGNORE INTO blobs VALUES (?,?)', (obj['sha256'], obj['size']))
            self.db.execute('INSERT INTO runs VALUES (?,?,?,?,?)',
                            (run_id, experiment_id, encoded, canonical(summary), now()))
            self.db.executemany('INSERT INTO artifacts VALUES (?,?,?)',
                                [(run_id, name, obj['sha256']) for name, obj in objects.items()])
        return run_id

    def get(self, run_id):
        row = self.db.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
        if row is None:
            raise ValueError('Unknown run: '+run_id)
        return dict(id=row['id'], imported_at=row['imported_at'],
                    record=json.loads(row['record']), summary=json.loads(row['summary']))

    def list_runs(self, experiment=None):
        rows = self.db.execute('SELECT id FROM runs'+(' WHERE experiment_id=?' if experiment else '')+
                               ' ORDER BY imported_at,id', (experiment,) if experiment else ())
        return [self.get(row['id']) for row in rows]

    def report(self, run_id):
        obj = self.get(run_id)['record']['artifacts']['report']
        path = self.object_path(obj['sha256'])
        if digest_file(path) != (obj['sha256'], obj['size']):
            raise ValueError('Report object integrity failure')
        return load_report(path)

    def diff(self, left, right, mode='exact-v1'):
        a, b = self.get(left), self.get(right)
        reports = [self.report(left), self.report(right)]
        if any('events' in run['record']['artifacts'] for run in (a, b)):
            streams = []
            for run, report in zip((a, b), reports):
                obj = run['record']['artifacts'].get('events')
                if obj:
                    path = self.object_path(obj['sha256'])
                    if digest_file(path) != (obj['sha256'], obj['size']):
                        raise ValueError('Event archive integrity failure')
                    streams.append(iter_event_archive(path))
                elif report.get('trace_start_index', 0):
                    raise ValueError('Full event archive missing for windowed report')
                elif 'trace' not in report:
                    raise ValueError('Missing trace')
                else:
                    streams.append(iter(report['trace']))
            result = compare_event_streams(*reports, *streams, mode)
        else:
            result = compare_reports(*reports, mode)
        result.update(left_run=left, right_run=right,
                      same_experiment=a['record']['experiment_id'] == b['record']['experiment_id'],
                      provenance_equal=a['record']['provenance'] == b['record']['provenance'],
                      provenance={'left': a['record']['provenance'], 'right': b['record']['provenance']},
                      provenance_completeness_verified=False)
        return result

    def verify(self):
        if self.db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or self.db.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('Catalog integrity failure')
        count = 0
        for row in self.db.execute('SELECT * FROM blobs'):
            if digest_file(self.object_path(row['sha256'])) != (row['sha256'], row['size']):
                raise ValueError('Artifact integrity failure: '+row['sha256'])
            count += 1
        return {'verified_objects': count, 'runs': self.db.execute('SELECT count(*) FROM runs').fetchone()[0]}

    def backup(self, destination):
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=False)
        with sqlite3.connect(destination/'index.sqlite3') as snapshot:
            self.db.backup(snapshot)
            rows = snapshot.execute('SELECT sha256 FROM blobs').fetchall()
        for (digest,) in rows:
            target = destination/'objects'/digest[:2]/digest
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.object_path(digest), target)
        with Catalog(destination) as snapshot:
            result = snapshot.verify()
        (destination/'BACKUP_COMPLETE').write_text(canonical(result)+'\n')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', type=Path, default=Path(__file__).resolve().parents[1]/'artifacts/catalog')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init')
    define = sub.add_parser('define')
    define.add_argument('id')
    define.add_argument('manifest', type=Path)
    ingest = sub.add_parser('ingest')
    ingest.add_argument('experiment')
    ingest.add_argument('report', type=Path)
    ingest.add_argument('--run-id')
    ingest.add_argument('--provenance', type=Path)
    ingest.add_argument('--artifact', action='append', default=[], metavar='NAME=PATH')
    listing = sub.add_parser('list')
    listing.add_argument('--experiment')
    show = sub.add_parser('show')
    show.add_argument('run')
    diff = sub.add_parser('diff')
    diff.add_argument('left')
    diff.add_argument('right')
    diff.add_argument('--mode', choices=('exact-v1', 'control-flow-v1'), default='exact-v1')
    sub.add_parser('verify')
    backup = sub.add_parser('backup')
    backup.add_argument('destination', type=Path)
    args = parser.parse_args()
    try:
        with Catalog(args.store, create=args.command == 'init') as store:
            if args.command == 'init':
                result = {'store': str(store.root), 'schema_version': 1}
            elif args.command == 'define':
                result = {'experiment': store.define(args.id, load_report(args.manifest))}
            elif args.command == 'ingest':
                extras = {}
                for spec in args.artifact:
                    name, separator, path = spec.partition('=')
                    if not separator or not name or not path or name in extras:
                        raise ValueError('Expected unique NAME=PATH artifacts')
                    extras[name] = Path(path)
                result = {'run': store.ingest(args.experiment, args.report, run_id=args.run_id,
                    provenance=load_report(args.provenance) if args.provenance else {}, artifacts=extras)}
            elif args.command == 'list':
                result = store.list_runs(args.experiment)
            elif args.command == 'show':
                result = store.get(args.run)
            elif args.command == 'diff':
                result = store.diff(args.left, args.right, args.mode)
            elif args.command == 'verify':
                result = store.verify()
            else:
                result = store.backup(args.destination)
        print(json.dumps(result, indent=2, allow_nan=False))
    except (ValueError, OSError, EOFError, sqlite3.Error) as error:
        parser.exit(2, f'{error}\n')


if __name__ == '__main__':
    main()
