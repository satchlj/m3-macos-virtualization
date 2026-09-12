"""Host-side attempt manifests and atomic partial reports; no device APIs."""
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
import uuid


def utc():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, indent=2, allow_nan=False)+'\n'
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as f:
        temp = Path(f.name)
        try:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            temp.unlink()
            raise
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def file_identity(path):
    path = Path(path)
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            digest.update(block)
            size += len(block)
    return dict(path=str(path.resolve()), sha256=digest.hexdigest(), size=size)


def git_identity(path):
    path = Path(path).resolve()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(path), *args], stderr=subprocess.PIPE, timeout=30)
    try:
        head = git('rev-parse', 'HEAD').decode().strip()
        diff = git('diff', '--binary', 'HEAD', '--')
        untracked = [file_identity(path/os.fsdecode(p)) for p in
                     git('ls-files', '--others', '--exclude-standard', '-z').split(b'\0') if p]
        return dict(path=str(path), commit=head, dirty=bool(diff or untracked),
                    tracked_diff_sha256=hashlib.sha256(diff).hexdigest(),
                    untracked=untracked, submodules=git('submodule', 'status', '--recursive').decode().splitlines(),
                    ignored_files_included=False)
    except (OSError, subprocess.SubprocessError) as error:
        return dict(path=str(path), error=str(error), completeness='unknown')


def trace_count(report):
    return report.get('trace_total_events', len(report['trace']))


def append_event(report, event):
    total = trace_count(report)+1
    report['trace'].append(event)
    report['trace_total_events'] = total
    window = report.get('trace_window')
    if window and len(report['trace']) > window:
        del report['trace'][:-window]
    report['trace_start_index'] = total-len(report['trace'])


class RunCapture:
    def __init__(self, root, report_path, parameters, *, repo, checkout, command=None):
        self.run_id = str(uuid.uuid4())
        self.root = Path(root)/self.run_id
        self.root.mkdir(parents=True, exist_ok=False)
        self.report_path = Path(report_path)
        self.journal_next = 0
        self.started = time.monotonic()
        self.manifest = dict(schema_version=1, run_id=self.run_id,
            producer='bounded-sptm-entry', backend='hardware' if parameters['execute'] else 'offline-layout',
            started_at=utc(), ended_at=None, status='preparing', phase='provenance',
            parameters=parameters, command=list(sys.argv if command is None else command), cwd=os.getcwd(),
            host=dict(platform=platform.platform(), python=sys.version, executable=sys.executable, packages={d.metadata['Name']: d.version for d in metadata.distributions() if d.metadata['Name']}),
            target=dict(connection=parameters.get('device'), identity=None, os_version=None,
                        firmware_version=None, reset_state='unknown'),
            capture=dict(complete=False, checkpoint_events=0, console_captured=False),
            runtime_identity=dict(verification='not-attempted'))
        self.write_manifest()
        self.manifest['sources'] = dict(research=git_identity(repo), checkout=git_identity(checkout))
        self.manifest['inputs'] = [file_identity(p) for p in sorted(Path(repo).glob('upstream*.lock'))]
        self.manifest['inputs'] += [file_identity(p) for p in sorted((Path(repo)/'patches').rglob('*.patch'))]
        elf = Path(checkout)/'build/m1n1-raw.elf'
        self.manifest['expected_runtime'] = file_identity(elf) if elf.is_file() else None
        self.write_manifest()

    def write_manifest(self):
        atomic_json(self.root/'manifest.json', self.manifest)

    def save_input(self, name, data):
        """Retain exact small runtime inputs, not just hashes of unavailable bytes."""
        if not isinstance(name, str) or not name or Path(name).name != name or name in ('.', '..'):
            raise ValueError('Input name must be a single filename')
        directory = self.root/'inputs'
        directory.mkdir(exist_ok=True)
        path = directory/name
        with path.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        identity = file_identity(path)
        self.manifest.setdefault('captured_inputs', {})[name] = identity
        self.write_manifest()
        return identity

    def phase(self, phase):
        self.manifest['phase'] = phase
        self.manifest['status'] = 'running'
        self.write_manifest()

    def save(self, report):
        self.observe(report)
        if report.get('trace_window'):
            start = report.get('trace_start_index', 0)
            total = trace_count(report)
            if not start <= self.journal_next <= total:
                raise ValueError('Event journal checkpoint gap')
            with (self.root/'events.jsonl').open('a+') as journal:
                offset = journal.tell()
                try:
                    for index in range(self.journal_next, total):
                        journal.write(json.dumps({'index': index, 'event': report['trace'][index-start]}, separators=(',', ':'), allow_nan=False)+'\n')
                    journal.flush()
                    os.fsync(journal.fileno())
                except BaseException:
                    journal.seek(offset)
                    journal.truncate()
                    raise
            self.journal_next = total
            self.manifest['capture']['journal_events'] = total
            self.manifest['capture']['event_archive'] = 'events.jsonl'
        # The bundle is authoritative; the requested path remains a convenient copy.
        atomic_json(self.root/'report.json', report)
        self.manifest['capture']['checkpoint_events'] = len(report.get('trace', []))
        self.manifest['capture']['total_events'] = trace_count(report)
        self.manifest['capture']['checkpoint_at'] = utc()
        atomic_json(self.report_path, report)
        self.write_manifest()

    def finish(self, report, error=None):
        self.manifest.update(ended_at=utc(), duration_seconds=time.monotonic()-self.started,
                             status='interrupted' if isinstance(error, (KeyboardInterrupt, SystemExit)) else
                                    'failed' if error or report.get('error') or report.get('cleanup_error') else 'finished')
        if error is not None:
            self.manifest['exception'] = dict(type=type(error).__name__, message=str(error))
        self.manifest['capture']['complete'] = error is None and not report.get('report_save_error') and not report.get('cleanup_error') and not report.get('trace_incomplete')
        self.manifest['outcome'] = {k: report[k] for k in ('stop_reason', 'error', 'cleanup_error',
            'hardware_executed', 'guest_boot_verified', 'proxy_alive_after_exit') if k in report}
        self.save(report)
        if report.get('trace_window'):
            self.manifest['capture']['event_archive_identity'] = file_identity(self.root/'events.jsonl')
            self.write_manifest()

    def observe(self, report):
        if 'layout' in report:
            self.manifest['payloads'] = {k: {'path': v['path'], 'sha256': v['sha256']}
                                        for k, v in report['layout']['images'].items()}
        if 'image_sections' in report:
            self.manifest['runtime_identity'] = dict(verification='immutable-sections-compared',
                sections=report['image_sections'], whole_runtime_verified=False)
        if 'guest_image_sha256' in report:
            self.manifest['guest_image_sha256'] = report['guest_image_sha256']
        for key in ('device_tree_sha256', 'trustcache_sha256'):
            if key in report:
                self.manifest[key] = report[key]
