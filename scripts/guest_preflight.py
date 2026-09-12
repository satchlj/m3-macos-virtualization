#!/usr/bin/env python3
"""Offline diagnostics only. Never imports/executes m1n1 or opens a device."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {'bootargs_revision', 'bootargs_version', 'firmware_string',
          'memory_map_keys', 'cpu_names', 'boot_cpu', 'selected_cpu', 'command_line'}


def validate(data):
    if not isinstance(data, dict) or set(data) - FIELDS:
        raise ValueError('Metadata must be an object containing only documented fields')
    for key in ('bootargs_revision', 'bootargs_version'):
        if key in data and (type(data[key]) is not int or data[key] < 0):
            raise ValueError(key + ' must be a nonnegative integer')
    for key in ('firmware_string', 'boot_cpu', 'selected_cpu', 'command_line'):
        if key in data and not isinstance(data[key], str):
            raise ValueError(key + ' must be a string')
    for key in ('memory_map_keys', 'cpu_names'):
        if key in data and (not isinstance(data[key], list) or
                            any(not isinstance(x, str) for x in data[key])):
            raise ValueError(key + ' must be a string list')
    return data


def contract(checkout, lock):
    """Reject drift before applying assumptions audited against this source."""
    try:
        head = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], stderr=subprocess.DEVNULL, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        raise ValueError('Cannot identify source checkout') from None
    if head != lock['commit']:
        raise ValueError('Source commit differs from audited baseline')
    for name, digest in lock['files'].items():
        p = checkout / name
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            raise ValueError('Source contract changed or missing: ' + name)
    tree = ast.parse((checkout / 'proxyclient/m1n1/proxyutils.py').read_text())
    versions = next(ast.literal_eval(n.value) for n in tree.body
                    if isinstance(n, ast.Assign) and any(
                        isinstance(t, ast.Name) and t.id == 'VERSION_MAP' for t in n.targets))
    # Derive wire command-line sizes directly from the verified Construct definitions.
    tree = ast.parse((checkout / 'proxyclient/m1n1/tgtypes.py').read_text())
    sizes = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name.startswith('BootArgs_r'):
                sizes[int(name.removeprefix('BootArgs_r'))] = next(
                    ast.literal_eval(n.args[0]) for n in ast.walk(node.value)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == 'PaddedString')
    return versions, sizes


def diagnose(data, versions, sizes):
    data = validate(data)
    findings = []
    def add(code, state, detail):
        findings.append(dict(code=code, state=state, detail=detail))
    revision = data.get('bootargs_revision')
    if revision is None:
        add('bootargs', 'unknown', 'Actual proxy bootargs revision has not been supplied.')
    elif revision not in sizes:
        add('bootargs', 'blocked', 'No audited serializer for this revision. The patched loader rejects unsupported revisions before guest setup.')
    else:
        add('bootargs', 'checked', 'Serializer exists; this does not validate guest ABI.')
    if 'command_line' in data:
        try:
            size = len(data['command_line'].encode('ascii'))
        except UnicodeEncodeError:
            add('command_line', 'blocked', 'Construct command line is ASCII; input is not.')
        else:
            if revision not in sizes:
                add('command_line', 'unknown', 'Cannot validate without supported revision.')
            elif size >= sizes[revision]:
                add('command_line', 'blocked', 'Command line must fit wire field with space for a NUL terminator.')
            else:
                add('command_line', 'checked', 'ASCII command line fits with terminator space.')
    fw = data.get('firmware_string')
    if fw is None:
        add('firmware', 'unknown', 'Need exact ADT firmware string, not System Information numeric version.')
    elif fw not in versions:
        add('firmware', 'unknown', 'ProxyUtils returns None for this string. This is not a blanket guest-boot rejection; no alias applied.')
    else:
        add('firmware', 'checked', 'Proxy firmware label is recognized; it is not a guest compatibility verdict.')
    keys = data.get('memory_map_keys')
    if keys is None:
        add('memory_map', 'unknown', 'SEPFW and TrustCache presence not observed.')
    elif not {'SEPFW', 'TrustCache'} <= set(keys):
        add('memory_map', 'blocked', 'load_raw unconditionally reads SEPFW and TrustCache; required entry missing.')
    else:
        add('memory_map', 'checked', 'Required entry names present; sizes, ranges and contents remain unchecked.')
    selected = data.get('selected_cpu')
    cpus, boot = data.get('cpu_names'), data.get('boot_cpu')
    if selected is None or cpus is None or boot is None:
        add('single_cpu', 'unknown', 'Need selected CPU, actual CPU names and current boot CPU.')
    elif selected != boot or selected not in cpus:
        add('single_cpu', 'blocked', 'First single-core experiment must retain the actual boot CPU.')
    elif not (selected.startswith('cpu') and selected[3:].isascii() and selected[3:].isdecimal()):
        add('single_cpu', 'blocked', 'Selected CPU name is malformed.')
    else:
        add('single_cpu', 'checked', 'The patched --single-core selector retains the observed running boot CPU, including multi-digit IDs; no command executed.')
    add('runtime_contract', 'unknown', 'SPTM/TXM mode, bootargs version semantics, guest entry/exception behavior and loaded m1n1 ABI require separate evidence. No target executed.')
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--m1n1', required=True, type=Path)
    parser.add_argument('--metadata', type=Path, help='Optional allowlisted metadata JSON; no raw ADT or addresses')
    args = parser.parse_args()
    try:
        lock = json.loads((ROOT / 'upstream.lock').read_text())
        versions, sizes = contract(args.m1n1, lock)
        data = json.loads(args.metadata.read_text()) if args.metadata else {}
        findings = diagnose(data, versions, sizes)
        # Header inspection, not execution or validation of build provenance.
        artifact = args.m1n1 / 'build/m1n1.macho'
        magic = artifact.open('rb').read(4) if artifact.is_file() else b''
        findings.append(dict(code='build_artifact', state='checked' if magic == b'\xcf\xfa\xed\xfe' else 'unknown',
                             detail='Mach-O header present; artifact freshness/target ABI not established.' if magic == b'\xcf\xfa\xed\xfe' else 'Expected built Mach-O header not found.'))
        print(json.dumps({'scope': 'offline-guest-boot-preflight', 'guest_boot_verified': False,
                          'source_commit': lock['commit'], 'findings': findings}, indent=2))
        return 2 if any(f['state'] == 'blocked' for f in findings) else 0
    except (ValueError, OSError, SyntaxError, StopIteration) as error:
        print(json.dumps({'error': str(error), 'guest_boot_verified': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
