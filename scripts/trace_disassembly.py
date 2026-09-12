#!/usr/bin/env python3
"""Annotate bounded guest trace windows with disassembly of the ORIGINAL payload bytes.

Host-side only: verifies the SHA-256 of each payload file named in a run report's
layout before reading it, never writes payloads, never opens a device and never
executes guest code. The bytes shown are what was linked, not necessarily what
ran: the SPTM probe rewrites some sptm __TEXT_EXEC instructions to HVC before
loading (patch_probe_code in sptm_entry_probe.py, after upstream m1n1's
patch_synthetic_code). Recorded events are the evidence of what executed.
"""
import argparse
from collections import Counter
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
from run_manifest import atomic_json, file_identity
from trace_diff import iter_event_archive, load_report

MAX_WINDOW = 4096
MAX_HITS = 256
HVC_WORD = 0xd4000002
ERET_WORD = 0xd69f03e0
ENTRY_GUARD_IMM = 0x7ffe
DEFAULT_LLVM_MC = Path('/opt/homebrew/opt/llvm/bin/llvm-mc')
MC_ARGS = ['--disassemble', '--triple=aarch64', '--mattr=+all', '-show-encoding']
ENCODING = re.compile(r'//\s*encoding:\s*\[([^\]]*)\]')
INVALID = re.compile(r'^<stdin>:(\d+):\d+: warning: invalid instruction encoding')
# Architectural (op0, op1, CRn, CRm, op2) encodings patch_probe_code always rewrites.
KNOWN_REWRITES = {(3, 4, 1, 1, 0): ('HCR_EL2', 0x6000), (3, 4, 1, 0, 0): ('SCTLR_EL2', 0x6040),
                  (3, 0, 1, 0, 0): ('SCTLR_EL1', 0x6040)}
EC_NAMES = {0x00: 'unknown', 0x0e: 'illegal-execution-state', 0x16: 'hvc', 0x18: 'trapped-msr-mrs',
            0x20: 'instruction-abort-lower', 0x21: 'instruction-abort-same', 0x24: 'data-abort-lower',
            0x25: 'data-abort-same', 0x32: 'software-step-lower', 0x33: 'software-step-same'}
INTERPRETATION = ('Bytes and disassembly come from the verified original payload files. The probe rewrites '
                  'sptm __TEXT_EXEC instructions to HVC before loading (after upstream m1n1 patch_synthetic_code, '
                  'whose rules are not modelled here); rows with verdict "rewritten" executed as HVC, not as the '
                  'instruction shown. Events are correlated by instruction address (pc-4 for HVC traps, whose ELR '
                  'is the following instruction). Branch targets are printed as PC-relative literals. No boot '
                  'milestone, loop semantics or full machine state is inferred.')


class DisassemblerUnavailable(RuntimeError):
    """llvm-mc could not be found or run; nothing is inferred without it."""


class PayloadUnavailable(ValueError):
    """A layout payload file is missing or does not match its recorded SHA-256."""


class _Misaligned(Exception):
    pass


def _check_va(va):
    if type(va) is not int or not 0 <= va < 1 << 64:
        raise ValueError('Guest address must be an integer in [0, 2**64)')


def resolve(layout, va, *, guest_base=None, guest_size=None):
    """Map a guest address to original payload bytes; a pure function over the layout dict.

    Virtual addresses map through layout['virtual_base']; physical addresses map through the
    owned guest allocation when guest_base/guest_size are given. Returns status 'mapped'
    (fileoff valid), 'outside-image-bytes' (placed segment tail with no file bytes) or
    'unmapped' (no placement, or outside the guest windows) with a detail string.
    """
    _check_va(va)
    virtual_base, size = layout.get('virtual_base'), layout.get('size')
    if type(virtual_base) is not int or type(size) is not int or size <= 0 or virtual_base % 4:
        raise ValueError('Layout lacks a valid integer virtual_base/size')
    result = dict(va=va, va_hex=hex(va), status='unmapped', space=None, guest_offset=None, region=None,
                  image=None, segment=None, fileoff=None, in_placement=False,
                  probe_patched_segment=False, entry_guard=False, detail=None)
    physical = type(guest_base) is int and type(guest_size) is int and guest_size > 0
    if physical and guest_base <= va < guest_base+guest_size:
        result.update(space='physical', guest_offset=va-guest_base)
    elif virtual_base <= va < virtual_base+(guest_size if physical and guest_size > size else size):
        result.update(space='virtual', guest_offset=va-virtual_base)
    else:
        result['detail'] = 'outside the guest virtual window and the owned physical allocation'
        return result
    offset = result['guest_offset']
    if offset >= size:
        result['detail'] = 'beyond the constructed image; scratch RAM has no payload bytes'
        return result
    for name, (start, length) in layout.get('regions', {}).items():
        if length and not name.endswith(('-virt', '-entry')) and start <= offset < start+length:
            result['region'] = name
            break
    result['entry_guard'] = offset == layout.get('entry_offset')
    for placement in layout['placements']:
        if placement['offset'] <= offset < placement['offset']+placement['size']:
            segment = layout['images'][placement['image']]['segments'][placement['segment']]
            within = offset-placement['offset']
            result.update(image=placement['image'], segment=placement['segment'], in_placement=True,
                          probe_patched_segment=placement['image'] == 'sptm' and placement['segment'] == '__TEXT_EXEC')
            if within < segment['filesize']:
                result.update(status='mapped', fileoff=segment['fileoff']+within)
            else:
                result.update(status='outside-image-bytes',
                              detail='segment tail beyond filesize: zero-filled at load, not payload bytes')
            return result
    result['detail'] = 'no image placement covers this offset' + (
        f"; region {result['region']} is built at load time" if result['region'] else '')
    return result


class PayloadReader:
    """Read-only access to layout payload files; each file is hashed through its own open handle before any read."""

    def __init__(self, layout, payload_dir=None):
        self.images = layout['images']
        self.payload_dir = Path(payload_dir) if payload_dir else None
        self.handles, self.verified = {}, {}

    def path(self, name):
        if self.payload_dir is not None:
            return self.payload_dir/(name+'.macho')
        return Path(self.images[name]['path'])

    def verify(self, name):
        if name in self.verified:
            return self.verified[name]
        if name not in self.images:
            raise PayloadUnavailable(f'Layout records no image named {name!r}')
        path, expected = self.path(name), self.images[name]['sha256']
        if not path.is_file():
            raise PayloadUnavailable(f'Payload {name} not found at {path}; expected sha256 {expected}')
        handle = open(path, 'rb')
        try:
            # Hash through the handle later used for reads, so a swapped path cannot bypass verification.
            digest, size = hashlib.sha256(), 0
            for block in iter(lambda: handle.read(1024*1024), b''):
                digest.update(block)
                size += len(block)
            if digest.hexdigest() != expected:
                raise PayloadUnavailable(f'Payload {name} at {path} has sha256 {digest.hexdigest()}; layout recorded {expected}')
        except BaseException:
            handle.close()
            raise
        self.handles[name] = handle
        self.verified[name] = dict(name=name, path=str(path.resolve()), sha256=expected, size=size, verified=True)
        return self.verified[name]

    def read(self, name, fileoff, length):
        identity = self.verify(name)
        if type(fileoff) is not int or type(length) is not int or fileoff < 0 or length < 0 or fileoff+length > identity['size']:
            raise ValueError(f'Read range {fileoff:#x}+{length:#x} outside payload {name} ({identity["size"]:#x} bytes)')
        handle = self.handles[name]
        handle.seek(fileoff)
        data = handle.read(length)
        if len(data) != length:
            raise ValueError('Short payload read')
        return data

    def close(self):
        for handle in self.handles.values():
            handle.close()
        self.handles.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def find_llvm_mc():
    for candidate in (os.environ.get('TRACE_DISASSEMBLY_LLVM_MC'), str(DEFAULT_LLVM_MC), shutil.which('llvm-mc')):
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def disassembler_info(tool=None):
    tool = tool or find_llvm_mc()
    if tool is None:
        raise DisassemblerUnavailable('llvm-mc not found (set TRACE_DISASSEMBLY_LLVM_MC or install Homebrew llvm)')
    try:
        version = subprocess.run([tool, '--version'], capture_output=True, text=True, timeout=30).stdout.strip().splitlines()
    except (OSError, subprocess.SubprocessError) as error:
        raise DisassemblerUnavailable(f'llvm-mc failed to run: {error}')
    return dict(tool=tool, version=version[0] if version else None, invocation=[tool, *MC_ARGS],
                input='one instruction word per stdin line as little-endian hex bytes',
                note='llvm-objdump 23 rejects -b binary; llvm-mc decodes raw words without a container')


def _hex_words(words):
    return '\n'.join(' '.join(f'0x{b:02x}' for b in struct.pack('<I', word)) for word in words)+'\n'


def _run_mc(tool, words, strict=True):
    try:
        proc = subprocess.run([tool, *MC_ARGS], input=_hex_words(words), capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as error:
        raise DisassemblerUnavailable(f'llvm-mc failed to run: {error}')
    if proc.returncode != 0:
        raise DisassemblerUnavailable(f'llvm-mc exited {proc.returncode}: {proc.stderr.strip()[:500]}')
    invalid = {int(m.group(1)) for m in map(INVALID.match, proc.stderr.splitlines()) if m}
    lines = [line for line in proc.stdout.splitlines() if line.strip() and not line.strip().startswith('.')]
    results, cursor = [], 0
    for number, word in enumerate(words, 1):
        if number in invalid:
            results.append(None)
            continue
        if cursor >= len(lines):
            if not strict:
                results.append(None)
                continue
            raise _Misaligned
        line = lines[cursor]
        cursor += 1
        match = ENCODING.search(line)
        text = ' '.join((line[:match.start()] if match else line).split())
        if strict:
            if not match:
                raise _Misaligned
            encoding = bytes(int(part, 0) for part in match.group(1).split(','))
            if encoding != struct.pack('<I', word):
                raise _Misaligned
        results.append(text or None)
    if strict and cursor != len(lines):
        raise _Misaligned
    return results


def disassemble(data, va, count=None, *, tool=None):
    """Decode `count` little-endian AArch64 words from data starting at va (label only).

    Returns rows with `text` None for encodings llvm-mc rejects. A batch whose output cannot
    be matched word-for-word (by line and encoding) is retried one word at a time.
    """
    _check_va(va)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError('Instruction bytes required')
    data = bytes(data)
    if count is None:
        count = len(data)//4
    if type(count) is not int or not 0 <= count <= MAX_WINDOW:
        raise ValueError(f'Instruction count must be within 0..{MAX_WINDOW}')
    if len(data) < 4*count:
        raise ValueError('Insufficient bytes for the requested instruction count')
    if va % 4 or va+4*count > 1 << 64:
        raise ValueError('Instruction address must be 4-byte aligned and within the address space')
    words = list(struct.unpack_from(f'<{count}I', data))
    if not words:
        return []
    tool = tool or find_llvm_mc()
    if tool is None:
        raise DisassemblerUnavailable('llvm-mc not found (set TRACE_DISASSEMBLY_LLVM_MC or install Homebrew llvm)')
    try:
        texts = _run_mc(tool, words)
    except _Misaligned:
        texts = [_run_mc(tool, [word], strict=False)[0] for word in words]
    return [dict(va=va+4*i, va_hex=hex(va+4*i), word=word, word_hex=f'{word:08x}',
                 bytes=struct.pack('<I', word).hex(), text=text, valid=text is not None)
            for i, (word, text) in enumerate(zip(words, texts))]


def hvc_immediate(word):
    return (word >> 5) & 0xffff if word & 0xffe0001f == HVC_WORD else None


def sysreg_fields(word):
    """(read, (op0, op1, CRn, CRm, op2), rt) for MSR/MRS register forms, else None."""
    if word & 0xffd00000 != 0xd5100000:
        return None
    return (bool(word & (1 << 21)), (2 | ((word >> 19) & 1), (word >> 16) & 7, (word >> 12) & 15,
                                     (word >> 8) & 15, (word >> 5) & 7), word & 31)


def classify_original(word):
    """Describe a linked instruction word and whether patch_probe_code rewrites it to HVC."""
    imm = hvc_immediate(word)
    if imm is not None:
        return dict(kind='hvc', rewrite='none', expected_hvc=imm, detail=f'payload already contains HVC #{imm:#x}')
    if word == ERET_WORD:
        return dict(kind='eret', rewrite='always', expected_hvc=0x6080, detail='patch_probe_code rewrites ERET to HVC #0x6080')
    if word & 0xfffffff0 == 0x00201420:
        return dict(kind='apple-0x0020142x', rewrite='always', expected_hvc=0x6090 | (word & 15),
                    detail='Apple-specific word rewritten to HVC #0x609x')
    if word == 0x00201400:
        return dict(kind='apple-0x00201400', rewrite='always', expected_hvc=0x60a0, detail='Apple-specific word rewritten to HVC #0x60a0')
    fields = sysreg_fields(word)
    if fields:
        read, encoding, rt = fields
        base = dict(kind='mrs' if read else 'msr', encoding=list(encoding), read=read, rt=rt,
                    register='S%d_%d_C%d_C%d_%d' % encoding)
        name, tag = KNOWN_REWRITES.get(encoding, (None, None))
        if tag is not None:
            return dict(base, register=name, rewrite='always', expected_hvc=tag | (int(read) << 5) | rt,
                        detail=f'{name} access always rewritten by patch_probe_code')
        if encoding[0] == 3 and encoding[1] == 4:
            return dict(base, rewrite='likely', expected_hvc=None,
                        detail='EL2 register (op0=3, op1=4): rewritten to HVC #0x8xxx when in the probe register list (upstream m1n1 encodings, not modelled here)')
        return dict(base, rewrite='possible', expected_hvc=None,
                    detail='rewritten only if in the probe register list; upstream patch_synthetic_code may also rewrite it')
    return dict(kind='other', rewrite='not-modelled', expected_hvc=None,
                detail='not a patch_probe_code pattern; upstream patch_synthetic_code rules are not modelled')


def describe_hvc(imm):
    if type(imm) is not int or not 0 <= imm <= 0xffff:
        raise ValueError('HVC immediate must be 16 bits')
    result = dict(immediate=imm, immediate_hex=hex(imm))
    if imm == ENTRY_GUARD_IMM:
        return dict(result, category='entry-guard', detail='transient entry-word rewrite; the original word is restored after the first stop')
    if imm & 0xff80 == 0x6000:
        return dict(result, category='probe-control', register='SCTLR_EL2/SCTLR_EL1' if imm & 0x40 else 'HCR_EL2',
                    read=bool(imm & 0x20), rt=imm & 31)
    if imm & 0xc000 == 0x8000:
        return dict(result, category='probe-el2-register', register_index=(imm & 0x3fff) >> 6, read=bool(imm & 0x20), rt=imm & 31)
    if imm == 0x6080:
        return dict(result, category='eret-rewrite')
    if imm & 0xfff0 == 0x6090:
        return dict(result, category='apple-0x0020142x-rewrite', low_bits=imm & 15)
    if imm == 0x60a0:
        return dict(result, category='apple-0x00201400-rewrite')
    return dict(result, category='unclassified')


def event_summary(index, event):
    """Bounded view of a trace event with the address of the instruction it describes."""
    esr, pc = event.get('esr'), event.get('pc')
    ec = esr >> 26 if type(esr) is int and 0 <= esr < 1 << 64 else None
    summary = dict(index=index, kind=str(event.get('kind', 'unclassified')), pc=pc if type(pc) is int else None,
                   pc_hex=hex(pc) if type(pc) is int else None, esr=esr if type(esr) is int else None,
                   esr_hex=hex(esr) if type(esr) is int else None, ec=ec,
                   ec_name=EC_NAMES.get(ec, 'other') if ec is not None else None,
                   reason=event.get('reason'), code=event.get('code'))
    for key in ('register', 'read', 'value', 'sysreg'):
        if key in event:
            summary[key] = event[key]
    if ec == 0x16:
        summary['hvc'] = describe_hvc(esr & 0xffff)
        summary['instruction_va'] = pc-4 if type(pc) is int and pc >= 4 else None
        summary['instruction_va_note'] = 'HVC ELR is the following instruction; the HVC executed at pc-4'
    else:
        summary['instruction_va'] = pc if type(pc) is int else None
    return summary


def window_addresses(center, before, after):
    _check_va(center)
    if type(before) is not int or type(after) is not int or before < 0 or after < 0:
        raise ValueError('Window bounds must be non-negative integers')
    if before+after+1 > MAX_WINDOW:
        raise ValueError(f'Window exceeds {MAX_WINDOW} instructions')
    if center % 4:
        raise ValueError(f'Instruction address {center:#x} is not 4-byte aligned')
    start, end = center-4*before, center+4*after
    if start < 0 or end >= 1 << 64:
        raise ValueError('Window leaves the address space')
    return list(range(start, end+4, 4))


class HitCollector:
    """Per-address event hits inside a bounded address range; sample lists are capped."""

    def __init__(self, low, high, max_hits=8):
        if type(max_hits) is not int or not 0 <= max_hits <= MAX_HITS:
            raise ValueError(f'max_hits must be within 0..{MAX_HITS}')
        self.low, self.high, self.max_hits = low, high, max_hits
        self.hits, self.scanned = {}, 0

    def observe(self, index, event):
        self.scanned += 1
        summary = event_summary(index, event)
        va = summary['instruction_va']
        if va is None or not self.low <= va < self.high:
            return
        entry = self.hits.setdefault(va, dict(count=0, kinds={}, hvc_immediates={}, samples=[], truncated=False))
        entry['count'] += 1
        entry['kinds'][summary['kind']] = entry['kinds'].get(summary['kind'], 0)+1
        if 'hvc' in summary:
            key = summary['hvc']['immediate_hex']
            entry['hvc_immediates'][key] = entry['hvc_immediates'].get(key, 0)+1
        if len(entry['samples']) < self.max_hits:
            entry['samples'].append(summary)
        else:
            entry['truncated'] = True


def _verdict(row):
    resolution, original, hits = row['resolution'], row['original'], row['events']
    applies = bool(resolution['probe_patched_segment']) or bool(resolution['entry_guard'])
    observed = sorted(hits['hvc_immediates']) if hits else []
    result = dict(rewrite_pass_applies=applies, expectation=original['rewrite'] if original else None,
                  expected_hvc=original.get('expected_hvc') if original else None,
                  observed_hvc_immediates=observed, verdict=None, detail=None)
    if resolution['entry_guard']:
        result['expectation'] = 'entry-guard'
        result['expected_hvc'] = ENTRY_GUARD_IMM
    if original is None:
        result.update(verdict='no-payload-bytes', detail='no original bytes to compare; events, if any, are listed')
        return result
    if observed:
        immediates = ', '.join(observed)
        categories = sorted({describe_hvc(int(imm, 16))['category'] for imm in observed})
        if original['kind'] == 'hvc':
            result.update(verdict='payload-hvc', detail=f'payload HVC executed; observed immediates {immediates}')
        else:
            mismatch = ''
            if result['expected_hvc'] is not None and any(int(i, 16) != result['expected_hvc'] for i in observed):
                mismatch = f'; expected #{result["expected_hvc"]:#x} from the original word, observed {immediates}'
            location = '' if applies else ' outside the probe-patched segment'
            result.update(verdict='rewritten', detail=f'original word {row["word_hex"]} executed as HVC ({", ".join(categories)}) '
                          f'{immediates}{location}; the disassembly shown did not execute as such{mismatch}')
        return result
    stepped = bool(hits)
    if not applies:
        result.update(verdict='original', detail='outside the probe-patched segment; no HVC trap recorded here' if stepped
                      else 'outside the probe-patched segment; no event at this address in the supplied events')
        return result
    if result['expectation'] in ('always', 'entry-guard'):
        result.update(verdict='candidate-not-observed' if not stepped else 'candidate-stepped-only',
                      detail='patch_probe_code rewrites this word to HVC; ' + (
                          'events here are not HVC traps (a software-step event marks the instruction about to execute)'
                          if stepped else 'no event at this address in the supplied events source'))
    elif result['expectation'] in ('likely', 'possible'):
        result.update(verdict='candidate-unresolved', detail=original['detail'] + ('; no HVC trap recorded here'
                      if stepped else '; no event at this address in the supplied events source'))
    else:
        result.update(verdict='original', detail='no HVC trap recorded here' if stepped else 'no event at this address in the supplied events source')
    return result


def annotate(layout, addresses, reader, *, guest_base=None, guest_size=None, hits=None, disassembler=None, tool=None):
    """Rows of (resolution, original bytes, disassembly, classification, events, verdict) for each address."""
    if len(addresses) > MAX_WINDOW:
        raise ValueError(f'Window exceeds {MAX_WINDOW} instructions')
    disassembler = disassembler or disassemble
    rows = []
    for va in addresses:
        if va % 4:
            raise ValueError(f'Instruction address {va:#x} is not 4-byte aligned')
        resolution = resolve(layout, va, guest_base=guest_base, guest_size=guest_size)
        rows.append(dict(va=va, va_hex=hex(va), resolution=resolution, word_hex=None, bytes=None,
                         disassembly=None, decodable=None, original=None,
                         events=hits.get(va) if hits else None, probe_rewrite=None))
    readable = [row for row in rows if row['resolution']['status'] == 'mapped']
    start = 0
    while start < len(readable):
        end, head = start, readable[start]['resolution']
        while (end+1 < len(readable) and readable[end+1]['resolution']['image'] == head['image']
               and readable[end+1]['resolution']['fileoff'] == readable[end]['resolution']['fileoff']+4):
            end += 1
        data = reader.read(head['image'], head['fileoff'], 4*(end-start+1))
        for offset, row in enumerate(readable[start:end+1]):
            row['bytes'] = data[4*offset:4*offset+4]
        start = end+1
    if readable:
        decoded = disassembler(b''.join(row['bytes'] for row in readable), readable[0]['va'], len(readable), tool=tool)
        if len(decoded) != len(readable):
            raise ValueError('Disassembler returned a different instruction count')
        for row, item in zip(readable, decoded):
            word = struct.unpack('<I', row['bytes'])[0]
            row.update(word_hex=f'{word:08x}', bytes=row['bytes'].hex(), disassembly=item['text'],
                       decodable=item['text'] is not None, original=classify_original(word))
    for row in rows:
        row['probe_rewrite'] = _verdict(row)
    return rows


def format_rows(rows, center_va=None):
    lines = []
    for row in rows:
        resolution = row['resolution']
        if resolution['status'] == 'mapped':
            where = f"{resolution['image']}/{resolution['segment']}+{resolution['fileoff']:#x}"
        else:
            where = resolution['status'] + (f" ({resolution['region']})" if resolution['region'] else '')
        text = row['disassembly'] or ('<invalid encoding>' if row['word_hex'] else '<no payload bytes>')
        events = ''
        if row['events']:
            kinds = ' '.join(f'{k}x{v}' for k, v in sorted(row['events']['kinds'].items()))
            events = f"  events={row['events']['count']} [{kinds}]"
        marker = '=>' if row['va'] == center_va else '  '
        lines.append(f"{marker} {row['va_hex']:<20} {where:<36} {row['word_hex'] or '--------'}  {text:<40} "
                     f"{row['probe_rewrite']['verdict']}{events}")
    return lines


def load_source(path, events_mode='auto'):
    """Load a bundle directory or a report file; choose and verify the events source."""
    path = Path(path)
    if events_mode not in ('auto', 'window', 'archive'):
        raise ValueError('events mode must be auto, window or archive')
    if path.is_dir():
        manifest, report = load_report(path/'manifest.json'), load_report(path/'report.json')
        if not report.get('run_id') or manifest.get('run_id') != report.get('run_id'):
            raise ValueError('Run identity mismatch between manifest and report')
        source = dict(bundle=str(path.resolve()), report=file_identity(path/'report.json'),
                      manifest=file_identity(path/'manifest.json'), events='window', archive=None)
        expected = manifest.get('capture', {}).get('event_archive_identity')
        archive = path/'events.jsonl'
        if events_mode == 'archive' or (events_mode == 'auto' and expected and archive.is_file()):
            if not expected:
                raise ValueError('Manifest records no finalized event archive identity; use --events window')
            identity = file_identity(archive)
            if any(identity[key] != expected.get(key) for key in ('sha256', 'size')):
                raise ValueError('Archive identity mismatch')
            source.update(events='archive', archive=identity)
            return report, source, archive
        return report, source, None
    if events_mode == 'archive':
        raise ValueError('Archive streaming requires a run bundle directory')
    report = load_report(path)
    return report, dict(bundle=None, report=file_identity(path), manifest=None, events='window', archive=None), None


def _layout(report):
    layout = report.get('layout')
    if not isinstance(layout, dict) or not all(k in layout for k in ('images', 'placements', 'regions', 'virtual_base', 'size')):
        raise ValueError('Report lacks a layout produced by sptm_layout.plan')
    return layout


def _window_events(report):
    start, trace = report.get('trace_start_index', 0), report.get('trace')
    if type(start) is not int or not isinstance(trace, list):
        raise ValueError('Report lacks a trace window')
    return start, trace


def index_mode(report, archive, index, *, before, after, max_hits, reader, disassembler=None, tool=None):
    if type(index) is not int or index < 0:
        raise ValueError('Trace index must be a non-negative integer')
    layout, base, size = _layout(report), report.get('guest_base'), report.get('guest_size')
    if archive is not None:
        center = next((event for i, event in enumerate(iter_event_archive(archive)) if i == index), None)
        if center is None:
            raise ValueError(f'Index {index} beyond the event archive')
        events = enumerate(iter_event_archive(archive))
    else:
        start, trace = _window_events(report)
        if not start <= index < start+len(trace):
            raise ValueError(f'Index {index} outside the retained window [{start}, {start+len(trace)})')
        center = trace[index-start]
        events = ((start+i, event) for i, event in enumerate(trace))
    summary = event_summary(index, center)
    if summary['instruction_va'] is None:
        raise ValueError(f'Event {index} records no instruction address')
    addresses = window_addresses(summary['instruction_va'], before, after)
    collector = HitCollector(addresses[0], addresses[-1]+4, max_hits)
    total = 0
    for i, event in events:
        total = i+1
        collector.observe(i, event)
    if archive is not None and report.get('trace_total_events') not in (None, total):
        raise ValueError('Archive/report event count mismatch')
    rows = annotate(layout, addresses, reader, guest_base=base, guest_size=size, hits=collector.hits,
                    disassembler=disassembler, tool=tool)
    return dict(mode='index', center=summary, window=dict(before=before, after=after, start=addresses[0],
                end=addresses[-1], start_hex=hex(addresses[0]), end_hex=hex(addresses[-1])),
                events_scanned=collector.scanned, addresses_with_events=len(collector.hits),
                max_hits_per_address=max_hits, instructions=rows,
                rewrite_summary=dict(sorted(Counter(r['probe_rewrite']['verdict'] for r in rows).items())))


def pc_mode(report, pc, *, before, after, reader, disassembler=None, tool=None):
    layout = _layout(report)
    addresses = window_addresses(pc, before, after)
    rows = annotate(layout, addresses, reader, guest_base=report.get('guest_base'), guest_size=report.get('guest_size'),
                    disassembler=disassembler, tool=tool)
    return dict(mode='pc', center=dict(pc=pc, pc_hex=hex(pc), instruction_va=pc, trace_correlation=None),
                window=dict(before=before, after=after, start=addresses[0], end=addresses[-1],
                            start_hex=hex(addresses[0]), end_hex=hex(addresses[-1])),
                instructions=rows, rewrite_summary=dict(sorted(Counter(r['probe_rewrite']['verdict'] for r in rows).items())))


def hot_mode(report, profile, *, before, after, reader, disassembler=None, tool=None):
    layout = _layout(report)
    hottest = profile.get('hottest_pcs')
    if not isinstance(hottest, list) or any(not isinstance(e, dict) or type(e.get('pc')) is not int for e in hottest):
        raise ValueError('Profile lacks a hottest_pcs list of {pc, count, ...} objects')
    if profile.get('run_id') and report.get('run_id') and profile['run_id'] != report['run_id']:
        raise ValueError('Profile run identity differs from the report')
    if len(hottest)*(before+after+1) > MAX_WINDOW:
        raise ValueError(f'Hot listing exceeds {MAX_WINDOW} instructions; reduce --before/--after or the profile top count')
    entries = []
    for entry in hottest:
        pc = entry['pc']
        if pc % 4:
            entries.append(dict(pc=pc, pc_hex=hex(pc), count=entry.get('count'), error='PC is not 4-byte aligned'))
            continue
        addresses = window_addresses(pc, before, after)
        rows = annotate(layout, addresses, reader, guest_base=report.get('guest_base'), guest_size=report.get('guest_size'),
                        disassembler=disassembler, tool=tool)
        entries.append(dict(pc=pc, pc_hex=hex(pc), count=entry.get('count'), first_index=entry.get('first_index'),
                            last_index=entry.get('last_index'), resolution=rows[before]['resolution'], instructions=rows))
    return dict(mode='hot', profile_total_events=profile.get('total_events'), hot=entries,
                window=dict(before=before, after=after),
                note='Profile PCs are raw event addresses: for HVC-trap events they are the instruction after the HVC')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('source', type=Path, help='run bundle directory (manifest.json, report.json, events.jsonl) or a report.json[.gz]')
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--index', type=int, help='trace event index to centre the listing on')
    mode.add_argument('--pc', type=lambda s: int(s, 0), help='guest address to disassemble around without trace correlation')
    mode.add_argument('--hot', type=Path, help='trace_profile.py output whose hottest PCs are annotated')
    ap.add_argument('--before', type=int, default=8)
    ap.add_argument('--after', type=int, default=8)
    ap.add_argument('--events', choices=('auto', 'window', 'archive'), default='auto',
                    help='events source for --index: the report window or the verified bundle archive')
    ap.add_argument('--max-hits', type=int, default=8, help=f'event samples retained per address (max {MAX_HITS})')
    ap.add_argument('--payload-dir', type=Path, help='directory holding NAME.macho payloads instead of the recorded paths')
    ap.add_argument('--output', type=Path, help='write the annotated JSON listing atomically')
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args(argv)
    report, source, archive = load_source(a.source, a.events)
    info = disassembler_info()
    with PayloadReader(_layout(report), a.payload_dir) as reader:
        if a.index is not None:
            result = index_mode(report, archive, a.index, before=a.before, after=a.after, max_hits=a.max_hits,
                                reader=reader, tool=info['tool'])
        elif a.pc is not None:
            result = pc_mode(report, a.pc, before=a.before, after=a.after, reader=reader, tool=info['tool'])
        else:
            profile = load_report(a.hot)
            result = hot_mode(report, profile, before=a.before, after=a.after, reader=reader, tool=info['tool'])
            result['profile'] = file_identity(a.hot)
        payloads = list(reader.verified.values())
    result.update(schema_version=1, scope='offline-original-payload-disassembly', guest_boot_verified=False,
                  hardware_executed=False, run_id=report.get('run_id'), source=source, disassembler=info,
                  payloads=payloads, interpretation=INTERPRETATION)
    if not a.quiet:
        if result['mode'] == 'hot':
            for entry in result['hot']:
                print(f"# hot pc {entry['pc_hex']} count={entry.get('count')} {entry.get('error', '')}")
                for line in format_rows(entry.get('instructions', []), entry['pc']):
                    print(line)
        else:
            if result['mode'] == 'index':
                centre = result['center']
                print(f"# event {centre['index']} kind={centre['kind']} pc={centre['pc_hex']} esr={centre['esr_hex']} "
                      f"instruction={hex(centre['instruction_va'])}")
            for line in format_rows(result['instructions'], result['center']['instruction_va']):
                print(line)
    if a.output is not None:
        atomic_json(a.output, result)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
