"""Offline disassembly annotation over synthetic layouts; no Apple payloads, device or guest execution."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import trace_disassembly as td
from run_manifest import atomic_json, file_identity

VBASE = 0xfffffe0000000000
NOP, HVC0, ERET = 0xd503201f, 0xd4000002, 0xd69f03e0
MSR_HCR_X0 = 0xd51c1100          # msr HCR_EL2, x0   -> HVC #0x6000
MRS_X1_SCTLR_EL2 = 0xd53c1001    # mrs x1, SCTLR_EL2 -> HVC #0x6061
MRS_X2_EL2_OTHER = 0xd53c1002 | (5 << 8)  # op0=3 op1=4 CRn=1 CRm=5: probe list dependent
MSR_TTBR0_EL1_X3 = 0xd5182003    # op0=3 op1=0 CRn=2 CRm=0 op2=0
APPLE_2X, APPLE_00 = 0x00201423, 0x00201400
BL = 0x94000010
INVALID = 0xffffffff
CODE = [NOP, MSR_HCR_X0, ERET, MRS_X1_SCTLR_EL2, MRS_X2_EL2_OTHER, MSR_TTBR0_EL1_X3, APPLE_2X, APPLE_00, HVC0, BL, INVALID]
TEXTS = {NOP: 'nop', HVC0: 'hvc #0', ERET: 'eret', MSR_HCR_X0: 'msr HCR_EL2, x0', MRS_X1_SCTLR_EL2: 'mrs x1, SCTLR_EL2',
         MRS_X2_EL2_OTHER: 'mrs x2, S3_4_C1_C5_0', MSR_TTBR0_EL1_X3: 'msr TTBR0_EL1, x3', BL: 'bl #64'}
STEP = 0xca000000


def fake_disassemble(data, va, count=None, *, tool=None):
    count = len(data)//4 if count is None else count
    words = struct.unpack_from(f'<{count}I', data)
    return [dict(va=va+4*i, va_hex=hex(va+4*i), word=w, word_hex=f'{w:08x}', bytes=struct.pack('<I', w).hex(),
                 text=TEXTS.get(w), valid=w in TEXTS) for i, w in enumerate(words)]


def synthetic_layout(root, code=CODE):
    text_exec = b''.join(struct.pack('<I', w) for w in code)
    payload = root/'sptm.macho'
    payload.write_bytes(b'\x11'*0x100+text_exec+b'\x22'*0x100)
    sha = hashlib.sha256(payload.read_bytes()).hexdigest()
    sptm_vmin = 0xfffffff027000000
    segments = {'__TEXT': dict(va=sptm_vmin, size=0x4000, fileoff=0, filesize=0x100),
                '__TEXT_EXEC': dict(va=sptm_vmin+0x4000, size=0x4000, fileoff=0x100, filesize=len(text_exec)),
                '__DATA': dict(va=sptm_vmin+0x8000, size=0x4000, fileoff=0x100+len(text_exec), filesize=0x100)}
    kc = {'__TEXT_EXEC': dict(va=0xfffffe0007004000, size=0x4000, fileoff=0, filesize=0x4000)}
    entry = sptm_vmin+0x4008
    return dict(scope='offline-monitor-layout', guest_boot_verified=False,
                images=dict(sptm=dict(path=str(payload), sha256=sha, segments=segments, vmin=sptm_vmin, vmax=sptm_vmin+0xc000, entry=entry),
                            kernelcache=dict(path=str(root/'kernelcache.macho'), sha256='0'*64, segments=kc,
                                             vmin=0xfffffe0007004000, vmax=0xfffffe0007008000, entry=0xfffffe0007004000)),
                regions={'DeviceTree': [0, 0x4000], 'SPTM-ro': [0x4000, 0x4000], 'SPTM-rx': [0x8000, 0x4000],
                         'SPTM-rw': [0xc000, 0x4000], 'BootKC-rx': [0x10000, 0x4000], 'BootArgs': [0x14000, 0x4000],
                         'RAMDisk': [0x18000, 0], 'SPTM-virt': [sptm_vmin, 0], 'SPTM-entry': [entry, 0]},
                placements=[dict(image='sptm', segment='__TEXT', offset=0x4000, size=0x4000),
                            dict(image='sptm', segment='__TEXT_EXEC', offset=0x8000, size=0x4000),
                            dict(image='sptm', segment='__DATA', offset=0xc000, size=0x4000),
                            dict(image='kernelcache', segment='__TEXT_EXEC', offset=0x10000, size=0x4000)],
                size=0x18000, adt_offset=0x4000, virtual_base=VBASE, entry_offset=0x8008)


def step(pc):
    return dict(reason=2, code=0, pc=pc, esr=STEP, kind='instruction-step')


def hvc(pc_after, imm, **extra):
    return dict(reason=2, code=0, pc=pc_after, esr=0x5a000000 | imm, **extra)


TEXT = VBASE+0x8000
EVENTS = [step(TEXT), step(TEXT+4), hvc(TEXT+8, 0x6000, kind='probe-control', register='HCR_EL2', read=False, value=7),
          step(TEXT+8), hvc(TEXT+12, 0x6080, kind='eret-rewrite'), step(TEXT+12),
          hvc(TEXT+16, 0x6061, kind='probe-control', register='SCTLR_EL2', read=True, value=0),
          step(TEXT+16), step(TEXT+20), step(TEXT+32), hvc(TEXT+36, 0, kind='guest-hvc'), step(TEXT+0x100)]


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.layout = synthetic_layout(Path(self.tmp.name))

    def test_virtual_text_exec_maps_to_file_bytes(self):
        r = td.resolve(self.layout, TEXT+4)
        self.assertEqual((r['status'], r['image'], r['segment'], r['guest_offset'], r['fileoff'], r['in_placement']),
                         ('mapped', 'sptm', '__TEXT_EXEC', 0x8004, 0x104, True))
        self.assertEqual((r['space'], r['region']), ('virtual', 'SPTM-rx'))
        self.assertTrue(r['probe_patched_segment'])
        self.assertFalse(r['entry_guard'])
        self.assertFalse(td.resolve(self.layout, VBASE+0x4000)['probe_patched_segment'])

    def test_entry_guard_flag(self):
        self.assertTrue(td.resolve(self.layout, TEXT+8)['entry_guard'])

    def test_segment_tail_is_outside_image_bytes(self):
        r = td.resolve(self.layout, TEXT+4*len(CODE))
        self.assertEqual(r['status'], 'outside-image-bytes')
        self.assertTrue(r['in_placement'])
        self.assertIsNone(r['fileoff'])
        self.assertEqual(r['segment'], '__TEXT_EXEC')

    def test_load_time_region_has_no_placement(self):
        r = td.resolve(self.layout, VBASE+0x100)
        self.assertEqual((r['status'], r['region'], r['in_placement'], r['image']), ('unmapped', 'DeviceTree', False, None))
        self.assertIn('built at load time', r['detail'])
        self.assertEqual(td.resolve(self.layout, VBASE+0x14000)['region'], 'BootArgs')

    def test_outside_windows_and_beyond_image(self):
        self.assertEqual(td.resolve(self.layout, 0x1000)['status'], 'unmapped')
        self.assertEqual(td.resolve(self.layout, VBASE-4)['status'], 'unmapped')
        beyond = td.resolve(self.layout, VBASE+0x18000)
        self.assertEqual(beyond['status'], 'unmapped')
        self.assertIsNone(beyond['guest_offset'])
        scratch = td.resolve(self.layout, VBASE+0x18000, guest_base=0x800000000, guest_size=0x4000000)
        self.assertEqual((scratch['space'], scratch['guest_offset'], scratch['status']), ('virtual', 0x18000, 'unmapped'))
        self.assertIn('scratch', scratch['detail'])

    def test_physical_mapping_through_guest_allocation(self):
        r = td.resolve(self.layout, 0x800000000+0x8000, guest_base=0x800000000, guest_size=0x4000000)
        self.assertEqual((r['space'], r['status'], r['fileoff']), ('physical', 'mapped', 0x100))
        self.assertEqual(td.resolve(self.layout, 0x800000000+0x8000)['status'], 'unmapped')
        self.assertEqual(td.resolve(self.layout, 0x800000000-4, guest_base=0x800000000, guest_size=0x4000000)['status'], 'unmapped')

    def test_kernelcache_placement_resolves_without_reading(self):
        r = td.resolve(self.layout, VBASE+0x10010)
        self.assertEqual((r['image'], r['segment'], r['fileoff']), ('kernelcache', '__TEXT_EXEC', 0x10))

    def test_rejects_invalid_addresses_and_layouts(self):
        for bad in (-1, 1 << 64, 1.0, '0x10', None):
            with self.assertRaises(ValueError):
                td.resolve(self.layout, bad)
        with self.assertRaises(ValueError):
            td.resolve(dict(self.layout, virtual_base=None), TEXT)
        with self.assertRaises(ValueError):
            td.resolve(dict(self.layout, size=0), TEXT)


class ClassificationTests(unittest.TestCase):
    def test_hvc_immediate_and_rewrite_expectations(self):
        self.assertEqual(td.hvc_immediate(HVC0), 0)
        self.assertEqual(td.hvc_immediate(0xd4000002 | (0x7ffe << 5)), 0x7ffe)
        self.assertIsNone(td.hvc_immediate(0xd4000001))
        self.assertEqual(td.classify_original(ERET)['expected_hvc'], 0x6080)
        hcr = td.classify_original(MSR_HCR_X0)
        self.assertEqual((hcr['kind'], hcr['register'], hcr['rewrite'], hcr['expected_hvc']), ('msr', 'HCR_EL2', 'always', 0x6000))
        sctlr = td.classify_original(MRS_X1_SCTLR_EL2)
        self.assertEqual((sctlr['kind'], sctlr['expected_hvc']), ('mrs', 0x6040 | 0x20 | 1))
        self.assertEqual(td.classify_original(0xd5181000 | 9)['expected_hvc'], 0x6040 | 9)  # msr SCTLR_EL1, x9
        self.assertEqual(td.classify_original(MRS_X2_EL2_OTHER)['rewrite'], 'likely')
        self.assertEqual(td.classify_original(MSR_TTBR0_EL1_X3)['rewrite'], 'possible')
        self.assertEqual(td.classify_original(APPLE_2X)['expected_hvc'], 0x6093)
        self.assertEqual(td.classify_original(APPLE_00)['expected_hvc'], 0x60a0)
        self.assertEqual(td.classify_original(NOP)['rewrite'], 'not-modelled')
        self.assertEqual(td.classify_original(HVC0)['rewrite'], 'none')

    def test_describe_hvc_categories(self):
        self.assertEqual(td.describe_hvc(0x7ffe)['category'], 'entry-guard')
        control = td.describe_hvc(0x6061)
        self.assertEqual((control['category'], control['register'], control['read'], control['rt']),
                         ('probe-control', 'SCTLR_EL2/SCTLR_EL1', True, 1))
        self.assertEqual(td.describe_hvc(0x6000)['register'], 'HCR_EL2')
        el2 = td.describe_hvc(0x8000 | (3 << 6) | 0x20 | 4)
        self.assertEqual((el2['category'], el2['register_index'], el2['read'], el2['rt']), ('probe-el2-register', 3, True, 4))
        self.assertEqual(td.describe_hvc(0x6080)['category'], 'eret-rewrite')
        self.assertEqual(td.describe_hvc(0x6093)['low_bits'], 3)
        self.assertEqual(td.describe_hvc(0x60a0)['category'], 'apple-0x00201400-rewrite')
        self.assertEqual(td.describe_hvc(0)['category'], 'unclassified')
        with self.assertRaises(ValueError):
            td.describe_hvc(0x10000)

    def test_event_instruction_address_uses_pc_minus_4_for_hvc(self):
        s = td.event_summary(3, hvc(TEXT+8, 0x6000, kind='probe-control'))
        self.assertEqual((s['instruction_va'], s['ec'], s['ec_name'], s['hvc']['category']), (TEXT+4, 0x16, 'hvc', 'probe-control'))
        s = td.event_summary(4, step(TEXT+8))
        self.assertEqual((s['instruction_va'], s['ec_name']), (TEXT+8, 'software-step-lower'))
        s = td.event_summary(5, dict(kind='terminal'))
        self.assertEqual((s['instruction_va'], s['esr'], s['ec']), (None, None, None))
        self.assertEqual(td.event_summary(6, dict(pc=0x40, esr=0x62000000, sysreg={'name': 'MDSCR_EL1'}))['sysreg'], {'name': 'MDSCR_EL1'})

    def test_window_bounds(self):
        self.assertEqual(td.window_addresses(0x100, 2, 1), [0xf8, 0xfc, 0x100, 0x104])
        self.assertEqual(len(td.window_addresses(0x10000, 4095, 0)), 4096)
        for before, after, centre in [(4096, 0, 0x10000), (-1, 0, 0x100), (0, 0, 0x102), (1, 0, 0), (0, 1, (1 << 64)-4)]:
            with self.assertRaises(ValueError):
                td.window_addresses(centre, before, after)

    def test_hit_collector_bounds_samples_but_counts_all(self):
        collector = td.HitCollector(TEXT, TEXT+8, max_hits=1)
        for index, event in enumerate([step(TEXT), step(TEXT), hvc(TEXT+8, 0x6000), step(TEXT+8), dict(kind='terminal')]):
            collector.observe(index, event)
        self.assertEqual(collector.scanned, 5)
        self.assertEqual(sorted(collector.hits), [TEXT, TEXT+4])
        self.assertEqual((collector.hits[TEXT]['count'], len(collector.hits[TEXT]['samples']), collector.hits[TEXT]['truncated']), (2, 1, True))
        self.assertEqual(collector.hits[TEXT+4]['hvc_immediates'], {'0x6000': 1})
        with self.assertRaises(ValueError):
            td.HitCollector(0, 8, max_hits=td.MAX_HITS+1)


class PayloadReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.layout = synthetic_layout(self.root)

    def test_reads_only_after_hash_verification(self):
        with td.PayloadReader(self.layout) as reader:
            self.assertEqual(reader.read('sptm', 0x100, 4), struct.pack('<I', NOP))
            self.assertTrue(reader.verified['sptm']['verified'])
            with self.assertRaises(ValueError):
                reader.read('sptm', 0x100, 0x10000)
            with self.assertRaises(ValueError):
                reader.read('sptm', -4, 4)
        self.assertEqual(hashlib.sha256((self.root/'sptm.macho').read_bytes()).hexdigest(), self.layout['images']['sptm']['sha256'])

    def test_missing_and_mismatched_payloads_refuse(self):
        with td.PayloadReader(self.layout) as reader:
            with self.assertRaisesRegex(td.PayloadUnavailable, 'not found'):
                reader.read('kernelcache', 0, 4)
            with self.assertRaises(td.PayloadUnavailable):
                reader.read('nonesuch', 0, 4)
        (self.root/'sptm.macho').write_bytes(b'\x00'*0x200)
        with td.PayloadReader(self.layout) as reader:
            with self.assertRaisesRegex(td.PayloadUnavailable, 'sha256'):
                reader.read('sptm', 0x100, 4)
            self.assertEqual(reader.verified, {})

    def test_payload_dir_override_still_verifies(self):
        other = self.root/'elsewhere'
        other.mkdir()
        (other/'sptm.macho').write_bytes((self.root/'sptm.macho').read_bytes())
        (self.root/'sptm.macho').unlink()
        with td.PayloadReader(self.layout, payload_dir=other) as reader:
            self.assertEqual(reader.read('sptm', 0x104, 4), struct.pack('<I', MSR_HCR_X0))


@unittest.skipUnless(td.find_llvm_mc(), 'llvm-mc not installed')
class LlvmMcTests(unittest.TestCase):
    def test_known_words_and_invalid_encodings(self):
        words = [NOP, HVC0, ERET, INVALID, APPLE_2X, MSR_HCR_X0, 0xd4000002 | (0x7ffe << 5)]
        rows = td.disassemble(b''.join(struct.pack('<I', w) for w in words), 0xfffffe00070b0b20)
        self.assertEqual([r['text'] for r in rows], ['nop', 'hvc #0', 'eret', None, None, 'msr HCR_EL2, x0', 'hvc #0x7ffe'])
        self.assertEqual([r['valid'] for r in rows], [True, True, True, False, False, True, True])
        self.assertEqual(rows[1]['va_hex'], '0xfffffe00070b0b24')
        self.assertEqual(rows[0]['bytes'], '1f2003d5')
        self.assertEqual(td.disassemble(b'', 0x1000), [])
        self.assertIn('llvm-mc', td.disassembler_info()['tool'])

    def test_count_bounds_and_alignment(self):
        data = struct.pack('<I', NOP)*8
        self.assertEqual(len(td.disassemble(data, 0x1000, 2)), 2)
        with self.assertRaises(ValueError):
            td.disassemble(data, 0x1000, 9)
        with self.assertRaises(ValueError):
            td.disassemble(data, 0x1002)
        with self.assertRaises(ValueError):
            td.disassemble(struct.pack('<I', NOP)*(td.MAX_WINDOW+1), 0x1000)
        with self.assertRaises(ValueError):
            td.disassemble('nop', 0x1000)


class DisassemblerFallbackTests(unittest.TestCase):
    def test_missing_tool_is_explicit(self):
        with patch.object(td, 'find_llvm_mc', return_value=None):
            with self.assertRaises(td.DisassemblerUnavailable):
                td.disassemble(struct.pack('<I', NOP), 0x1000)
            with self.assertRaises(td.DisassemblerUnavailable):
                td.disassembler_info()

    def test_misaligned_batch_falls_back_to_single_words(self):
        calls = []

        def fake_run(argv, input, capture_output, text, timeout):
            lines = input.splitlines()
            calls.append(len(lines))
            out, err = [], []
            for number, line in enumerate(lines, 1):
                word = struct.unpack('<I', bytes(int(p, 0) for p in line.split()))[0]
                if word == INVALID:
                    err.append(f'<stdin>:{number}:1: warning: invalid instruction encoding')
                elif word == ERET and len(lines) > 1:
                    continue  # silently dropped line: batch output no longer aligns
                else:
                    out.append(f"\t{TEXTS[word].replace(' ', chr(9), 1)}   // encoding: [{','.join(f'0x{b:02x}' for b in struct.pack('<I', word))}]")
            return subprocess.CompletedProcess(argv, 0, '\n'.join(out)+'\n', '\n'.join(err)+'\n')
        with patch.object(td.subprocess, 'run', fake_run):
            rows = td.disassemble(b''.join(struct.pack('<I', w) for w in [NOP, ERET, INVALID, HVC0]), 0x1000, tool='/fake/llvm-mc')
        self.assertEqual([r['text'] for r in rows], ['nop', 'eret', None, 'hvc #0'])
        self.assertEqual(calls, [4, 1, 1, 1, 1])

    def test_tool_failure_is_reported(self):
        failed = subprocess.CompletedProcess(['x'], 1, '', 'boom')
        with patch.object(td.subprocess, 'run', return_value=failed):
            with self.assertRaisesRegex(td.DisassemblerUnavailable, 'boom'):
                td.disassemble(struct.pack('<I', NOP), 0x1000, tool='/fake/llvm-mc')


class BundleFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.layout = synthetic_layout(self.root)
        self.bundle = self.root/'bundle'
        self.bundle.mkdir()
        self.report = dict(run_id='run-1', layout=self.layout, guest_base=0x800000000, guest_size=0x4000000,
                           entry=0x800000000+0x8008, trace=EVENTS[4:], trace_start_index=4, trace_total_events=len(EVENTS),
                           trace_window=8, stop_reason='instruction-budget', guest_boot_verified=False)
        atomic_json(self.bundle/'report.json', self.report)
        archive = self.bundle/'events.jsonl'
        archive.write_text(''.join(json.dumps({'index': i, 'event': e})+'\n' for i, e in enumerate(EVENTS)))
        self.manifest = dict(run_id='run-1', ended_at='2026-09-09T00:00:00+00:00',
                             capture=dict(complete=True, event_archive_identity=file_identity(archive)))
        atomic_json(self.bundle/'manifest.json', self.manifest)
        patcher = patch.object(td, 'disassemble', fake_disassemble)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, *args):
        output = self.root/'out.json'
        with patch.object(td, 'disassembler_info', return_value=dict(tool='fake', version=None, invocation=['fake'])):
            self.assertEqual(td.main([*args, '--output', str(output), '--quiet']), 0)
        return json.loads(output.read_text())


class ArchiveModeTests(BundleFixture):
    def test_index_listing_marks_rewrites_from_hvc_traps(self):
        result = self.run_cli(str(self.bundle), '--index', '2', '--before', '1', '--after', '9')
        self.assertEqual((result['mode'], result['source']['events'], result['events_scanned']), ('index', 'archive', len(EVENTS)))
        self.assertEqual(result['center']['instruction_va'], TEXT+4)
        self.assertEqual(result['window']['start_hex'], hex(TEXT))
        rows = {r['va']: r for r in result['instructions']}
        self.assertEqual(len(rows), 11)
        self.assertEqual(rows[TEXT]['disassembly'], 'nop')
        self.assertEqual(rows[TEXT]['probe_rewrite']['verdict'], 'original')
        hcr = rows[TEXT+4]
        self.assertEqual((hcr['disassembly'], hcr['probe_rewrite']['verdict']), ('msr HCR_EL2, x0', 'rewritten'))
        self.assertEqual(hcr['probe_rewrite']['observed_hvc_immediates'], ['0x6000'])
        self.assertEqual(hcr['events']['kinds'], {'instruction-step': 1, 'probe-control': 1})
        self.assertIn('did not execute', hcr['probe_rewrite']['detail'])
        eret = rows[TEXT+8]
        self.assertEqual((eret['disassembly'], eret['probe_rewrite']['verdict'], eret['resolution']['entry_guard']), ('eret', 'rewritten', True))
        self.assertEqual(rows[TEXT+12]['probe_rewrite']['verdict'], 'rewritten')
        self.assertEqual(rows[TEXT+16]['probe_rewrite']['verdict'], 'candidate-unresolved')
        self.assertEqual(rows[TEXT+20]['probe_rewrite']['verdict'], 'candidate-unresolved')
        self.assertEqual(rows[TEXT+24]['probe_rewrite']['verdict'], 'candidate-not-observed')
        self.assertEqual(rows[TEXT+32]['probe_rewrite']['verdict'], 'payload-hvc')
        self.assertEqual((rows[TEXT+40]['decodable'], rows[TEXT+40]['disassembly']), (False, None))
        self.assertEqual(result['rewrite_summary']['rewritten'], 3)
        self.assertEqual(result['payloads'][0]['sha256'], self.layout['images']['sptm']['sha256'])
        self.assertFalse(result['guest_boot_verified'])
        self.assertFalse(result['hardware_executed'])
        self.assertEqual(result['source']['archive']['sha256'], self.manifest['capture']['event_archive_identity']['sha256'])

    def test_window_beyond_file_bytes_and_unmapped_rows(self):
        result = self.run_cli(str(self.bundle), '--index', '11', '--before', '1', '--after', '1', '--events', 'window')
        rows = result['instructions']
        self.assertEqual([r['resolution']['status'] for r in rows], ['outside-image-bytes']*3)
        self.assertEqual([r['probe_rewrite']['verdict'] for r in rows], ['no-payload-bytes']*3)
        self.assertEqual(rows[1]['events']['count'], 1)

    def test_archive_identity_and_index_bounds(self):
        with self.assertRaisesRegex(ValueError, 'beyond'):
            td.main([str(self.bundle), '--index', str(len(EVENTS)), '--quiet'])
        (self.bundle/'events.jsonl').write_text('{"index":0,"event":{"pc":4}}\n')
        with self.assertRaisesRegex(ValueError, 'identity'):
            td.main([str(self.bundle), '--index', '0', '--quiet'])
        atomic_json(self.bundle/'manifest.json', dict(self.manifest, run_id='other'))
        with self.assertRaisesRegex(ValueError, 'identity'):
            td.main([str(self.bundle), '--index', '0', '--events', 'window', '--quiet'])

    def test_unfinalized_archive_requires_explicit_window(self):
        atomic_json(self.bundle/'manifest.json', dict(run_id='run-1', capture={}))
        with self.assertRaisesRegex(ValueError, 'finalized'):
            td.main([str(self.bundle), '--index', '5', '--events', 'archive', '--quiet'])
        report, source, archive = td.load_source(self.bundle)
        self.assertEqual((source['events'], archive), ('window', None))

    def test_archive_count_mismatch_rejects(self):
        atomic_json(self.bundle/'report.json', dict(self.report, trace_total_events=len(EVENTS)+1))
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            self.run_cli(str(self.bundle), '--index', '2', '--before', '0', '--after', '0')


class WindowModeTests(BundleFixture):
    def test_report_file_uses_retained_window_only(self):
        result = self.run_cli(str(self.bundle/'report.json'), '--index', '6', '--before', '1', '--after', '1')
        self.assertEqual((result['source']['events'], result['source']['bundle'], result['events_scanned']), ('window', None, len(EVENTS)-4))
        self.assertEqual(result['center']['instruction_va'], TEXT+12)
        rows = {r['va']: r for r in result['instructions']}
        self.assertEqual(rows[TEXT+12]['probe_rewrite']['verdict'], 'rewritten')
        # Index 4 (the ERET-rewrite HVC) is retained; the evicted index-3 step at this address is not.
        self.assertEqual(rows[TEXT+8]['events']['kinds'], {'eret-rewrite': 1})
        with self.assertRaisesRegex(ValueError, 'outside the retained window'):
            td.main([str(self.bundle/'report.json'), '--index', '3', '--quiet'])
        with self.assertRaisesRegex(ValueError, 'bundle directory'):
            td.main([str(self.bundle/'report.json'), '--index', '5', '--events', 'archive', '--quiet'])

    def test_event_without_address_and_missing_layout(self):
        atomic_json(self.root/'r.json', dict(self.report, trace=[dict(kind='terminal')], trace_start_index=0))
        with self.assertRaisesRegex(ValueError, 'no instruction address'):
            td.main([str(self.root/'r.json'), '--index', '0', '--quiet'])
        atomic_json(self.root/'r.json', dict(run_id='x', trace=[]))
        with self.assertRaisesRegex(ValueError, 'layout'):
            td.main([str(self.root/'r.json'), '--pc', hex(TEXT), '--quiet'])


class PcAndHotModeTests(BundleFixture):
    def test_pc_mode_has_no_trace_correlation(self):
        result = self.run_cli(str(self.bundle), '--pc', hex(TEXT+4), '--before', '1', '--after', '1')
        self.assertEqual(result['mode'], 'pc')
        self.assertIsNone(result['center']['trace_correlation'])
        rows = result['instructions']
        self.assertEqual([r['events'] for r in rows], [None]*3)
        self.assertEqual([r['probe_rewrite']['verdict'] for r in rows], ['original', 'candidate-not-observed', 'candidate-not-observed'])
        physical = self.run_cli(str(self.bundle), '--pc', hex(0x800000000+0x8000), '--before', '0', '--after', '0')
        self.assertEqual((physical['instructions'][0]['resolution']['space'], physical['instructions'][0]['disassembly']), ('physical', 'nop'))

    def test_pc_mode_refuses_unaligned_and_oversized_windows(self):
        with self.assertRaisesRegex(ValueError, 'aligned'):
            td.main([str(self.bundle), '--pc', hex(TEXT+2), '--quiet'])
        with self.assertRaisesRegex(ValueError, '4096'):
            td.main([str(self.bundle), '--pc', hex(TEXT), '--before', '4096', '--quiet'])

    def test_missing_payload_is_an_explicit_error(self):
        with self.assertRaisesRegex(td.PayloadUnavailable, 'kernelcache'):
            td.main([str(self.bundle), '--pc', hex(VBASE+0x10000), '--quiet'])

    def test_hot_mode_annotates_profile_pcs(self):
        profile = self.root/'profile.json'
        atomic_json(profile, dict(run_id='run-1', total_events=12, hottest_pcs=[
            dict(pc=TEXT+8, count=5, first_index=3, last_index=9, pc_hex=hex(TEXT+8)),
            dict(pc=VBASE+0x100, count=1, first_index=0, last_index=0), dict(pc=TEXT+2, count=1)]))
        result = self.run_cli(str(self.bundle), '--hot', str(profile), '--before', '1', '--after', '1')
        self.assertEqual((result['mode'], result['profile']['sha256']), ('hot', file_identity(profile)['sha256']))
        first = result['hot'][0]
        self.assertEqual((first['count'], first['resolution']['segment'], first['instructions'][1]['disassembly']), (5, '__TEXT_EXEC', 'eret'))
        self.assertEqual(first['instructions'][1]['probe_rewrite']['verdict'], 'candidate-not-observed')
        self.assertEqual(result['hot'][1]['resolution']['status'], 'unmapped')
        self.assertIn('aligned', result['hot'][2]['error'])
        atomic_json(profile, dict(run_id='run-2', hottest_pcs=[]))
        with self.assertRaisesRegex(ValueError, 'identity'):
            td.main([str(self.bundle), '--hot', str(profile), '--quiet'])
        atomic_json(profile, dict(hottest_pcs=[dict(pc=TEXT)]*3))
        with self.assertRaisesRegex(ValueError, '4096'):
            td.main([str(self.bundle), '--hot', str(profile), '--before', '2000', '--quiet'])
        atomic_json(profile, dict(hottest_pcs=[dict(pc='0x10')]))
        with self.assertRaisesRegex(ValueError, 'hottest_pcs'):
            td.main([str(self.bundle), '--hot', str(profile), '--quiet'])

    def test_text_listing_and_payload_untouched(self):
        before = (self.root/'sptm.macho').read_bytes()
        with td.PayloadReader(self.layout) as reader:
            lines = td.format_rows(td.pc_mode(self.report, TEXT+4, before=1, after=1, reader=reader)['instructions'], TEXT+4)
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[1].startswith('=> ' + hex(TEXT+4)))
        self.assertIn('sptm/__TEXT_EXEC+0x104', lines[1])
        self.assertIn('candidate-not-observed', lines[1])
        self.assertEqual((self.root/'sptm.macho').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
