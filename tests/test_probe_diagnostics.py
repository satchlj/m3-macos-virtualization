from pathlib import Path
import hashlib
import os
import tempfile
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from probe_diagnostics import (printable_pointers, parse_va_read, read_guest_va,
    verify_panic_carveout, read_panic_carveout_header, PANIC_CARVEOUT_BASE,
    PANIC_CARVEOUT_SIZE, verify_apple_physical_timer_stop,
    APPLE_PHYSICAL_TIMER_PC, APPLE_PHYSICAL_TIMER_ESR)
from probe_diagnostics import (verify_socd_trace_buffer, read_socd_trace_buffer,
    SOCD_TRACE_BASE, SOCD_TRACE_SIZE, SOCD_TRACE_FAR, SOCD_TRACE_PC,
    SOCD_TRACE_ESR)


class DiagnosticBoundsTests(unittest.TestCase):
    def test_socd_trace_read_is_exactly_fault_and_adt_bound(self):
        blob = b'archived device tree'
        digest = hashlib.sha256(blob).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'host-device-tree.adt'
            path.write_bytes(blob)
            event = {'kind': 'xnu-native-exception', 'pc': SOCD_TRACE_PC,
                     'esr': SOCD_TRACE_ESR, 'far': SOCD_TRACE_FAR,
                     'regs': [0] * 9 + [2, 0, SOCD_TRACE_FAR]}
            report = {'run_id': 'run', 'device_tree_sha256': digest,
                      'trace': [event]}
            manifest = {'run_id': 'run', 'status': 'finished', 'captured_inputs': {
                'host-device-tree.adt': {'path': str(path), 'sha256': digest,
                                         'size': len(blob)}}}
            class Node:
                _properties = {'device_type': 'socd-trace-ram'}
                def get_reg(self, index):
                    self.last_index = index
                    return SOCD_TRACE_BASE, SOCD_TRACE_SIZE
            class Tree:
                def __getitem__(self, name):
                    if name == 'socd-trace-ram':
                        return Node()
                    raise KeyError(name)
            verified = verify_socd_trace_buffer(
                report, manifest, path, blob, blob, lambda _: Tree())
            calls = []
            data = read_socd_trace_buffer(
                lambda address, size: calls.append((address, size)) or b'S' * size,
                verified)
            self.assertEqual(calls, [(SOCD_TRACE_BASE, SOCD_TRACE_SIZE)])
            self.assertEqual(len(data), 0x39c)
            for field, delta in (('pc', 4), ('esr', 1), ('far', 4)):
                changed = dict(event)
                changed[field] += delta
                with self.subTest(field=field), self.assertRaises(ValueError):
                    verify_socd_trace_buffer(
                        dict(report, trace=[changed]), manifest, path, blob, blob,
                        lambda _: Tree())

    def test_attempt66_archived_adt_has_exact_socd_trace_region(self):
        root = Path(__file__).resolve().parents[1]
        run = root/'artifacts/runs/observe-sprr/attempt-66/runs/1755ffa6-2b38-4d70-9db0-7716b2838a26'
        archived, manifest_path = run/'inputs/host-device-tree.adt', run/'manifest.json'
        report_path = root/'artifacts/runs/observe-sprr/attempt-66/report.json'
        if not all(path.exists() for path in (archived, manifest_path, report_path)):
            self.skipTest('attempt-66 archived evidence is unavailable')
        import json
        checkout = Path(os.environ['VEL2_CHECKOUT'])/'proxyclient'
        sys.path.insert(0, str(checkout))
        try:
            from m1n1.adt import load_adt
            blob = archived.read_bytes()
            result = verify_socd_trace_buffer(
                json.loads(report_path.read_text()), json.loads(manifest_path.read_text()),
                archived, blob, blob, load_adt)
        finally:
            sys.path.remove(str(checkout))
        self.assertEqual((result['base'], result['size']),
                         (SOCD_TRACE_BASE, SOCD_TRACE_SIZE))

    def test_socd_trace_read_rejects_unverified_or_truncated_region(self):
        with self.assertRaises(ValueError):
            read_socd_trace_buffer(lambda *_: b'', {
                'base': SOCD_TRACE_BASE + 1, 'size': SOCD_TRACE_SIZE})
        with self.assertRaises(ValueError):
            read_socd_trace_buffer(lambda *_: b'X' * (SOCD_TRACE_SIZE - 1), {
                'base': SOCD_TRACE_BASE, 'size': SOCD_TRACE_SIZE})

    def test_apple_timer_alias_read_requires_exact_retained_stop(self):
        event = {'kind': 'xnu-native-exception',
                 'pc': APPLE_PHYSICAL_TIMER_PC,
                 'esr': APPLE_PHYSICAL_TIMER_ESR,
                 'regs': [0] * 8 + [2]}
        report = {'stop_reason': 'xnu-native-exception', 'trace': [event]}
        result = verify_apple_physical_timer_stop(report)
        self.assertEqual(result['candidate_encoding'], [3, 4, 15, 4, 3])
        self.assertFalse(result['routing_established'])
        self.assertFalse(result['physical_s3_1_bank_touched'])
        for change in ('pc', 'esr', 'value', 'stop'):
            changed = {'stop_reason': report['stop_reason'],
                       'trace': [dict(event, regs=list(event['regs']))]}
            if change == 'stop':
                changed['stop_reason'] = 'hang'
            elif change == 'value':
                changed['trace'][0]['regs'][8] = 3
            else:
                changed['trace'][0][change] += 4 if change == 'pc' else 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_apple_physical_timer_stop(changed)

    def test_panic_carveout_header_is_identity_bound_and_exactly_bounded(self):
        blob = b'archived device tree'
        digest = hashlib.sha256(blob).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'host-device-tree.adt'
            path.write_bytes(blob)
            report = {'run_id': 'run', 'device_tree_sha256': digest}
            manifest = {'run_id': 'run', 'status': 'finished', 'captured_inputs': {
                'host-device-tree.adt': {'path': str(path), 'sha256': digest,
                                         'size': len(blob)}}}
            class Node:
                _properties = {'region-id-98': (PANIC_CARVEOUT_BASE,
                                                PANIC_CARVEOUT_SIZE)}
            class Tree:
                def __getitem__(self, name):
                    if name == 'chosen':
                        return self
                    if name == 'carveout-memory-map':
                        return Node()
                    raise KeyError(name)
            verified = verify_panic_carveout(
                report, manifest, path, blob, blob, lambda _: Tree())
            calls = []
            data = read_panic_carveout_header(
                lambda address, size: calls.append((address, size)) or b'P' * size,
                verified)
            self.assertEqual(calls, [(PANIC_CARVEOUT_BASE, 64)])
            self.assertEqual(data, b'P' * 64)

    def test_attempt62_archived_adt_has_verified_panic_carveout(self):
        root = Path(__file__).resolve().parents[1]
        run = root/'artifacts/runs/observe-sprr/attempt-62/runs/2c2a3857-b3ca-4d85-88bc-8a9fe1b17960'
        archived = run/'inputs/host-device-tree.adt'
        manifest_path = run/'manifest.json'
        report_path = root/'artifacts/runs/observe-sprr/attempt-62/report.json'
        if not all(path.exists() for path in (archived, manifest_path, report_path)):
            self.skipTest('attempt-62 archived evidence is unavailable')
        import json
        checkout = Path(os.environ['VEL2_CHECKOUT'])/'proxyclient'
        sys.path.insert(0, str(checkout))
        try:
            from m1n1.adt import load_adt
            blob = archived.read_bytes()
            result = verify_panic_carveout(
                json.loads(report_path.read_text()), json.loads(manifest_path.read_text()),
                archived, blob, blob, load_adt)
        finally:
            sys.path.remove(str(checkout))
        self.assertEqual((result['base'], result['size']),
                         (PANIC_CARVEOUT_BASE, PANIC_CARVEOUT_SIZE))

    def test_panic_carveout_rejects_identity_tuple_and_truncation_changes(self):
        with self.assertRaises(ValueError):
            read_panic_carveout_header(lambda *_: b'', {
                'base': PANIC_CARVEOUT_BASE + 1, 'size': PANIC_CARVEOUT_SIZE,
                'header_size': 64})
        with self.assertRaises(ValueError):
            read_panic_carveout_header(lambda *_: b'X' * 63, {
                'base': PANIC_CARVEOUT_BASE, 'size': PANIC_CARVEOUT_SIZE,
                'header_size': 64})

    def test_va_read_parser_is_bounded(self):
        self.assertEqual(parse_va_read('0x1234:0x400'), (0x1234, 0x400))
        for spec in ('1234', 'x:4', '0:0', '0:4097', '0xffffffffffffffff:2'):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                parse_va_read(spec)

    def test_va_read_translates_each_page_and_stays_in_owned_ram(self):
        report = {'guest_base': 0x10000, 'guest_size': 0xc000}
        controls = {'ttbr0': 0x10000, 'ttbr1': 0x14000}
        memory = bytearray(0xc000)
        memory[0x8000:0x8004] = b'abcd'
        memory[0xa000:0xa004] = b'efgh'
        pages = {}
        def read(address, length):
            return bytes(memory[address-0x10000:address-0x10000+length])
        def walk(va, ttbr0, ttbr1, read_page):
            read_page(ttbr0)
            pa = 0x18000 + (va & 3) if va < 0x4000 else 0x1a000 + (va & 3)
            return {'pa': pa, 'level': 3, 'descriptor': 0x403, 'access_flag': True}
        with patch('probe_diagnostics.translate', side_effect=walk):
            data, mappings = read_guest_va(report, controls, read, 0x3ffc, 8, pages)
        self.assertEqual(data, b'abcdefgh')
        self.assertEqual([m['bytes'] for m in mappings], [4, 4])
        self.assertEqual(pages, {0x10000: bytes(memory[:0x4000])})

    def test_va_read_rejects_translation_outside_owned_ram(self):
        report = {'guest_base': 0x10000, 'guest_size': 0x8000}
        controls = {'ttbr0': 0x10000, 'ttbr1': 0x14000}
        with patch('probe_diagnostics.translate', return_value={
                'pa': 0x20000, 'level': 3, 'descriptor': 0x403, 'access_flag': True}):
            with self.assertRaises(ValueError):
                read_guest_va(report, controls, lambda a, n: b'\0' * n, 0x4000, 16)

    def test_optional_snapshot_retains_only_walked_owned_table_pages(self):
        report={'guest_base':0x10000,'guest_size':0x8000,
                'monitor_mmu_controls':{'ttbr0':0x10000,'ttbr1':0x14000},
                'trace':[{'regs':[0x14000]}]}
        def walk(va, root0, root1, read_page):
            read_page(root0)
            return {'pa':va}
        pages={}
        with patch('probe_diagnostics.translate',side_effect=walk):
            printable_pointers(report,lambda a,n:b'\0'*n,pages)
        self.assertEqual(pages,{0x10000:b'\0'*0x4000})

    def test_text_is_bounded_and_binary_data_ignored(self):
        report={'guest_base':0x10000,'guest_size':0x8000,'monitor_mmu_controls':{'ttbr0':0x10000,'ttbr1':0x14000},
                'trace':[{'regs':[0x17ff0,0x20000]}]}
        calls=[]
        def read(addr,size):
            calls.append((addr,size))
            self.assertTrue(0x10000<=addr<addr+size<=0x18000)
            return b'example text\0'.ljust(size,b'\0')
        with patch('probe_diagnostics.translate',side_effect=lambda va,*args:{'pa':va}):
            result=printable_pointers(report,read)
        self.assertEqual(result[0]['text'],'example text')
        self.assertEqual(calls,[(0x17ff0,16)])
        with patch('probe_diagnostics.translate',return_value={'pa':0x10000}):
            self.assertEqual(printable_pointers(report,lambda a,n:b'\xff'*n),[])
