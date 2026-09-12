"""Exercise real patched source without importing the hardware HV module."""
import ast
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest


def module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class LoaderPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = os.environ.get('M1N1_CHECKOUT')
        if not root:
            raise unittest.SkipTest('Set M1N1_CHECKOUT to test applied patch')
        cls.root = Path(root)
        cls.helper = module(cls.root/'proxyclient/m1n1/guest_boot.py')
        cls.types = module(cls.root/'proxyclient/m1n1/tgtypes.py')
        cls.serializers = {i:getattr(cls.types, f'BootArgs_r{i}') for i in (1,2,3)}

    def test_all_real_serializers_accept_parsed_hex_revision(self):
        for revision, serializer in self.serializers.items():
            with self.subTest(revision=revision):
                wire = revision.to_bytes(2,'little') + bytes(serializer.sizeof()-2)
                args = serializer.parse(wire)
                chosen = self.helper.bootargs_serializer(args, self.serializers)
                self.assertEqual(chosen.build(args), wire)

    def test_unsupported_revision_before_hv_init_or_load_raw_side_effects(self):
        tree = ast.parse((self.root/'proxyclient/m1n1/hv/__init__.py').read_text())
        hv = next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='HV')
        for method in ('init','load_raw'):
            node = next(n for n in hv.body if isinstance(n,ast.FunctionDef) and n.name==method)
            namespace = {'bootargs_serializer':self.helper.bootargs_serializer,
                         **{f'BootArgs_r{i}':s for i,s in self.serializers.items()}}
            exec(compile(ast.Module(body=[node], type_ignores=[]), '<public-HV-method>', 'exec'), namespace)
            # No proxy, device, ADT or heap exists on this object: any access before
            # rejection would raise AttributeError, not the expected ValueError.
            obj = SimpleNamespace(u=SimpleNamespace(ba=SimpleNamespace(revision=4)),tba=SimpleNamespace(revision=4))
            with self.subTest(method=method), self.assertRaisesRegex(ValueError,'Unsupported guest bootargs'):
                namespace[method](obj, b'') if method=='load_raw' else namespace[method](obj)

    def nodes(self, running='cpu10'):
        return [SimpleNamespace(name=n,state='running' if n==running else 'stopped') for n in ('cpu0','cpu1','cpu10')]

    def test_single_core_retains_nonzero_multidigit_boot_cpu(self):
        self.assertEqual(self.helper.select_guest_cpus(self.nodes(),single_core=True), {'cpu10'})

    def test_legacy_selector_preserved(self):
        self.assertEqual(self.helper.select_guest_cpus(self.nodes('cpu0'),'01'), {'cpu0','cpu1'})

    def test_delimited_selector_supports_multidigit(self):
        self.assertEqual(self.helper.select_guest_cpus(self.nodes(),'0,10'), {'cpu0','cpu10'})

    def test_missing_boot_cpu_unknown_cpu_and_empty_selector_rejected(self):
        for spec in ('01','9','', '0,,10'):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                self.helper.select_guest_cpus(self.nodes(),spec)

    def test_ambiguous_boot_cpu_or_conflicting_modes_rejected(self):
        with self.assertRaises(ValueError):
            self.helper.select_guest_cpus(self.nodes('absent'),single_core=True)
        with self.assertRaises(ValueError):
            self.helper.select_guest_cpus(self.nodes(),'0,10',True)

    def test_first_event_marker_only_once(self):
        tree = ast.parse((self.root/'proxyclient/m1n1/hv/__init__.py').read_text())
        hv = next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='HV')
        node = next(n for n in hv.body if isinstance(n,ast.FunctionDef) and n.name=='handle_exception')
        # Execute the actual first guard only, without loading exception/device state.
        node.body = node.body[:1]
        lines=[]
        namespace={'print':lambda *args,**kw:lines.append(args[0])}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<event-marker>','exec'),namespace)
        obj=SimpleNamespace(started=True)
        for _ in range(2): namespace['handle_exception'](obj,None,None,None)
        self.assertEqual(lines,['GUEST-STAGE first-event'])
