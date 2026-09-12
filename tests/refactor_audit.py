#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One-time structural audit against the pre-refactor Git revision.

No project code or hardware is executed. This compares the refactor with its
baseline, not future intentional behavior changes. See the package README for
the limits of this comparison. Checks remain enabled under Python -O.
"""
import ast
import copy
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = '2cab764'
REFACTORED = '5460e9f'
TEST_MODULES = (
    'test_probe_controls', 'test_probe_adapters', 'test_probe_platform',
    'test_probe_handoff_controls', 'test_probe_txm_entry', 'test_probe_txm_trace',
    'test_probe_allocation_trace', 'test_probe_retype_survey',
    'test_probe_native_controls', 'test_probe_permission_windows',
    'test_probe_observation',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def baseline(path):
    return ast.parse(subprocess.check_output(
        ['git', 'show', BASELINE + ':' + path], cwd=ROOT, text=True,
    ))


def definitions(path):
    relative = Path(path).resolve().relative_to(ROOT)
    return ast.parse(subprocess.check_output(
        ['git', 'show', REFACTORED + ':' + str(relative)], cwd=ROOT, text=True,
    )).body


def methods(classes):
    return [method for cls in classes if isinstance(cls, ast.ClassDef)
            for method in cls.body if isinstance(method, ast.FunctionDef)]


class RestoreBindings(ast.NodeTransformer):
    """Inline handler calls and reverse the two explicit binding prefixes."""
    def __init__(self, handlers):
        self.handlers = handlers

    def visit_Expr(self, node):
        call = node.value
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)):
            key = (call.func.value.id, call.func.attr)
            if key in self.handlers:
                require([ast.unparse(arg) for arg in call.args] == ['run', 'event_state']
                        and not call.keywords, 'Unexpected handler arguments')
                return [self.visit(copy.deepcopy(stmt)) for stmt in self.handlers[key].body]
        return self.generic_visit(node)

    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name) and node.value.id in ('run', 'event_state'):
            return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node)
        return self.generic_visit(node)


def main():
    original = baseline('scripts/sptm_entry_probe.py')
    old = next(node for node in ast.walk(original)
               if isinstance(node, ast.FunctionDef) and node.name == 'stopped')
    package = ROOT / 'scripts/sptm_probe'
    handlers = {(path.stem, node.name): node
                for name in ('allocation', 'exceptions', 'handoff', 'native_platform',
                             'retype', 'txm_entry', 'txm_entry_setup', 'txm_step',
                             'txm_trace')
                for path in (package / 'events' / (name + '.py'),)
                for node in definitions(path) if isinstance(node, ast.FunctionDef)}
    new = next(node for node in definitions(package / 'callback.py')
               if isinstance(node, ast.FunctionDef) and node.name == 'stopped')
    # The only new event-local initialization is a fresh namespace for arguments.
    expected_init = ast.parse(
        'event_state = SimpleNamespace(reason=reason, code=code, info=info)'
    ).body[0]
    require(ast.dump(new.body[0]) == ast.dump(expected_init), 'Event state initialization changed')
    new = RestoreBindings(handlers).visit(new)
    new.body = [copy.deepcopy(old.body[0])] + new.body[1:]
    new.args = copy.deepcopy(old.args)
    left, right = ast.dump(old), ast.dump(new)
    require(left == right, 'Callback structure differs from the refactor baseline')

    old_runtime = next(node for node in original.body
                       if isinstance(node, ast.FunctionDef) and node.name == 'run_probe')
    new_runtime = next(node for node in definitions(package / 'runtime.py')
                       if isinstance(node, ast.FunctionDef) and node.name == 'run_probe')
    nonlocals = set(old.body[0].names)

    synchronized = []

    class RestoreLifecycle(ast.NodeTransformer):
        def visit_Assign(self, node):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target = node.targets[0].id
                if target == 'callback_bindings':
                    expected = ast.parse('callback_bindings = RunBindings({**globals(), **locals()})').body[0]
                    require(ast.dump(node) == ast.dump(expected), 'Run binding construction changed')
                    return None
                if target == 'stopped':
                    expected = ast.parse('stopped = partial(dispatch_event, callback_bindings)').body[0]
                    require(ast.dump(node) == ast.dump(expected), 'Callback registration changed')
                    return copy.deepcopy(old)
                if (target in nonlocals and isinstance(node.value, ast.Attribute)
                        and isinstance(node.value.value, ast.Name)
                        and node.value.value.id == 'callback_bindings'):
                    require(node.value.attr == target, 'Mismatched nonlocal synchronization')
                    synchronized.append(target)
                    return None
            return self.generic_visit(node)

    new_runtime = RestoreLifecycle().visit(new_runtime)
    require(Counter(synchronized) == Counter(nonlocals), 'Nonlocal synchronization changed')
    require(ast.dump(old_runtime) == ast.dump(new_runtime), 'Run lifecycle changed')
    old_cli = next(node for node in original.body
                   if isinstance(node, ast.FunctionDef) and node.name == 'main')
    new_cli = next(node for node in definitions(package / 'cli.py')
                   if isinstance(node, ast.FunctionDef) and node.name == 'main')
    roots = [node for node in ast.walk(new_cli) if isinstance(node, ast.Subscript)
             and ast.unparse(node.value) == 'Path(__file__).resolve().parents']
    require(len(roots) == 1 and ast.literal_eval(roots[0].slice) == 2,
            'Unexpected CLI repository-root expression')
    roots[0].slice = ast.Constant(value=1)
    require(ast.dump(old_cli) == ast.dump(new_cli), 'CLI behavior changed')

    pure = {}
    for module in ('constants', 'adapters', 'platform'):
        for node in definitions(package / (module + '.py')):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                pure[node.name] = node
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        pure[target.id] = node
    count = 0
    for node in original.body:
        if getattr(node, 'name', None) in ('main', 'run_probe'):
            continue
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            name = node.name
        elif isinstance(node, ast.Assign):
            name = node.targets[0].id
        else:
            continue
        require(ast.dump(node) == ast.dump(pure[name]), 'Changed definition: ' + name)
        count += 1

    old_tests = baseline('tests/test_probe_controls.py')
    old_cases = [method for method in methods(old_tests.body) if method.name.startswith('test_')]
    new_cases = [method for module in TEST_MODULES
                 for method in methods(definitions(ROOT / 'tests' / (module + '.py')))
                 if method.name.startswith('test_')]
    require(Counter(map(ast.dump, old_cases)) == Counter(map(ast.dump, new_cases)),
            'Moved test methods changed or are missing/duplicated')
    old_control = next(cls for cls in old_tests.body
                       if isinstance(cls, ast.ClassDef) and cls.name == 'ProbeControlTests')
    support = definitions(ROOT / 'tests/probe_control_support.py')
    new_control = next(cls for cls in support
                       if isinstance(cls, ast.ClassDef) and cls.name == 'ProbeControlFixture')
    old_helpers = [method for method in methods([old_control])
                   if not method.name.startswith('test_')]
    new_helpers = methods([new_control])
    require(Counter(map(ast.dump, old_helpers)) == Counter(map(ast.dump, new_helpers)),
            'Shared fixture methods changed')
    print(json.dumps({
        'baseline_commit': BASELINE,
        'callback_ast_sha256': hashlib.sha256(left.encode()).hexdigest(),
        'reconstructed_callback_ast_sha256': hashlib.sha256(right.encode()).hexdigest(),
        'unchanged_top_level_definitions': count,
        'extracted_branch_bodies': len(handlers),
        'unchanged_test_methods': len(old_cases),
        'unchanged_shared_fixture_methods': len(old_helpers),
        'run_lifecycle_structure_preserved': True,
        'cli_structure_preserved_with_repository_root_adjustment': True,
    }, indent=2))


if __name__ == '__main__':
    main()
