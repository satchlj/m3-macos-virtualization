# Probe implementation

[Script map](../README.md) · [Code review](../../docs/CODE-REVIEW.md) · [Tests](../../tests/README.md)

The public command remains `scripts/sptm_entry_probe.py`. That file also
re-exports the existing constants, helpers, and entry functions used by other
modules. Files in this package are implementation modules, not new commands.

## Responsibility map

| Module | Responsibility |
| --- | --- |
| [cli.py](cli.py) | Existing argument parsing, validation, signal handling, and attempt finalization |
| [runtime.py](runtime.py) | Existing setup, source loading, execution lifecycle, and cleanup |
| [constants.py](constants.py) | Pinned names, addresses, and source/byte contracts |
| [adapters.py](adapters.py) | Firmware adapter interfaces, GL1 redirect, and teardown auditing |
| [platform.py](platform.py) | Platform contracts, compatibility transforms, and restore helpers |
| [callback.py](callback.py) | Ordered event dispatch, exception handling, and callback finalization |
| [events/allocation.py](events/allocation.py) | Allocation-trace and authenticated-return branches |
| [events/retype.py](events/retype.py) | Retype-survey and three-site HVC branches |
| [events/descriptor.py](events/descriptor.py) | Descriptor and leaf binding branches |
| [events/txm_trace.py](events/txm_trace.py) | TXM trace and debug-gate branches |
| [events/txm_step.py](events/txm_step.py) | Bounded TXM context-step branch |
| [events/txm_entry.py](events/txm_entry.py) | Context-entry validation branch |
| [events/txm_entry_setup.py](events/txm_entry_setup.py) | Context-entry preparation branch |
| [events/native_platform.py](events/native_platform.py) | Existing native platform event branches |
| [events/handoff.py](events/handoff.py) | Existing handoff branches |
| [events/exceptions.py](events/exceptions.py) | General exception decoding and dispatch branches |

## State lifetime and control flow

`RunBindings` keeps one run's dependencies and mutable callback state. It retains
its dictionary by identity, so the replay harness can replace synthetic inputs
without a second implementation of the handler logic. Runtime setup supplies
its existing globals and locals; this is a dependency snapshot, not source-code
evaluation. The seven former `nonlocal` values are written back for the enclosing
run's cleanup after execution returns or raises.

Each callback creates a fresh `event_state` namespace for its arguments and
scratch values. Extracted handlers share that namespace for the duration of the
callback. It is not reused for the next event. Nested helper functions and
exception aliases retain their local Python scope.

The original conditions and their order remain in the dispatcher. Twenty-two
complete branch bodies moved into named handlers. The outer exception handlers
and `finally` sequence remain in `callback.py`; a helper failure returns to that
same finalization path. Handler modules do not construct transports or run
experiments at import time.

[replay_debug_probe.py](../replay_debug_probe.py) now calls this same callback
directly. It still extracts a small set of setup definitions for its synthetic
bindings; it no longer reconstructs the whole callback from a large source file.
Mocks for moved dependencies must target their owner, such as
`sptm_probe.runtime.plan`, rather than a facade's imported alias.

## Refactor validation

The baseline is Git revision `2cab764`. The
[structural audit](../../tests/refactor_audit.py) can be run from the repository root:

```sh
python3 tests/refactor_audit.py
```

It reverses the explicit binding references and inlines extracted handlers, then
compares the resulting callback AST with the baseline. It also checks the 187
moved top-level definitions, all 124 moved test bodies, and 11 shared fixture
methods. It also compares the run lifecycle and CLI after accounting for the
callback binding and the relocated repository-root expression. The audit passes with normal Python and `python3 -O`. It is specific to
this refactor, not a permanent prohibition on future intentional behavior changes.

Structural equality after normalization is not a proof of runtime binding or
hardware equivalence. The host suite checks the refactored bindings and behavior:
491 tests ran with 5 private-evidence skips, and each of the 11 split test modules
passed independently. Command-line help was byte-for-byte identical. No target
execution is part of this validation. See the
[recorded validation](../../docs/refactor-validation.json).

The package retains upstream notices and the repository's licensing boundaries.
Using the GPL-derived layout module in a combined program still carries its
obligations; see [LICENSES.md](../../LICENSES.md).
