# Code organization and maintenance review

[Repository home](../README.md) · [Script map](../scripts/README.md) · [Contributing](../CONTRIBUTING.md)

Updated 2026-09-11 after the module refactor. Scope: source organization, host
regression coverage, and documentation. This is not a comprehensive correctness
or security audit, and no new hardware result is claimed.

## Current organization

The central probe now has a stable facade and a focused implementation package.
The [package guide](../scripts/sptm_probe/README.md) explains its modules, state
lifetimes, and validation. Existing commands and helper imports remain available
through `scripts/sptm_entry_probe.py`.

| Area | Before this refactor | Current structure |
| --- | --- | --- |
| Probe entry point | 6,326 lines | 20-line facade |
| Probe implementation | Setup, constants, helpers, and callback in one file | 17 package modules, largest 822 lines |
| Event callback | 4,573-line nested function | Ordered dispatcher and 22 extracted branch bodies grouped by concern |
| Probe control tests | 3,295-line file | 124 original methods across 11 focused modules; shared fixture methods separated |
| Callback replay | Reconstructed the callback from the large file's AST | Calls the same callback used by runtime; small setup-definition extraction remains |

The large single-event dispatcher was split along complete branch boundaries.
Its condition order, exception handling, and finalization sequence are retained.
Run bindings and per-event scratch state are explicit. This makes the code easier
to locate without mixing algorithm changes into a structural refactor.

The GPL-derived layout module remains a licensing boundary. Moving code or
changing an import path does not remove its obligations; see
[LICENSES.md](../LICENSES.md).

## Reading order

1. [Overview](OVERVIEW.md) and [current status](STATUS.md) for the research scope.
2. `run_manifest.py`, `trace_diff.py`, and the evidence import tools for host-side
   data handling; find them in the [script map](../scripts/README.md).
3. The [probe package guide](../scripts/sptm_probe/README.md), then `cli.py`,
   `runtime.py`, and `callback.py` for responsibility boundaries.
4. The event module for a specific concern, paired with the matching
   [focused test module](../tests/README.md#focused-probe-tests).

## What still needs work

These are engineering tasks, separate from the hardware milestones in
[STATUS.md](STATUS.md).

| Priority | Work | Completion criterion |
| --- | --- | --- |
| First | Document reusable host tools' input/output schemas | Small synthetic examples and explicit required/optional fields and version behavior |
| Next | Narrow and type the run-binding contracts | Preserve deferred dependency lookup, shared mutable state, and event isolation under the same regression coverage |
| Next | Reduce remaining setup-AST extraction in replay | Tests still exercise production definitions without invoking hardware setup |
| Next | Establish a consistent formatting baseline | A separately reviewed formatting-only change preserves behavior |
| Next | Declare and test supported Python/platform combinations | A real test matrix replaces assumptions based on a minimum version |
| Later | Decide whether independent host tools warrant a package | Explicit APIs and invocation rules replace ad hoc sibling imports without breaking commands |

`runtime.py` intentionally keeps setup and cleanup together. One long synthetic
allocation scenario also remains a single test: preserving its end-to-end
assertions was preferable to splitting its sequence merely to reduce line count.
Older code still has dense expressions and some long lines. The refactor
preserved those statements and their explanatory comments for reviewability.

## Validation

[Recorded results](refactor-validation.json), using Python 3.14.7:

- Configured host suite: **491 tests, 5 skips, no failures or errors**.
- Unconfigured host suite: **483 tests, 180 skips, no failures or errors**.
- All 11 split test modules also passed independently.
- The full test inventory is unchanged after accounting for module/class moves.
  All 124 moved test method bodies and 11 shared fixture methods have identical ASTs.
- All 187 moved top-level definitions have identical ASTs. After reversing explicit
  binding references and inlining extracted branches, the callback AST matches
  the pre-refactor callback. Run lifecycle and CLI structure also match after
  accounting for their explicit relocation changes. The [audit tool](../tests/refactor_audit.py) produces
  the same results with normal Python and `python3 -O`.
- The command-line help is byte-for-byte unchanged. Manifest finalization and
  interruption tests still exercise the original command facade; their mocks
  now target the layout dependency in its owning runtime module.
- Pinned patch hashes are unchanged. No target was accessed.

The five configured skips require private historical traces, device trees, or a
retained SPTM payload absent from the public clone. Structural checks support the
refactor review; they do not establish CPU or hardware equivalence. Hardware
findings in the historical notes retain their original scope.

## Documentation maintenance

The root README provides reading paths. `STATUS.md` is the current milestone
summary; older notes retain historical context. The script and documentation
indexes cover all included modules and Markdown pages. `scripts/check_docs.py`
checks local paths, Markdown reachability, and script-index coverage. It does not
check external URLs, heading fragments, or the correctness of example commands.
