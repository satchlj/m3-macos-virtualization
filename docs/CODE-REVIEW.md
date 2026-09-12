# Code organization and maintenance review

[Repository home](../README.md) · [Script map](../scripts/README.md) · [Contributing](../CONTRIBUTING.md)

Review date: 2026-09-11. Scope: the public snapshot, its entry points, module
boundaries, tests, and documentation. This is not a comprehensive correctness or
security audit. The documentation cleanup does not change the research runtime.

## Assessment

The repository is usable for research review, but the experimental runtime is
not yet organized like a reusable library. Small host utilities have clearer
boundaries than the central probe. Readers should start with manifests, archive
handling, and pure analysis modules, then consult the probe only for a specific
research question.

| Area | Assessment | Consequence |
| --- | --- | --- |
| Independent host modules | Generally small and have module docstrings | Easier to inspect and test in isolation |
| `sptm_entry_probe.py` | About 6,300 lines; large setup, callback, and cleanup sections | High review cost and risk when mixing unrelated changes |
| `test_probe_controls.py` | About 3,300 lines | Test intent is harder to find despite substantial coverage |
| Callback replay | Extracts definitions/callbacks from source ASTs | Keeps tests away from hardware setup, but couples tests to source structure |
| Python layout | Standalone scripts with sibling imports and test `sys.path` setup | Run from the documented paths; this is not an installed Python package |
| Formatting | Dense expressions and multiple statements per line occur in older code | A future formatting pass should be isolated from behavioral changes |
| Defaults and historical tools | Some refer to private, attempt-specific artifacts | Their existence is not a fresh-clone example or a portable interface |
| Patch tracks | Exact revisions and hashes distinguish two independent bases | Preserve patch bytes unless deliberately regenerating the corresponding lock |

The GPL-derived layout module is an important architectural boundary. See
[LICENSES.md](../LICENSES.md); splitting files or moving imports does not remove
its licensing obligations.

## Reading order for code review

1. `run_manifest.py` and `trace_diff.py`: report identity, event streams, comparisons.
2. `experiment_store.py` and the import tools: local evidence organization.
3. Pure inspection and reporting modules, paired with their `test_*.py` files.
4. `replay_debug_probe.py` and `tests/probe_fixtures.py`: the synthetic test boundary.
5. The two patch tracks and central probe, using the relevant evidence note.

Links to every script are in the [script map](../scripts/README.md). The
[test guide](../tests/README.md) explains external prerequisites and skips.

## Maintenance backlog

These are outstanding engineering improvements, not completed research results.
They are separate from the scientific milestones in [STATUS.md](STATUS.md).

| Priority | Work | Completion criterion |
| --- | --- | --- |
| First | Split the large test file by concern | Every existing test remains discoverable; coverage and skip reasons remain explicit |
| First | Document input/output schemas of reusable host tools | Small synthetic examples round-trip, with required/optional fields and version behavior explained |
| Next | Isolate independent reporting and configuration concerns from the central probe | Small reviewable changes preserve behavior and evidence contracts; avoid simultaneous runtime changes |
| Next | Establish a consistent formatting baseline | Formatting-only changes are separately reviewed and the applicable checks still pass |
| Next | Clarify supported Python/platform combinations | Automated checks exercise a declared matrix rather than implying one from a minimum version |
| Later | Decide whether reusable host tools warrant a package | An explicit API and invocation model replace ad hoc path assumptions without breaking existing scripts |

## Documentation work completed in this review

- A shorter landing page directs readers by purpose instead of requiring a
  hardware setup before orientation.
- Current status, historical evidence, and engineering debt have separate homes.
- Stage 0's stale “current frontier” summary is replaced with historical context.
- Directory indexes cover every research note and script.
- Setup, test prerequisites, skipped coverage, licensing, and private-evidence
  limitations are explicit.
- `scripts/check_docs.py` checks local paths, Markdown reachability from the root
  README, and script-index coverage without a network request. It does not check
  external URLs, heading fragments, or command correctness.

No broad code-formatting, module extraction, hardware execution, or new hardware
result is part of this cleanup. Runtime tidiness remains a documented follow-up,
not a claim that the large probe has been refactored.

## Validation recorded for this cleanup

On 2026-09-11 with Python 3.14.7:

- Configured host suite: **491 tests, 5 skips, no failures**. The skips require
  private historical traces, device trees, or a retained SPTM payload absent from
  the public clone. The six documentation-checker tests are included.
- Both external patched source trees used for the configured run matched the
  commits and recorded source hashes in the repository's lock files.
- Documentation checker: all **97 Markdown files** reachable from the root README,
  local link paths valid against the source listing, and all **44 Python scripts**
  included in the script map. External URLs and heading anchors were not checked.
- `git diff --check` passed; existing runtime code and patch hashes were unchanged.

Before adding the checker, a fresh-clone-style run with neither upstream checkout
variable set reported 477 tests and 180 skips, with no failures. This illustrates
why the test guide distinguishes basic host checks from configured coverage;
it is not the final suite count.
