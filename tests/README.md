# Host tests

[Repository home](../README.md) · [Source setup](../setup/README.md) · [Contributing](../CONTRIBUTING.md)

Run from the repository root. The suite exercises host parsers, synthetic data,
mock transports, and selected upstream code. It does not boot a guest or access
a physical target. Some tests compile small C libraries with the host compiler.

## Start without a target or upstream checkout

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_docs.py
```

This is a useful first check on a fresh clone. Tests requiring an upstream
checkout, LLVM, or retained evidence report skips. Inspect those reasons:
“OK” with many skips is not the same coverage as a configured environment.
If your shell already sets `M1N1_CHECKOUT` or `VEL2_CHECKOUT`, those tests will use
that source tree; use a clean shell for a true fresh-clone check.

## Add pinned-source coverage

Follow the [source setup guide](../setup/README.md), activate its host environment,
then run the same discovery command with `python`. `M1N1_CHECKOUT` must refer to
the patched loader track and `VEL2_CHECKOUT` to the patched runtime track.
A host C compiler is needed for the C-engine, batching, and filter tests.

| Coverage | Prerequisite | What a pass establishes |
| --- | --- | --- |
| Pure Python, archive/catalog, synthetic fixture tests | Python | Behavior for the tested inputs |
| Applied loader and callback replay | Matching patched trees and host dependencies | Source-level and host-control behavior |
| Native C unit tests | Patched runtime tree and host C compiler | Selected C logic on the host architecture |
| Disassembly tests | LLVM tools | Annotation behavior for the test bytes |
| Historical evidence checks | Specific private captures/payloads | Agreement with those retained inputs |

Private-evidence tests normally skip in a public clone. The small
[fixture](fixtures/debug-events.json) is public; raw traces and Apple inputs are
not. See the [artifact policy](../docs/artifact-storage.md).

## Find the relevant tests

Most files follow `test_<module>.py`. For example, `test_run_manifest.py` checks
`scripts/run_manifest.py`, and `test_check_docs.py` checks documentation navigation.
There are some broader groups:

| Group | Files |
| --- | --- |
| Manifests, archives, catalog, transfer/import | `test_run_manifest.py`, `test_event_archive.py`, `test_experiment_store.py`, `test_fetch_pipeline_archive.py`, `test_import_probe_pipeline.py`, `test_ingest_probe_bundle.py` |
| Payload/layout and translation | `test_guest_payload.py`, `test_guest_preflight.py`, `test_sptm_layout.py`, `test_guest_pt.py`, `test_replay_table_snapshot.py` |
| Upstream loader and C runtime | `test_loader_patch.py`, `test_vel2.py`, `test_step_batch.py`, `test_step_filter.py` |
| Probe policy and simulated callbacks | `test_probe_controls.py`, the focused `test_probe_*` modules below, `test_probe_guards.py`, `test_probe_exceptions.py`, `test_guest_debug.py`, `test_live_ttbr.py` |
| Reports and trace analysis | `test_trace_*.py`, `test_classify_xnu_map_progress.py`, `test_xnu_console.py` |
| Pipeline, receipts, and cleanup policy | `test_probe_pipeline.py`, `test_fresh_gate_receipt.py`, `test_guarded_pause.py`, `test_free_run_watchdog.py` |

For a focused run, use discovery's pattern option:

```sh
python3 -m unittest discover -s tests -p 'test_run_manifest.py' -v
```

## Focused probe tests

The former large `test_probe_controls.py` is split by concern. Shared synthetic
input builders live in [probe_control_support.py](probe_control_support.py),
which contains no test cases. The original 124 test methods remain discoverable
exactly once across these modules:

| File | Concern |
| --- | --- |
| [test_probe_controls.py](test_probe_controls.py) | Translation/control policy and budgets |
| [test_probe_adapters.py](test_probe_adapters.py) | Adapter protocols and failure cleanup |
| [test_probe_platform.py](test_probe_platform.py) | Pure platform contracts and compatibility helpers |
| [test_probe_handoff_controls.py](test_probe_handoff_controls.py) | Handoff boundaries and returned contexts |
| [test_probe_txm_entry.py](test_probe_txm_entry.py) | Context-entry validation |
| [test_probe_txm_trace.py](test_probe_txm_trace.py) | TXM trace results |
| [test_probe_allocation_trace.py](test_probe_allocation_trace.py) | End-to-end synthetic allocation/fast-path scenario |
| [test_probe_retype_survey.py](test_probe_retype_survey.py) | Retype survey outcomes and bounds |
| [test_probe_native_controls.py](test_probe_native_controls.py) | Native platform event contracts |
| [test_probe_permission_windows.py](test_probe_permission_windows.py) | Temporary permission-window state and cleanup |
| [test_probe_observation.py](test_probe_observation.py) | Observation/virtual-world state |

A focused `-p 'test_probe_controls.py'` run now covers only translation/control
policy. Use full discovery for all probe coverage. Every listed module also runs
independently with discovery's `-p` option.

[refactor_audit.py](refactor_audit.py) is a separate, one-time source-structure
comparison against the pre-refactor Git revision; it is not automatically run by
unit-test discovery. Its scope is documented in the
[package guide](../scripts/sptm_probe/README.md).

A green suite is not a CPU model, a test of production safety, or evidence of a
macOS boot. The current refactor's configured run reports 491 tests and 5 expected
private-evidence skips; the unconfigured run reports 483 tests and 180 skips.
