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
| Probe policy and simulated callbacks | `test_probe_controls.py`, `test_probe_guards.py`, `test_probe_exceptions.py`, `test_guest_debug.py`, `test_live_ttbr.py` |
| Reports and trace analysis | `test_trace_*.py`, `test_classify_xnu_map_progress.py`, `test_xnu_console.py` |
| Pipeline, receipts, and cleanup policy | `test_probe_pipeline.py`, `test_fresh_gate_receipt.py`, `test_guarded_pause.py`, `test_free_run_watchdog.py` |

For a focused run, use discovery's pattern option:

```sh
python3 -m unittest discover -s tests -p 'test_run_manifest.py' -v
```

The large `test_probe_controls.py` also covers experimental features. Its size
and reliance on callback extraction are documented in the
[maintenance review](../docs/CODE-REVIEW.md). A green suite is not a CPU model,
a test of production safety, or evidence of a macOS boot.
