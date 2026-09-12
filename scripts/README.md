# Script map

[Repository home](../README.md) · [Code review](../docs/CODE-REVIEW.md) · [Tests](../tests/README.md)

Scripts are grouped by purpose, not by readiness. Some are importable helpers;
not every file is a command-line program. Paths are kept stable because research
notes and tests refer to them. Read a tool's module docstring and its argument
parser before assuming a default is appropriate for your inputs.

Offline tools may read private payloads, invoke a local disassembler, or write
reports. “Offline” means no target connection, not necessarily no filesystem
side effects. Historical decoders are tied to the report format and attempt
named in their source. Helpers can be used by either replay or live code; their
caller's transport determines whether an operation accesses a target.

Target-connected tools belong to the experimental research workflow, including
those described as read-only. This index is a source-reading aid, not an execution
sequence. Review [the evidence and safety model](../docs/SAFETY.md) separately.

## Offline inspection and analysis

| File | Purpose |
| --- | --- |
| [guest_preflight.py](guest_preflight.py) | Offline diagnostics only. Never imports/executes m1n1 or opens a device. |
| [inspect_guest_payload.py](inspect_guest_payload.py) | Inspect Mach-O load commands only; no disassembly, imports of m1n1 or device I/O. |
| [sptm_layout.py](sptm_layout.py) | Offline segmented SPTM/TXM/BootKC placement from the pinned public QEMU loader. |
| [sprr_leaf_permissions.py](sprr_leaf_permissions.py) | Decode one stage-1 leaf descriptor under recorded SPRR permission registers. |
| [sprr_permissions.py](sprr_permissions.py) | Offline exact representability audit of upstream SPRR permission mappings. |
| [trace_disassembly.py](trace_disassembly.py) | Annotate bounded guest trace windows with disassembly of the ORIGINAL payload bytes. |
| [trace_events_summary.py](trace_events_summary.py) | Summarize non-step events of a verified finalized run bundle in one archive pass. |
| [trace_exception_window.py](trace_exception_window.py) | Locate the first guest vector entry in a verified complete trace archive. |
| [trace_profile.py](trace_profile.py) | Summarize complete event archives without loading full traces or decoding code. |
| [classify_xnu_map_progress.py](classify_xnu_map_progress.py) | Classify verified XNU/SPTM MAP_PAGE progress without making a loop claim. |
| [decode_panic.py](decode_panic.py) | Decode a report's outcome: launch, sptm_panic (resolving strings+site), or budget. |
| [decode_attempt27.py](decode_attempt27.py) | Decode an attempt report into one of the three attempt-27 outcomes. |
| [replay_table_snapshot.py](replay_table_snapshot.py) | Replay bounded guest translation from hash-verified diagnostic table pages. |
| [replay_debug_probe.py](replay_debug_probe.py) | Replay debug traps through the real probe callback and an in-memory transport. |

## Local evidence and repository maintenance

| File | Purpose |
| --- | --- |
| [run_manifest.py](run_manifest.py) | Host-side attempt manifests and atomic partial reports; no device APIs. |
| [trace_diff.py](trace_diff.py) | Versioned, conservative comparisons of bounded JSON trace reports. |
| [experiment_store.py](experiment_store.py) | Local immutable experiment catalog; ingestion and comparison never run a target. |
| [import_experiment_evidence.py](import_experiment_evidence.py) | Import checksum-verified historical SPTM reports without inventing provenance. |
| [import_probe_pipeline.py](import_probe_pipeline.py) | Verify and import a downloaded pipeline archive without target access. |
| [ingest_probe_bundle.py](ingest_probe_bundle.py) | Register a finalized probe bundle and optional console log, without device access. |
| [fresh_gate_receipt.py](fresh_gate_receipt.py) | Issue and atomically consume authenticated fresh-boot gate receipts. |
| [guarded_pause.py](guarded_pause.py) | Local, typed decisions for a device-owning process paused at a policy guard. |
| [check_docs.py](check_docs.py) | Check local Markdown paths and navigation without fetching links or running code. |

## Transfer tooling

| File | Purpose |
| --- | --- |
| [fetch_pipeline_archive.py](fetch_pipeline_archive.py) | Copy a closed pipeline archive from a USB host, then import it locally. |

## Helpers used by the experimental runtime

| File | Purpose |
| --- | --- |
| [boot_data_audit.py](boot_data_audit.py) | Observe guest ownership of ADT boot ranges; never grant mappings or remove data. |
| [boot_data_relocation.py](boot_data_relocation.py) | Bounded RAM copies for selected boot inputs; no firmware or MMIO execution. |
| [guest_debug.py](guest_debug.py) | Guest-only debug state for the bounded SPTM probe, with no proxy access. |
| [guest_exception_stop.py](guest_exception_stop.py) | Pure, incremental stop decision for recorded guest vector PCs. |
| [guest_handoff.py](guest_handoff.py) | Classify an eret target by live translation and verified loaded entry bytes. |
| [guest_pt.py](guest_pt.py) | Bounded 16 KiB, 47-bit guest table walk for pre-entry address checks. |
| [step_batch.py](step_batch.py) | Drain bounded native software-step records; never emulate their instructions. |
| [zero_loop.py](zero_loop.py) | Recognize one exact, synthetic-assembler-verified bounded zero-fill primitive. |
| [free_run_watchdog.py](free_run_watchdog.py) | Bound a native guest using m1n1's existing timer-polled user interrupt. |
| [extract_xnu_console.py](extract_xnu_console.py) | Recover early XNU character output from observed SPTM dispatch calls. |

## Target-connected tools and experiment runners

| File | Purpose |
| --- | --- |
| [chainload_preserve_boot.py](chainload_preserve_boot.py) | Load the research runtime from a fresh baseline, preserving boot-data aliases. |
| [clean_reboot_target.py](clean_reboot_target.py) | Request a guarded target reboot and wait for the m1n1 proxy to return. |
| [inspect_pending_ttbr.py](inspect_pending_ttbr.py) | Read-only validation of the latest stopped probe's proposed root switch. |
| [probe_diagnostics.py](probe_diagnostics.py) | Read bounded printable guest data after a completed probe; never resume a guest. |
| [run_fresh_gate.py](run_fresh_gate.py) | Run the nonce-bound fresh gate and issue an authenticated one-use receipt. |
| [run_probe_pipeline.py](run_probe_pipeline.py) | Run one probe, collect diagnostics, and publish a fast compressed transfer bundle. |
| [sptm_entry_probe.py](sptm_entry_probe.py) | Stable command/import facade for the [probe implementation](sptm_probe/README.md). |
| [vel2_smoke.py](vel2_smoke.py) | Compile a synthetic vEL2 smoke test; --execute explicitly enables RAM-only target work. |
| [step_batch_smoke.py](step_batch_smoke.py) | Exercise native batching with 64 known additions; hardware requires --execute. |
| [free_run_watchdog_smoke.py](free_run_watchdog_smoke.py) | RAM-only native busy-loop; prove the timer kick exits with a live proxy. |

## Input and output conventions

Reusable report/trace tools generally consume JSON reports or finalized run
bundles; a bundle has a manifest, report, and event journal. Some tools also
require local source/payload files to verify identities. A historical filename
under `artifacts/` is not included merely because it appears in a default or
example. See [artifact storage](../docs/artifact-storage.md) and
[experiment automation](../docs/experiment-automation.md).

The layout module has a GPL-2.0-or-later exception to the repository's MIT default.
Read [LICENSES.md](../LICENSES.md) before redistributing combined tools.

## Probe implementation modules

See the [package guide](sptm_probe/README.md) for responsibility boundaries and
state lifetimes. These are internal modules, not additional CLI entry points.

| Module | Purpose |
| --- | --- |
| [sptm_probe/__init__.py](sptm_probe/__init__.py) | Internal implementation of the stable sptm_entry_probe entry point. |
| [sptm_probe/adapters.py](sptm_probe/adapters.py) | Firmware adapter interfaces and teardown auditing. |
| [sptm_probe/callback.py](sptm_probe/callback.py) | Callback lifecycle and ordered dispatch, shared by live code and host replay. |
| [sptm_probe/cli.py](sptm_probe/cli.py) | Bounded SPTM instruction trace in isolated guest RAM; not a macOS boot loader. |
| [sptm_probe/constants.py](sptm_probe/constants.py) | Pinned register names and source/byte contracts; not portable defaults. |
| [sptm_probe/events/__init__.py](sptm_probe/events/__init__.py) | Ordered event-handler implementation; not standalone commands. |
| [sptm_probe/events/allocation.py](sptm_probe/events/allocation.py) | Allocation event handlers extracted from the original probe callback. |
| [sptm_probe/events/exceptions.py](sptm_probe/events/exceptions.py) | Exceptions event handlers extracted from the original probe callback. |
| [sptm_probe/events/handoff.py](sptm_probe/events/handoff.py) | Handoff event handlers extracted from the original probe callback. |
| [sptm_probe/events/native_platform.py](sptm_probe/events/native_platform.py) | Native platform event handlers extracted from the original probe callback. |
| [sptm_probe/events/retype.py](sptm_probe/events/retype.py) | Retype event handlers extracted from the original probe callback. |
| [sptm_probe/events/txm_entry.py](sptm_probe/events/txm_entry.py) | Txm entry event handlers extracted from the original probe callback. |
| [sptm_probe/events/txm_entry_setup.py](sptm_probe/events/txm_entry_setup.py) | Txm entry setup event handlers extracted from the original probe callback. |
| [sptm_probe/events/txm_step.py](sptm_probe/events/txm_step.py) | Txm step event handlers extracted from the original probe callback. |
| [sptm_probe/events/txm_trace.py](sptm_probe/events/txm_trace.py) | Txm trace event handlers extracted from the original probe callback. |
| [sptm_probe/platform.py](sptm_probe/platform.py) | Existing platform contracts, compatibility transforms, and restore helpers. |
| [sptm_probe/runtime.py](sptm_probe/runtime.py) | Existing run setup, source loading, execution lifecycle, and cleanup. |
