# Experiment automation foundation

The goal is many reproducible experiments with parallel preparation and analysis, while each physical target has one execution owner. Tahoe remains the target. The first implementation provides a local immutable catalog and conservative trace comparisons; it never opens a device connection or executes an experiment.

## Implemented now

`scripts/experiment_store.py` uses SQLite schema 1 for experiment definitions, attempts and artifact references, with SHA-256-addressed files for raw content. Definitions and attempts are immutable. Repeating an experiment creates a new attempt even when bytes are identical; supplying an explicit run ID makes an ingestion retry idempotent and rejects conflicting data. Files are copied and hashed before metadata is committed, and concurrent publication cannot overwrite existing objects.

Raw JSON/gzip reports and opaque attachments retain their original bytes. Reports summarize only producer-supplied claims; ingestion does not infer a successful boot or assign its own machine's source revision to historical evidence. Missing provenance remains unknown. Comparisons return both provenance records and explicitly do not certify their completeness.

SQLite runs locally in WAL mode with full synchronization and short write transactions. Processes can prepare files concurrently, but SQLite permits only one writer at a time. Keep the live catalog on a local filesystem, not a shared network or synchronized Drive folder. See [SQLite WAL constraints](https://sqlite.org/wal.html). For multiple hosts, first use per-host artifact bundles sent to a central ingestor; move to a server database/object store if measured workload warrants it.

`verify` checks database integrity, foreign keys and all registered object hashes. `backup` takes a SQLite snapshot, independently copies its referenced files and verifies the result before writing `BACKUP_COMPLETE`. It refuses an existing destination. A failed backup can leave a partial directory without that marker. There is no garbage collector: interrupted or rejected imports can leave unreferenced objects, deliberately retained for now. Producers should finish and close artifacts before submitting them; copying and hashing cannot make a concurrently changing source a coherent capture.

## Use

From the repository root with the development environment activated:

```sh
python scripts/experiment_store.py init
python scripts/import_experiment_evidence.py
python scripts/experiment_store.py list
python scripts/experiment_store.py verify
python scripts/experiment_store.py diff \
  evidence/2026-09-09/mmu-sptm/sptm-entry-mmu-enable.json.gz \
  evidence/2026-09-09/mmu-sptm/sptm-entry-timer.json.gz \
  --mode control-flow-v1
python scripts/experiment_store.py backup artifacts/backups/my-snapshot
```

The evidence importer verifies every checksum in the retained bundle before registering reports. It imports 18 bounded SPTM reports with deterministic IDs and explicit historical provenance. Re-running it does not create duplicate attempts. The default catalog is ignored `artifacts/catalog`; use `--store PATH` before the subcommand for a different location. The importer also accepts `--store PATH`.

For a new experiment, write a definition JSON object and a provenance JSON object, then ingest a completed producer report:

```sh
python scripts/experiment_store.py define translation-case-001 local/definition.json
python scripts/experiment_store.py ingest translation-case-001 local/report.json \
  --run-id translation-case-001-attempt-001 \
  --provenance local/provenance.json --artifact console=local/console.log
python scripts/experiment_store.py show translation-case-001-attempt-001
```

The definition and provenance schemas are currently open JSON objects. This supports incomplete historical records; it is not yet a validated execution manifest contract.

## What a diff means

`exact-v1` compares complete event objects. `control-flow-v1` retains event reason/code/kind, PC, ESR and selected system-register fields. It normalizes a PC only when it lies within the report's explicit guest physical allocation; high virtual addresses remain exact. Register values, stack, fault address and other fields are omitted and these exclusions are reported. Equal projected events do not establish equal machine state.

Both modes report event counts, common prefix, first same-index divergence, kind counts and selected outcome differences. A missing trace is not an empty trace. There is no insertion/deletion alignment or semantic decoder yet. The JSON reader caps decompressed input at 256 MiB; large GPU captures will need a versioned streaming format such as NDJSON rather than increasing this limit indefinitely.

The retained MMU-enable versus timer comparison has a 249-event common prefix in the control-flow view. Its next events have the same staged SPRR operation and guest-relative PC but different raw ESR/HVC indices. That is evidence of instrumentation encoding differences, not by itself proof of different guest semantics. Future adapters must version and record those encoding mappings before normalizing them.

## Planned execution and analysis contract

The intended flow is an immutable experiment definition, a recorded attempt, execution by a device worker, raw artifact publication, then independent versioned decoding and comparison. Preserve raw bytes so a decoder correction can be applied to every previous run without repeating hardware work.

Each new execution manifest should record:

- Hypothesis, changed parameters, comparison baseline, backend (`hardware`, `replay` or `simulator`), seed and execution budgets.
- Source commits plus dirty-diff hashes, patch and payload hashes, tool versions, full command, and identities of the images actually running.
- Device identity, OS/firmware, reset state, parent session/attempt, start/end times, and capture completeness.
- Producer outcome, timeout/error/cleanup details and recovery observations; retain partial logs even for failed runs.

These fields are a design target, not claims about historical reports. Decoder outputs should name their code/version/configuration and input artifact hashes. A decoded interpretation is a derived artifact, never a replacement for raw evidence.

Execution state will distinguish planned, claimed, running and terminal attempts, including failure, timeout and unknown device state. A retry is a new attempt. For each physical M3, a broker must own the connection exclusively; an expired lease must quarantine an uncertain target until recovery establishes a quiescent state. It must not let a second worker start merely because the first worker stopped reporting.

Parallelism belongs initially in test-case generation, replay/simulation, decoding, classification and trace comparisons. Multiple physical targets can later execute independent queues. One target's stateful monitor/GPU experiments remain serialized. A replay or virtual target result must remain distinguishable from hardware evidence.

## Next implementation points

1. Initial manifest generation and a run-bundle writer are implemented below. Refine the execution manifest contract with connected-target observations before implementing a scheduler.
2. Add a single-device execution broker and explicit recovery state after the first connected sessions establish reliable reset behavior.
3. Add versioned event adapters and semantic alignment using observed trace differences. Retain exact comparison as a reference.
4. Adapt upstream AGX capture windows and raw-object archives once Tahoe guest execution and M3 mappings work. Validate Tahoe decoders from evidence; older firmware labels are not sufficient.
5. Add batch analysis jobs keyed by input hashes and decoder versions. Measure ingestion/analysis bottlenecks before adding distributed infrastructure.

Validation on September 9: all 158 research tests pass, including 24 new catalog/diff tests. Tests cover four concurrent writer processes, separate repeated attempts, idempotent retries, metadata rollback, corrupted objects, bounded parsing and independent backups. The actual catalog contains 18 verified historical reports and has an independently verified initial backup. This is correctness validation, not a throughput benchmark. No hardware execution or GPU ABI compatibility was tested by this work.

## Automatic bounded-probe manifests

The bounded SPTM probe now creates a unique attempt bundle automatically, before payload validation. Existing invocations retain `--report`; no new option is required. By default the bundle is `<report>.runs/<UUID>/`, or choose its parent with `--run-dir PATH`. Each bundle contains `manifest.json` and `report.json`; the requested report path is an atomic convenience copy. Use distinct report paths for concurrent invocations so their convenience copies do not compete.

```sh
source setup/activate.sh
python scripts/sptm_entry_probe.py --checkout "$VEL2_CHECKOUT" \
  --payload local/payload --steps 128 --report local/reports/offline-entry.json
```

This example validates layout only. Hardware execution still requires the existing explicit `--execute --device ...` arguments and an appropriate experiment plan.

Manifest schema 1 records the UUID, full argv/cwd, effective parameters, host/Python/package versions, both Git commits, tracked dirty-diff hashes, untracked file hashes, submodule status, lock/patch hashes and expected raw ELF hash. Payload hashes come from the bytes inspected by the layout planner; hardware image construction checks the subsequently loaded bytes against those hashes. Existing live immutable-section checks supply a separately labelled runtime observation. The guest image, device-tree and trustcache hashes are captured when available. Device OS/firmware and reset state remain explicitly unknown; a serial path is a connection identifier, not proof of device identity. Ignored source files are not exhaustively inventoried, and the Git metadata is not a source archive. Keep source trees stable during an attempt.

A manifest records lifecycle phase, start/end times, elapsed time, producer outcome and capture completeness. Normal bounded stops are `finished`, not a claim of guest boot success. Python exceptions are `failed`; Ctrl-C and SIGTERM are `interrupted`. Initial and periodic report checkpoints are atomic; callback checkpoints retain the existing 128-event cadence. Caught interruptions preserve the in-memory partial trace and attempt finalization. SIGKILL, host failure or unavailable storage cannot guarantee a final record: an unfinished manifest must be treated as incomplete, and up to the events since the last checkpoint may be absent. Console output is not yet bundled and `console_captured` is false.

This adds evidence capture, not recovery guarantees: setup failures can leave target state uncertain, and a responsive proxy after cleanup does not establish a clean reset. No watchdog, device broker, automatic retry or automatic catalog ingestion is installed. Capture does not change instruction budgets or permit additional monitor transitions.

To register a completed bundle, use its UUID for the run ID, its manifest as provenance, and preserve the manifest as an attachment:

```sh
python scripts/experiment_store.py ingest YOUR_EXPERIMENT BUNDLE/report.json \
  --run-id UUID --provenance BUNDLE/manifest.json \
  --artifact manifest=BUNDLE/manifest.json
```

Define the experiment first with the catalog's `define` command. Keeping catalog publication separate allows inspection of incomplete attempts and avoids introducing database failures into the device callback. Import retries with the same ID and unchanged bundle remain idempotent.

Validation: 164 research tests pass, including six new tests covering source identity, atomic-write failures, unique attempts, catalog round trips, offline/failing probe finalization and SIGTERM capture. An actual offline invocation against the retained Tahoe payloads generated a complete bundle without target access. Hardware capture remains untested until the next USB session.

`ingest_probe_bundle.py EXPERIMENT BUNDLE --console LOG` now validates finalized manifest/report identity and checkpoint counts before catalog ingestion. It accepts finished, failed and interrupted attempts; still-running bundles remain unregistered. Submit closed bundles only. The bounded probe's maximum selectable event budget is now 131072; the default remains 128. This accommodates the observed finite initialization loops beyond 65536 events without bypassing instruction execution or register checks.

Long-trace follow-up: full JSON checkpoints now use 128-event intervals through event 4096, then 4096-event intervals, plus every stop/finalization. The 131072-event hardware run exposed quadratic write amplification from serializing the entire growing report every 128 events. This reduces checkpoint I/O substantially without omitting events from finalized reports. Abrupt uncatchable termination can now lose up to 4095 events after the last checkpoint on long runs. An append-only streaming event format remains the better long-term solution.

## Streamed long experiments

`--trace-window 8192` retains the most recent 8192 events in the JSON report while writing every event, with its absolute index, to `events.jsonl` in the attempt bundle. The event budget counts all events, including evicted ones. Budgets above 131072 require this mode; the maximum selectable budget is 1048576. The summary includes `trace_total_events` and `trace_start_index`, and the manifest records archive count and final SHA-256/size. Finalized bundle ingestion verifies and retains that archive as an opaque artifact. Its streaming decoder remains a future adapter; existing JSON diffs reject windows with different starting indices.

Events are journaled at checkpoints, not individually fsynced. An uncatchable crash can still lose events since the last checkpoint; the manifest remains the last known checkpoint. Caught failures attempt finalization, and missing archive digests prevent terminal bundle ingestion. Producers must close bundles before submission. Report `trace` now means the retained window when this option is used; it must not be mistaken for the full execution history.

The catalog now compares full `events` archives with bounded memory, including comparisons against older complete JSON reports. It verifies stored archive hashes and contiguous record indices, validates total event counts where reported, and computes first divergence and complete counts while streaming. Without a full archive, mismatched summary windows still reject comparison. The full-stream comparison does not claim full machine-state equivalence.

## Bounded post-stop diagnostics

`probe_diagnostics.py REPORT --checkout CHECKOUT --device SERIAL --output JSON` verifies the current runtime's immutable sections, reads saved guest exception registers, and samples up to 256 bytes at each of at most 30 register-derived pointers through the recorded guest tables. Both table reads and final data reads must stay inside the report's owned guest allocation. Only printable strings are reported. It never resumes the guest or broadens stage-2 mappings. Use it only for the latest completed attempt, with no intervening run or image reload and no competing device owner: an old report cannot establish that RAM is still current. Empty output does not establish absence of a diagnostic.

After the clean million-event stop, the selectable streamed event ceiling is 2097152. The full archive showed progression through multiple initialization loops rather than a single repeated state; the larger ceiling is a bounded diagnostic run, not evidence of a boot milestone. The default remains 128 and budgets above 131072 still require a bounded summary window.
# Complete archive profiles

`python scripts/trace_profile.py PATH_TO_RUN_BUNDLE --output profile.json`
verifies the finalized event archive digest and count, then streams PC
frequencies, first/last occurrence indices, register endpoint changes at the
most frequent PCs, and newly observed PCs per 65,536-event window. It refuses
to silently truncate the unique-PC table. These are execution observations;
they do not identify loop semantics, prove useful progress, or establish a
boot milestone. The profile records its source manifest and archive hashes
for later automated comparisons.

New hardware attempts also retain exact host and constructed guest ADT bytes
under `inputs/` in the run bundle. The manifest hashes these files, and bundle
ingestion verifies and stores them. Earlier attempts only recorded ADT hashes
and cannot be reconstructed from those hashes. The observational
`scripts/boot_data_audit.py` compares named memory-map and firmware segment
ranges with the owned guest allocation; it does not authorize mapping or
discarding an outside range. Saved diagnostic table pages can be replayed
with `scripts/replay_table_snapshot.py`, which distinguishes missing evidence
from an unmapped address.


## Automatic guest exception capture

New probe attempts record `initial_guest_exception_registers` and
`final_guest_exception_registers` before cleanup: ESR, ELR, FAR, SPSR and VBAR
from the guest EL12 bank. An unavailable final snapshot is reported explicitly
and does not prevent cleanup. These are observations, not evidence of a full
reset; compare initial and final values and the trace before assigning a fault
to the attempt. Separate bounded table diagnostics remain available.

`trace_exception_window.py BUNDLE DIAGNOSTICS --output JSON` checks the
finalized archive hash, diagnostic source-report identity and event count,
then retains bounded context around the first recorded vector-table PC.
It distinguishes no observed vector entry from a recorded entry, without
inferring an exception cause from PC alone.
