# Verified pipeline import

`run_probe_pipeline.py` produces a closed `.tar.gz` and matching
`.tar.gz.identity.json` after its probe and optional diagnostics. Copy both
files to `artifacts/transfers/archives/` on the analysis workstation, using an
authenticated SSH connection to the USB host. The sidecar records the expected SHA-256 and byte
count; it checks transfer integrity, not who produced an unauthenticated file.

Import a downloaded attempt into an already defined catalog experiment:

```sh
python scripts/import_probe_pipeline.py EXPERIMENT \
  artifacts/transfers/archives/ATTEMPT.tar.gz \
  --destination artifacts/runs/imports/ATTEMPT
```

The importer hashes the compressed archive before creating its destination.
Extraction accepts one root directory, regular files and directories only. It
rejects absolute/traversing paths, duplicate names, links, devices, sparse
files, more than 100,000 entries and more than 16 GiB of expanded contents.
`--max-expanded-bytes` can set an explicit alternative. Archive-supplied file
permissions and ownership are not applied. The destination must be new;
existing files are never overwritten. Invalid extraction removes its own
partial destination.

A finalized probe bundle is registered through the existing bundle importer,
which validates its run ID, event counts and captured-input/archive digests.
This preserves its immutable producer identity. Pipeline configuration,
console output, diagnostics and captured table files belong to a separate
catalog record named `pipeline:SHA256`, whose provenance links to the probe
run. Its report describes orchestration status; it does not claim a successful
guest boot. This avoids adding post-run attachments to an immutable probe
record. Reimporting the same bytes from another path produces the same records.
A probe previously imported with a different attachment set still conflicts;
the importer never changes an existing immutable record to resolve that conflict.

A failed pipeline can contain a finalized failed or interrupted probe, which
is registered as that terminal attempt. Missing or unfinished probe bundles
are preserved in the extracted directory but never registered as terminal
probe runs. The separate pipeline record retains the orchestration failure.
An unfinished pipeline itself is rejected. Catalog validation failures leave
the verified extraction available for investigation; they do not delete the
source archive. Successful imports write `import-receipt.json` next to the
extracted pipeline root.

Catalog registration is idempotent. To repeat the CLI after a partial catalog
failure, provide a new extraction directory; an existing extraction can also
be passed to the Python `register_pipeline` function after its contents and
original transfer identity have been verified. Keep all archives, extracted
attempts and catalog objects under the ignored artifact tree described in
[artifact storage](artifact-storage.md).

## One-step fetch and import

[`fetch_pipeline_archive.py`](pipeline-fetch.md) performs the scp copy of the
sidecar and archive into `artifacts/transfers/archives/`, the identity check
and this import as one command. It reuses an identical local archive, refuses
a differing one, and writes the same `import-receipt.json` plus a `transfer`
block. [`trace_events_summary.py`](trace-events-summary.md) reads an imported
finalized bundle's non-step events after re-checking its archive identity.
