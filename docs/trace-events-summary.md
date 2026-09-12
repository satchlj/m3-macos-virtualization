# Non-step event summary of a finalized bundle

`trace_events_summary.py runs/RUN_ID --output SUMMARY.json` lists every
recorded event that is not an `instruction-step`, with the number of recorded
single steps between consecutive non-step events. It is an offline reader of
the immutable bundle and touches no device.

```sh
python scripts/trace_events_summary.py artifacts/runs/imports/ATTEMPT/job/runs/RUN_ID \
  --output artifacts/runs/summaries/RUN_ID-events.json --after 300 --context 8
```

Before reading any event, the tool requires a terminal manifest status with
`ended_at`, matching manifest/report run IDs, `capture.event_archive` set to
`events.jsonl` and an `events.jsonl` whose SHA-256 and size equal
`capture.event_archive_identity`. The archive is then parsed once through the
bounded JSONL reader; if its record count differs from
`report.trace_total_events` the summary is rejected. Hashing is a separate
byte pass; events are never held in memory as a whole.

Each non-step row carries `index`, `kind`, `pc`, `steps_since_previous` and
whichever of `register`, `read`, `value`, `sysreg`, `effects` and
`unsupported_detail` the event recorded. Events without a `kind` are counted
as `unclassified`. The summary also reports total and selected event counts,
first/last selected and non-step indices, per-kind counts, and the trailing
step run after the last non-step event.

`--after INDEX` restricts selection, counts and context to events at or after
that index; an index beyond the archive is an error. `--context N` (0 to 256)
attaches the up to N instruction steps recorded immediately before each
non-step event, reset at every non-step event and never reaching back before
`--after`. Output is written atomically; one line summarizing counts is
printed.

Step runs count recorded single-step events. With native step batching they do
not equal executed guest instructions, and the summary makes no claim about
guest state beyond what each event already recorded.
