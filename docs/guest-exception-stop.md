# Stop at the first recorded guest vector visit

`scripts/guest_exception_stop.py` supplies a pure incremental detector for the
bounded SPTM probe. It recognizes the first recorded PC in the half-open interval
`[VBAR_EL12, VBAR_EL12 + 2048)` using the current host-stop VBAR sample. It does
not infer an exception from ESR, which can retain a previous exception's value.
A vector-range visit can also result from a branch, so this is a stop trigger,
not proof of a particular architectural exception.

## Integration contract

1. Construct `GuestExceptionStop(batch_capacity)` before recording the first
   event. Use capacity zero when native batching is disabled.
2. Drain and preserve the whole native batch. Preserve the current host callback
   event too. Sample `VBAR_EL12` while the guest is stopped.
3. Call `observe(report['trace'], start_index=report['trace_start_index'],
   vbar=current_vbar)` before rearming or resuming the guest. An incremental list
   with its global start index works too. Overlapping windows are deduplicated;
   dropping unseen events is a validation error.
4. If a hit is returned, exit the guest instead of rearming. Read `ESR_EL12`,
   `ELR_EL12`, `FAR_EL12`, `SPSR_EL12`, and `VBAR_EL12` while still stopped and
   attach them through `snapshot_cause()`. Preserve the hit report even if a
   subsequent register read fails. Run the existing read-only diagnostic path.

The returned report retains the first hit's global zero-based trace index and
complete recorded context, the sampled VBAR, and the number of recorded events
after the hit. Input events are never modified or removed. An observation may
contain at most one full batch plus its callback, so recorded overshoot is at
most the configured batch capacity. This bounds **recorded events**, not elapsed
time or unrecorded execution in a native handler. It does not justify claiming
that no exception-handler instructions ran after the first visit.

Zero VBAR is treated as unconfigured, and the synthetic `entry-guard` event is
excluded. This matches this probe's initialization, where useful monitor vectors
are nonzero. A target using vectors at address zero needs an explicit different
initialization policy.

## Sampling limits

Native handling rewrites guest VBAR accesses and does not necessarily expose
writes to the Python callback. Read `VBAR_EL12` at every batch/callback rather
than caching it from a prior callback. Measure that read's cost in a short paired
run before assessing throughput impact.

A stop-time VBAR sample is not a historical VBAR timeline. If VBAR changes during
a batch, the detector cannot prove which base applied to every earlier event;
it may miss a visit to a former vector table or classify an earlier PC against
the newer table. Exact detection across such changes would require native
per-event VBAR metadata or flushing whenever VBAR changes. Cause registers read
after a batch likewise might describe a later exception. The report labels them
as stop-time observations and does not assign them unconditionally to the first
vector visit. The first recorded vector PC may already be inside a vector slot;
its index is not necessarily the exact architectural exception boundary.

Run the target-free checks with:

```sh
python3 -m unittest discover -s tests -p test_guest_exception_stop.py
```

## Integration status

`sptm_entry_probe.py --stop-on-vector-entry` (pipeline field
`stop_on_vector_entry`) constructs the detector with the native batch capacity.
The callback finalizer observes the drained batch plus the current trap event
against a fresh `VBAR_EL12` read only when it is about to resume the guest;
exit paths add no proxy reads. A hit sets stop reason
`guest-vector-range-entry`, exits without rearming, and stores the report under
`guest_vector_stop` with stop-time `ESR_EL12`, `ELR_EL12`, `FAR_EL12`,
`SPSR_EL12` and `VBAR_EL12`. A failed register read preserves the hit and adds
`guest_vector_stop_error`; a failed VBAR read or detector validation error stops
with `vector-stop-error`. The report also records `vector_stop_enabled`.

The added per-stop VBAR read has not been measured on hardware yet. Offline
callback tests live in `tests/test_probe_guards.py`.
