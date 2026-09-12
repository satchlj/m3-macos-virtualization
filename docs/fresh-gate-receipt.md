# Accelerated fresh-boot gate receipt

## Status

The host-only receipt issuer/validator, fail-closed pipeline consumption, and
accelerated three-stage hardware path are qualified. Attempt 104 ran the
nonce-bound four-stage qualification gate, consumed its receipt immediately in
the real pipeline, reached its intended Phase 5.3 stop, returned the guest
cleanly, and left the proxy alive. Future runs may explicitly select
`run_fresh_gate.py --accelerated`; neither gate mode is an implicit default.

The measured saving is the entire 20.02-second short-probe pass. Chainload, transition
smoke, native batch smoke, immutable `.init`/`.text`/`.rodata` comparison,
preserved boot-data capture, device binding, and one real run per installed
boot remain mandatory.

## Receipt contract

`scripts/fresh_gate_receipt.py` uses a private 32-byte local key and HMAC-SHA256.
One signed receipt binds:

- one random 256-bit gate nonce echoed by the chainloader and both smokes;
- the device path;
- SHA-256 and size of `m1n1.bin` and `m1n1-raw.elf`;
- SHA-256 and size of all three reports and every preserved boot-data span;
- ordered report start/end timestamps, with the batch report no more than 15
  minutes old and the complete three-stage gate bounded to 30 minutes;
- strict success predicates for the preserving chainload, transition smoke,
  immutable runtime sections, all seven batch checks, and clean proxy returns;
- issuance and expiry timestamps (two hours by default).

Consumption rechecks the signature, device, expiry, and current runtime file
identities.  It then creates a nonce-named record with `O_EXCL` in a private,
key-adjacent consumption directory whose location is not caller-selectable.
The marker is created before the target run;
therefore a setup fault after consumption burns the receipt instead of risking
a second run.  Copying the JSON does not bypass the global nonce ledger, and
concurrent consumers have exactly one winner.

This is a host workflow capability, not target remote attestation.  A person
who deliberately replaces the private key or deletes the consumption ledger
can defeat it, just as they can bypass the existing shell gate.  It prevents
accidental stale-report mixing, runtime drift, copied-receipt reuse, and two
launchers racing for one fresh boot.

## Wired workflow

`scripts/run_fresh_gate.py` implements the gate sequence.  It:

1. Creates `artifacts/.fresh-gate-receipt.key` once with mode 0600.
2. Acquires the same per-device lock used by the probe pipeline and holds it
   across the complete chainload-through-receipt sequence.
3. Generates a nonce with `fresh_gate_receipt.py nonce`.
4. Passes `--fresh-gate-nonce "$nonce"` to
   `chainload_preserve_boot.py`, `vel2_smoke.py`, and
   `step_batch_smoke.py`.
5. Issues a receipt from the three new reports, exact runtime binary, and raw
   ELF.  Receipt issuance must be the final gate step.
6. Prints the explicit receipt path.  `run_probe_pipeline.py` acquires its
   existing per-device lock, validates and consumes that receipt, retains the
   receipt and consumption record in the attempt bundle, and only then spawns
   `sptm_entry_probe.py`.

`gate.json` records wall-clock stage timestamps plus monotonic durations for
lock acquisition, each hardware stage, receipt issuance, and the full gate.

No ambient “current receipt” or automatic newest-file lookup should be used.
Every hardware command must name the receipt explicitly; this makes a missing
or stale gate fail before target access.

The accelerated form, after qualification, is:

```sh
python -u scripts/run_fresh_gate.py \
  --checkout "$VEL2_CHECKOUT" --device "$M1N1DEVICE" \
  --output "$GATE_DIR" --execute --accelerated
python -u scripts/run_probe_pipeline.py \
  --config "$CONFIG" --output "$ATTEMPT_DIR" --execute \
  --fresh-gate-receipt "$GATE_DIR/fresh-gate-receipt.json"
```

For the qualification run, replace `--accelerated` with
`--legacy-short-probe --payload "$ASAHI_ROOT/payload"` in the first command.
As a transitional fallback, an ordinary four-stage gate
can be followed by `run_probe_pipeline.py --execute --legacy-full-gate`.
That flag is only an explicit operator assertion; the pipeline cannot infer
that the old shell gate ran.  Every execute invocation requires exactly one of
the receipt or legacy flags.  Offline/dry-run pipeline validation requires
neither.

The gate releases its device lock after issuing the receipt, and the pipeline
reacquires it before consumption.  The existing one-owner rule still applies
in that interval: the receipt prevents stale/repeated/racing managed launches,
but it cannot detect an arbitrary external command that bypasses the lock and
changes target state.

## Why the short probe can only be removed after qualification

The real pipeline already repeats the payload, guest-input, boot-data
relocation, runtime-identity, and cleanup checks performed by the short probe.
Replacing the short probe therefore moves those checks into the one intended
real run rather than deleting them. Attempt 104 demonstrated that equivalence
with the receipt-enabled binaries on the target. Its qualification gate took
24.59 seconds: 3.00 seconds for the preserving chainload, 0.85 seconds for
transition smoke, 0.71 seconds for batch smoke, and 20.02 seconds for the legacy
short probe. The qualified accelerated gate therefore retains about 4.57
seconds of measured gate work and removes only the redundant short probe.

## One-time hardware qualification

On a fresh installed boot, run `run_fresh_gate.py --legacy-short-probe` so one
nonce passes through its first three stages and the receipt is issued after the
legacy short probe returns.  Then give that receipt to the ordinary real
pipeline, which consumes it under the device lock.  Confirm:

- the legacy gate and receipt validator accept the same exact runtime and
  reports;
- receipt consumption occurs immediately before the real probe opens the
  device;
- a second consume, a copied receipt, a changed ELF, and a changed device all
  fail before target access;
- the following ordinary real pipeline repeats the input/runtime identity
  checks and returns the proxy cleanly.

The private gate reports, receipt, consumption record, and attempt bundle remain
outside this repository. The explicit `--accelerated` three-stage mode is now
the qualified fast path.
Keep `--legacy-short-probe` for periodic or
post-firmware-change comparison, never for obtaining a second real run from one
boot.
