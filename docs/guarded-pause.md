# Guarded continuation protocol

`scripts/guarded_pause.py` provides a local control channel for the existing
USB-owning process while it holds a rejected, pending guest trap. A resumed run
is continuation of the same attempt and guest state, not an independent
experiment or reset. This helper does not access USB or modify a register.

The caller creates `GuardedPause(capture.root / 'pauses')` and calls
`wait(reason, context, policies, allowed_flags=..., on_pause=...)`. The callback
receives the unique pause directory and initial status; persist the report and
print this directory before waiting. Polling sleeps at most one second, with a
finite timeout (default one hour, maximum one day). Timeout, interruption, or too
many invalid commands selects exit. Unexpected filesystem/callback failures
propagate so the probe must exit its pending guest in its existing `finally`.

From another shell on the USB host:

```sh
python scripts/guarded_pause.py RUN/pauses/PAUSE_ID status
python scripts/guarded_pause.py RUN/pauses/PAUSE_ID resume --enable allow_live_ttbr
python scripts/guarded_pause.py RUN/pauses/PAUSE_ID exit
```

Submission is not acknowledgement: inspect `status.json` for the owner's final
`decision`. A command that races with timeout may remain unused. Each pause has
a unique UUID and each request a separate UUID. JSON is published by atomic
rename. The owner checks exact fields, version, pause ID, request ID, filename,
boolean types and the per-trap allowlist; malformed/stale commands cannot resume
the guest. Requests and rejection receipts remain under the run bundle for
provenance. Use the channel only between trusted processes under the same local
account; it is not a network service or an authentication boundary.

Only `allow_live_ttbr` and `allow_monitor_mmu` are globally enumerated. The caller
must narrow these further for the specific pending guard. Enabling a policy
only permits the existing validation path to run; page-table and continuation
checks remain mandatory. There is no arbitrary expression, shell command,
source reload, register write, or instruction-budget change protocol. New
handler code requires a new process/run and potentially replay from entry.

## Probe integration invariants

1. Drain native batch records once on entry to the callback, before pausing.
   Retain the pending context and the ordinary callback's closure state.
2. Split trap processing from callback finalization. On a *deliberate policy
   rejection before any hardware/context side effect*, call `wait`. A resume
   updates only validated flag values and retries this same processing helper.
   Never recursively call `stopped`: that would duplicate event accounting,
   batch drain and `p.exit`.
3. Limit eligibility to `monitor-translation-contract` with the recognized MMU
   profile and disabled policy, or `live-translation-control-change` for a TTBR
   bank with disabled policy. Unsupported controls, validation errors, partial
   hardware writes, budget exhaustion and asynchronous exceptions must exit.
4. Keep the saved pending PC unchanged on retry. Patched HVC traps already point
   beyond the patched instruction; ordinary system-register exceptions use
   their existing single `elr += 4` only after successful handling.
5. Record each pause ID, requested decision and actual applied policy changes
   in the report/run manifest. Clear only the rejected attempt's stop reason
   before retry. Append the final trap event once after the decision and
   validation. Save policy decisions separately from instruction trace events.
6. Rearm batching and call `p.exit(ret)` once in the existing callback finalizer.
   An exception while waiting/saving must still reach that finalizer. Do not
   arm guest execution while the host is waiting for a decision.

The module's tests cover typed validation, unchanged caller state, timeout,
interrupt, stale request isolation, malformed/oversized commands, request ID
mismatch, command limits and error finalization. A mocked callback integration
test should separately assert one batch drain, one event append and one exit
when a rejected trap is retried, as well as mandatory validation on resume.

## Integration status

`sptm_entry_probe.py --pause-on-guard [--pause-timeout SECONDS]` enables the
channel; the pipeline fields are `pause_on_guard` and integer `pause_timeout`
(default one hour, maximum one day). Pause directories are created under the
attempt bundle at `runs/RUN_ID/pauses/PAUSE_ID` and the path is printed on
stdout, so it also appears in the pipeline `console.log`.

Exactly two guards are eligible, both before any hardware or context effect:

- `monitor-translation-contract` when the recognized VHE monitor profile is
  written with `allow_monitor_mmu` disabled, VHE HCR staged and SPRR config
  zero. Allowed flag: `allow_monitor_mmu`.
- `live-translation-control-change` when a TTBR0/TTBR1 bank changes with
  `allow_monitor_mmu`-enabled translation and `allow_live_ttbr` disabled.
  Allowed flag: `allow_live_ttbr`. TCR/MAIR changes still exit.

Every other rejection, validation error, budget stop or asynchronous exception
exits as before. A resume that enables the trap's flag retries the same trap
once through the same validation path in the same callback: the native batch
was drained once before pausing, the trap event is appended once, batching is
rearmed only after the decision, and `p.exit` runs once. A resume that leaves
the flag disabled, an exit, a timeout, a command limit or an interrupt keeps
the original stop reason and exits the guest; SIGTERM/Ctrl-C during a pause
therefore ends the run cleanly with that stop reason rather than aborting the
callback. A channel or report-save failure while pausing becomes
`probe-validation-error` and still exits the pending guest.

The report records `guard_pause_enabled`, one `guard_pauses` entry per pause
(pause ID, guard, flag, the pending trap context, the decision and the applied
changes) and cumulative `policy_overrides`. The run manifest's recorded
parameters keep the flags as originally requested. Offline callback tests in
`tests/test_probe_guards.py` cover the retry accounting, side-effect ordering,
ineligible rejections and the real channel's resume/timeout paths. The device's
behaviour while its host callback waits for a long time has not been measured
on hardware yet; use a short timeout for the first paused hardware attempt.
