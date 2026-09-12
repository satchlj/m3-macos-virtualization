# attempt-25 — ENTER_GUEST panics from idle: SPTM never reaches launch-ready (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

First launch attempt: `--guarded-call-selectors 0x1b` (ENTER_GUEST) from the patched
idle. Result:

```
stop_reason      guarded-call-panic
guarded_calls    [{selector 0x1b (ENTER_GUEST), panicked True, steps 135}]
launch           NONE
path             ... 0xe86e0 0xe86e4 0xe86e8 0xe86ec -> 0xf8ca0 (panic)
```

ENTER_GUEST hit the **same null-action panic path** (`0xe86c4 -> 0xf8ca0`) as
attempt-24's CALL_SPTM. So from the state SPTM is in at our idle, the guest-launch
transition has no action -> panic. The panic-stop caught it cleanly (non-mutating).

## Why: the idle is a terminal wait, not launch-ready

Disassembly of the idle (`0xf8b88`): after zeroing a per-CPU structure and a `bl`,
SPTM enters `wfe; b .-4` -- an **unconditional terminal wait loop**. SPTM's primary
CPU parks here having finished its bring-up, but it **did not launch XNU** and is not
in the launch-ready state (`STATE_XNU` with ENTER_GUEST valid, per the transition
decode). So our probe's SPTM boot stops short of the launch.

## What this means

The launch is NOT a simple ENTER_GUEST from idle (the earlier "trigger is cheap"
read was wrong). SPTM must first REACH the launch-ready state during its boot, which
our synthetic boot does not. Candidate reasons (next investigation):
- The XNU context prep didn't complete (a `chosen/memory-map` region missing/wrong
  so the entry-PC global `0x98928` stayed 0, or a validation failed), so SPTM took a
  fallback/idle path instead of the launch path.
- A precondition the launch path requires is unmet: SMP (all `sptm_n_cpus` up -- our
  probe is single-CPU), a device/timer, or a handshake the real boot provides.
- SPTM launches XNU only when driven by a lower level / an event our probe doesn't
  supply, and the idle wfe is "waiting for that."

## Next (offline)

Trace the boot path that leads to the `0xf8b88` idle vs the launch path (action
`0xa424c`), and find the branch/check that chose idle -- i.e. the precondition that
gates the launch. Also determine SPTM's state at idle (`percpu+2656`) and whether the
entry-PC global `0x98928` was populated (context prepared or not).

## Complexity note

This moves the launch complexity back up: the ENTER_GUEST *trigger* is cheap, but
reaching launch-ready (satisfying whatever SPTM's boot requires -- likely SMP or a
context-prep precondition) is the real work. Closer to the original ~1.5-2.5 estimate.
