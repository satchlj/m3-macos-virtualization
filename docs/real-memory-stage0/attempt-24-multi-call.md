# attempt-24 — multi-call driver works; idle rejects general SPTM calls (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

First run of the multi-call driver (`--guarded-call-selectors`). It issued
`x16 = 0x100000000` (CALL_SPTM, func index 1) from the patched idle genter.

## Result

```
stop_reason         guarded-call-panic
guarded_calls       [{index 0, selector 0x100000000, panicked True, steps 129}]
proxy_alive_after_exit  True
```

Path (from the trace): genter#0 -> dispatcher 0xa4524 -> type 2 (CALL_SPTM) ->
action 0xa424c -> C service 0xe8d4c -> dispatch_state_machine (0xe842c) -> null
action for (STATE_XNU, this func) -> 0xe86c4 -> **PANIC 0xf8ca0**, where the probe
HALTED before the panic ran. 129 guarded instructions, non-mutating, clean exit.

## What this proves and finds

- **The multi-call driver works end to end:** it set the selector, drove a real
  CALL_SPTM service call, and the panic-stop caught the invalid-index panic cleanly
  (no hang, no reboot, no mutation). target M3 healthy after.
- **Func index 1 is not permitted in STATE_XNU (idle).** SPTM's state machine has no
  action for a general CALL_SPTM in idle -> null -> panic. This matches the model:
  **idle (STATE_XNU) is "kernel not yet launched"; general SPTM services are for a
  running kernel** (a different state), so idle rejects them.

## Implication for direction

- Sweeping more CALL_SPTM indices from idle is inefficient: a panic ends the run,
  and a real-guarded run is one-per-boot (SPRR lock), so it's ~one boot per index,
  and the analysis says idle rejects them all anyway.
- The meaningful idle transition is **ENTER_GUEST** (`x16 = 0x1b`) -- launch the
  normal-world kernel. That is the next milestone (the ~1.5-2.5 complexity pivot):
  it needs a guest kernel image + launch context + a reversibility plan for a live
  OS, so it is a prep effort, not a quick run.
- Definitive alternative to confirm idle scope without sweeping: read the SPTM
  per-function handler+allowed-state table (~0x99xxx, __LATE_CONST, populated at
  init) from SPTM's live RAM to see which indices (if any) are valid in STATE_XNU.

The guarded-call mechanism is now fully proven (enter, dispatch, service, safe
return/panic). The frontier moves to the kernel launch.
