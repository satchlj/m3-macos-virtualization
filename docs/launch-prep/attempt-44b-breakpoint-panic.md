# Attempt 44b: VBAR worked; the TXM breakpoint caused the panic

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Attempt 44b proves the `VBAR_GL1` correction worked. It also proves that the
transient HVC installed at TXM `+0x4c` did not behave as a host breakpoint: TXM
executed it at GL0, it became an undefined instruction delivered to SPTM, and
SPTM panicked on its unhandled-exception path. The later “dispatch id 10” panic
is secondary error reporting, not a failure of the VBAR alias.

## Exact chain

1. SPTM's two vector writes were applied through `VBAR_GL12`, rather than
   staged: event 33 wrote `0xfffffe00070ad000`; event 50 wrote the final
   `0xfffffe00070a8000`. The exit readback is exactly
   `VBAR_GL1 = 0xfffffe00070a8000`.
2. The verified breakpoint replaced TXM's original word `0x97ffdfed`
   (`bl 0xfffffe0017068000`) at `0xfffffe001707004c` with
   `hvc #0x47f0` (`0xd408fe02`). SPTM entered TXM at event 750. TXM ran its
   relocation routine natively and reached that patched address.
3. The HVC did not trap to vel2, so the harness never marked or restored it
   (`hit=false`, `restored=false`). Instead it took a GL0 synchronous exception
   through the corrected SPTM vector: `VBAR_GL1 + 0x400` is
   `0xfffffe00070a8400`, whose first branch targets
   `0xfffffe00070a5e28`. The very next recorded event is the rewritten sysreg at
   original PC `0xfffffe00070a5e30` (reported HVC return PC
   `0xfffffe00070a5e34`). That placement is direct evidence of the vector route.
4. The captured guarded bank describes the breakpoint instruction:

   | register | value |
   | --- | --- |
   | `ESR_GL1` | `0x02000000` = EC 0, IL 1, undefined instruction |
   | `ELR_GL1` | `0xfffffe001707004c` = exact patched TXM address |
   | `SPSR_GL1` | `0x600013c0` = interrupted GL0 state |
   | `FAR_GL1` | zero from the current software shadow |

   The full returned values must be read from the following trace event: the
   probe records a read event before replacing the target GPR. Thus event 753's
   displayed `value=0x08000000` is stale x8, while the subsequent branch state
   has EC 0; the later save reads leave `x21=0x02000000`,
   `x22=0xfffffe001707004c`, and `x23=0x600013c0`. The final guarded-bank
   snapshot independently matches ESR and ELR.
5. At `0xfffffe00070a5e58`, SPTM accepts only EC `0x15` (SVC64) and `0x16`
   (HVC64). EC 0 takes the default branch to `0xfffffe00070a60a8`, which saves
   the interrupted TXM context. The path selects the payload string
   `[TXM] Unhandled synchronous exception taken from GL0` and calls the panic
   reporter with a synthetic return at `0xfffffe00070a61fc`; the recorded PAC
   LR at the next event corresponds to that return site.
6. While reporting the unhandled exception, SPTM reaches its
   `dispatch_id_to_string` failure. Post-exit diagnostics recovered
   `dispatch_id_to_string: 10 is not a valid dispatch id (valid dispatch IDs
   are 0 - 9)`, and the panic-halt register set has `x1=10` and `x14=10`.
   Recorded control then passes through `0xfffffe00070f8d90`,
   `0xfffffe00070f89a8`, and the panic WFE at `0xfffffe00070f8b88`.

## Conclusion

The causal chain is:

```text
verified TXM BL replaced by HVC #0x47f0
  -> HVC is undefined at TXM GL0
  -> corrected VBAR_GL1 routes to SPTM +0x400 vector
  -> SPTM sees ESR EC 0 / ELR exactly TXM +0x4c
  -> unhandled TXM-GL0 exception reporter
  -> secondary invalid-dispatch-id-10 panic
```

This run therefore validates the VBAR correction and invalidates the assumption
that an HVC planted in TXM can serve as a vel2 breakpoint. It does not test
TXM's natural first SVC: the breakpoint replaced the BL that would have called
the `svc #0` stub and was never restored. The next natural-flow run must execute
the original `bl 0xfffffe0017068000` at `+0x4c`.

Evidence: `artifacts/runs/observe-sprr/attempt-44b/report.json`, its run-local
`events.jsonl`, `diagnostics.json`, and the verified original SPTM/TXM payloads.
