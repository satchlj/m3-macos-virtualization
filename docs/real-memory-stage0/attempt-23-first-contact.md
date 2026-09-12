# attempt-23 — first contact: a real guarded service call into SPTM (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

**Milestone.** With `--first-contact` (patch the normal-world WFE idle at 0xf8b88 to
genter #0) plus the GL2 shadow and A/B/C backing, SPTM completed full init, reached
idle, and the injected `genter #0` made a real guarded service call:

```
stop_reason         first-contact-service-boundary
first_contact.stop_pc            0xfffffe00070a4ac0   (T0 'b ->0xe8d4c')
first_contact.reached_dispatcher True                 (0xa4524)
trace_total_events  7,815,737     guest_exec 338 s
```

Round trip: idle -> `genter #0` -> world switch -> dispatcher `0xa4524` -> type read
(type 0) -> T0 handler `0xa4a14` -> **halted at `0xa4ac0`**, the instruction before
the branch to the C service `0xe8d4c`. The service never ran: non-mutating by
construction. First real guarded service call into SPTM under the probe. Clean exit,
proxy alive.

## Consecutive real-guarded runs: no EL2 software fix (investigated, ruled out)

Goal: run follow-up real-guarded runs without a power cycle. attempt-22 and the
attempt-19 first launch both crashed at `hv_start` on a 2nd run. Investigation:

- attempt-23 diagnostic: **`el2_context_after.gxf_en_cleared = False`** — the
  teardown's `GXF_CONFIG=0` write does not take; SPTM locks GXF (and SPRR: its boot
  sets `SPRR_CONFIG 0x1->0xfb->0xff`, lock bits included) during boot. Locked config
  registers cannot be cleared from EL2.
- Read `VBAR_EL2` from the live proxy = `0x10002a8e800`, so m1n1's runtime base is
  `0x10002a84000` (physical low, not the `0xfffffe00…` VA). Then `GXF_ENTER_EL1`
  reads `0x10002a8d090` = m1n1's `_gxf_entry` (clean), disproving the "SPTM leaves a
  dirty GXF_ENTER" hypothesis.
- Mechanism: on run 2, `hv_start` does `gl2_call(hv_set_gxf_vbar)` (because
  `gxf_enabled()` is stuck true). The genter enters the guarded world, but under
  SPTM's **locked SPRR**, m1n1's own guarded entry code is not guarded-executable ->
  fault -> `wdt_reboot` (full reset) -> iBoot -> macOS.

Nothing settable from EL2 (`GXF_ENTER`, a `gxf_init` re-call, disabling GXF) touches
a locked register. Only a full boot clears the locks, and a full boot exits to macOS
(P_REBOOT/wdt_reboot; see [../reboot-helper-design.md](../reboot-helper-design.md)).
**Conclusion: one real-guarded run per boot; no EL2 workaround.**

## The sustainable path: multiple calls within ONE run

The lock is only a problem across `hv_start` re-boots. Within a single run, after a
first-contact genter returns (let the service run and `gexit`), SPTM is back at the
normal-world idle with SPRR/GXF already correctly configured. So follow-up guarded
work should be **multiple genter calls in one `hv_start` session** (loop: inject
genter, let it complete, observe, repeat), not separate runs. That sidesteps the
lock entirely. It requires letting the service execute (mutating) and a loop driver
— the next build.

## Live ABI confirmation (from attempt-23's single-stepped trace)

The trace confirms the guarded-call ABI on real hardware, matching the static
disassembly exactly:

```
0xfffffe00070f8b88   idle -> genter #0 fires
0xfffffe00070a4524   DISPATCHER entry
0xfffffe00070a4528   mrs x8, guarded ESR (S3_6_C15_C10_5)
0xfffffe00070a452c   and x8, #0x1f  (call type)
...                  dispatch to T0 (0xa4a14)
0xfffffe00070a4a14.. T0 runs linearly (save x0-x7, frame setup)
0xfffffe00070a4ac0   b ->0xe8d4c  (HALTED here; service not run)
```

So the genter goes straight to the dispatcher `0xa4524` (not the per-CPU init
`0xb0b98`) -- the guest's steady-state `GXF_ENTER` is the dispatcher, as expected;
the earlier EL2 read of m1n1's `_gxf_entry` was a different (EL2/GL2) bank. The
multi-call driver's mechanism is therefore sound: setting x16 at `0xf8b88` and
letting the genter proceed reliably reaches the type-0 dispatch and the service.
