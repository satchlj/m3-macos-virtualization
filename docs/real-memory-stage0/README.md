# real-memory-stage0 — index

Navigation for the "real-memory / real-guarded" phase of the M3 SPTM research.
Start here. Parent context: [../real-memory-phase-plan.md](../real-memory-phase-plan.md).

## Overview

This phase takes the SPTM monitor from the observation sandbox (isolated guest,
staged-never-applied security state) toward operating against real machine memory
and real guarded execution. Stage 0 (offline) built the region map, the safe
DRAM range, the mutation model, and the SPRR permission model; **R1 (real backing
under virtual GXF) is effectively demonstrated** — backing just the three
scattered regions A/B/C, even with zeroed frames, carried SPTM through full
initialization to a WFE idle loop. The frontier is **R2, the guarded-call wake
via `genter`**. As of the latest doc
([attempt-17-real-genter.md](attempt-17-real-genter.md)), the real-enable
mechanism has been resolved and **native `genter` now works — the first real
guarded execution under the probe** (a real world switch into the guarded world),
but one step later execution **diverts to a spin at physical `0x100033f1a00`**
(below the guest window, in the m1n1/boot region). The next step is a batched
re-run (attempt-18) plus capturing the guarded vector/bank state (`VBAR_GL1`,
`GXF_ENTRY_EL1`, the guarded exception bank) to determine what that divert is.

## Contents

| Doc | Covers |
|-----|--------|
| [STAGE0-SUMMARY.md](STAGE0-SUMMARY.md) | Consolidated Stage-0 picture: per-CPU ownership-descriptor tables, the 8-region map (accessed A/B/C, dormant D/E/F, guest-RAM G/H), safe DRAM pool, ADT-sourced extent, and the attempt-10/11 capture results (SPRR gap closed, full init → WFE idle). |
| [region-map.md](region-map.md) | The monitor's context pointer table (`TPIDR_EL2`, stride `0x14c0`): enumerated pointer offsets, the eight regions, VA→IPA resolution (A/B/C resolved, D–H pending), and the single `--snapshot-leaf` capture that completes the map. |
| [safe-dram-range.md](safe-dram-range.md) | The safe real host-DRAM pool for R1 backing (recommended `0x10100000000..0x10140000000`), the authoritative target M3 machine map, and the reserved regions (guest window, m1n1/heap, boot-data homes, TZ0/TZ2, MMIO) that must never be handed over. |
| [mutation-and-extent.md](mutation-and-extent.md) | What the monitor writes (the read-modify-write descriptor-init function, 16-byte `{valid bit, permission bitmap}` slots) and how it learns physical extent (from the ADT `/chosen` `dram-base`/`dram-size` and `chosen/memory-map`, not a register). |
| [sprr-permission-model.md](sprr-permission-model.md) | The offline-validated Apple SPRR permission model: leaf index decode, the six leaf classes over 13,857 leaves (Wave 2 / attempt-10), native-vs-SPRR divergence, guarded-world W^X, and the finalized go-conditions for any hardware SPRR enable. |
| [wake-path.md](wake-path.md) | How SPTM leaves the WFE idle: the park routine, why EL vectors are record-then-fatal (`VBAR` → `0xDEAD`), and the real service path — GXF guarded-call dispatch at `GXF_ENTRY_EL1 = 0xa4524` with the call type in the guarded ESR. |
| [call-abi.md](call-abi.md) | The guarded-call ABI: the type dispatch (types 0–4), the type-0 call path (selector in x16, args x0–x7, result x0 via gexit), and the gexit-terminal C service handler (`0xe8d8c`); what is established vs. still open (the per-selector map). |
| [genter-driver-design.md](genter-driver-design.md) | Design for issuing a real guarded call: un-virtualize GXF + enable real SPRR + a normal-world EL1 stub; Option B (synthetic entry) for first contact vs. Option A (real launch); observability tradeoff and the Piece-1 pre-idle dry-run plan. |
| [first-contact-spec.md](first-contact-spec.md) | Tight build spec for the first real `genter`: the safety realization (single-step halts at the dispatcher before the service, so first contact is non-mutating regardless of selector), the normal-world context to construct, and the observability plan. |
| [real-enable-mechanism.md](real-enable-mechanism.md) | How `--real-guarded` must apply the guest's SPRR/GXF: the early pre-MMU setup, the three tried mechanisms, and the resolution — EL12-alias redirect via `HV.MSR_REDIRECTS`; open item: non-redirectable perms (PMPRR / `*_SH{1,2,3}`) have no alias. |
| [attempt-17-real-genter.md](attempt-17-real-genter.md) | The latest hardware attempt: the EL2 SPRR/GXF context fix, advancing to 7.786 M+ events, the real `genter` world switch (first real guarded execution), the immediate divert to a spin at `0x100033f1a00`, and the offline-prepared next steps. |
| [attempt-17-divert-analysis.md](attempt-17-divert-analysis.md) | Source-grounded analysis of the post-genter divert: full-trace facts + vel2 GXF study. `genter` is a fixed-pointer transfer, so the divert is a separate guarded exception vectoring to `VBAR_GL1 + 0x200`. Two falsifiable predictions for attempt-18 (`VBAR_GL1 == 0x100033f1800`, `GXF_ENTRY_EL1 == 0xb0b98`). |
| [attempt-18-divert-confirmed.md](attempt-18-divert-confirmed.md) | Hardware confirmation: both attempt-17 predictions TRUE. `GXF_ENTRY_EL1=0xb0b98`, `VBAR_GL1+0x200` = the spin, `ESR_GL1` instr-abort translation-fault L1. The block is uninstalled guarded vectors, not genter. Next: bounded single-step for the original trigger syndrome. |

## Attempt ledger (real-guarded arc)

Scope: the real-guarded hardware attempts as attested by these docs. (Earlier
attempts 4–9 are the observation-phase artifacts the Stage-0 analyses were built
from; attempts 10–11 are the R1 captures.)

| Attempt | What it did | What it established |
|--------:|-------------|--------------------|
| 8 | Backed only `0x211050000` (1 page) | Faulted at region A `+0x5008` (first RMW) — confirmed slot→region→IPA mapping. |
| 9 | Backed region A | Advanced past A, faulted at region B `+0x9008` — the reference config for the Stage-0 analyses. |
| 10 | attempt-9 config + 10 `--snapshot-leaf` VAs (observation only) | Closed the SPRR coverage gap (all three PXNTable L3 sub-hierarchies walked; 13,857 leaves, no missing tables); resolved 5 of 8 regions. |
| 11 | Backed A/B/C zeroed, snapshot D–H | Ran the full 16 M-step budget with **no fault**: SPTM completes init and parks in a WFE idle loop. D/E/F dormant; G/H already in guest RAM. **R1 effectively demonstrated.** |
| 12–16 | Real-enable mechanism iterations (`--real-guarded`) | Mapped how to apply the guest's SPRR/GXF. Doc-attested specifics: **13** — EL2 `u.msr` of the EL1 register name writes the HV's *own* copy under VHE (guest GXF never enabled); **14** — native execution leaves the guest's `SPRR_PPERM_EL1` write EC-0 undefined (EL1 SPRR is gated by EL2). Attempts **14–16 stalled at ~258 events**. Resolution: apply SPRR/GXF via their **EL12 aliases** (`HV.MSR_REDIRECTS`), keeping `genter`/`gexit` native. |
| 17 | `--real-guarded` hybrid + the EL2 SPRR/GXF **context fix** (`u.msr(SPRR_CONFIG_EL1,1)` + `u.msr(GXF_CONFIG_EL1,1)` before the guest runs, mirroring the vel2 HV) | **First real guarded execution.** Advanced to 7.786 M+ events; real `genter` performed a real world switch (SPSR bit `0x400000` set = guarded world). Then **diverted to a spin at physical `0x100033f1a00`** (below the guest window) for the remaining ~525 K events. Next: batched re-run + guarded-bank capture. |

Note: the docs directly attest attempts 13, 14, the 14–16 event stall, and the
attempt-17 result. The finer "attempt 12 = guard too strict / 15–16 = EL12-alias
hybrid" breakdown comes from the attempt records outside this directory and is not
detailed in these Stage-0 docs; the row above states only what the docs support.

## Open questions

- **What is the divert to `0x100033f1a00`?** SPSR was unchanged across the jump
  (not a fresh EL exception). Likely a guarded-world exception vectoring through
  `VBAR_GL1` (if it points into the m1n1/boot region), or a jump to a
  stale/parked address because the guarded entry target was never set to a real
  handler under the probe. Resolved by capturing `VBAR_GL1`, `GXF_ENTRY_EL1`, and
  the guarded exception bank at the enter point — these are native/untrapped under
  `--real-guarded`, so it may need a small probe addition
  ([attempt-17-real-genter.md](attempt-17-real-genter.md)).
- **Non-redirectable permissions.** `SPRR_PMPRR_EL1` and the `SPRR_*_SH{1,2,3}`
  variants are not in `HV.MSR_REDIRECTS` (no EL12 alias); they currently stage. If
  the monitor writes them before the first `genter` and their absence breaks
  guarded execution, a mechanism for them is needed
  ([real-enable-mechanism.md](real-enable-mechanism.md)).
- **The per-selector guarded call map** — which selector (if any) launches the
  kernel below SPTM. The dispatch is obscured by heavy inlining; cheaper to obtain
  by observing the first real `genter` a kernel issues than by static decode
  ([call-abi.md](call-abi.md)).
- **The type-0 `genter` immediate** — the `genter #imm` that lands on
  guarded-ESR type 0 is hardware-specific and unverified; determine it
  empirically at first contact ([first-contact-spec.md](first-contact-spec.md)).
- **Normal-world context SPTM expects** for the Option-B synthetic caller — the
  exact caller state the type-0 path reads/restores
  ([genter-driver-design.md](genter-driver-design.md)).
- **Re-validate SPRR on population / at the enable point.** The structure tables
  mutate live during the run, so go-conditions must be validated against the exact
  enable-point snapshot; empty gap #1/#2 must be re-decoded if they populate
  ([sprr-permission-model.md](sprr-permission-model.md)).
- **Reversibility rehearsal** with real SPRR/GXF enabled but the stub halted
  before any service is still pending before the first-contact run
  ([first-contact-spec.md](first-contact-spec.md)).
