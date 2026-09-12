# genter driver — design (2026-09-10, sub-step 3)

How to issue a real guarded call so SPTM services it, given the call ABI
([call-abi.md](call-abi.md)), the wake path ([wake-path.md](wake-path.md)), and
the finalized SPRR model ([sprr-permission-model.md](sprr-permission-model.md)).
This is the core new mechanism of Phase 2 / R2. Design only — no hardware.

## Execution model

SPTM and the kernel both run at EL1, in two GXF worlds: SPTM is the **guarded**
world, the kernel is the **normal** world; `genter`/`gexit` switch worlds at the
same EL. Our HV sits above at EL2 and observes. In the observation phase we
**virtualized** GXF (rewrote `genter`/`gexit` to HVC) and **staged** SPRR (never
enabled it), and SPTM reached its guarded idle `wfe`.

To drive a real call, a **normal-world EL1 caller must execute a real `genter`**.
That requires two things we deliberately avoided before:
1. **Real GXF** — stop virtualizing `genter`; let `GXF_CONFIG` be genuinely
   enabled so `genter` is defined and transfers to `GXF_ENTRY`.
2. **Real SPRR** — the guarded world runs under SPRR, so it must be really
   enabled, reproducing the monitor's exact sequence with the captured registers
   (gated by the sub-step-2 go-conditions).

## What changes from the observation probe

- **Un-virtualize GXF**: don't rewrite `genter`/`gexit`; allow real guarded
  transitions. We lose the `VEL2-STAGE` staged-register visibility — see
  Observability below.
- **Enable real SPRR** per the go-conditions: reproduce `CONFIG 0x1 → 0xfb →
  genter → 0xff` with the captured `PPERM/UPERM/PMPRR`, validate all six leaf
  classes at the **enable-point** ttbr snapshot (state mutates between passes),
  confirm no leaf grants user access.
- **Back the real regions (R1)**: A `0x211050000:3`, B `0x211e40000:3`,
  C `0x211f00000:17` so SPTM's managed structures are real while it operates.
- **Provide a normal-world EL1 caller** (the driver stub) — below.

## The driver mechanism — two options

**Option B (recommended for first contact): synthetic normal-world entry.**
After SPTM reaches a known post-init point, the HV (EL2) constructs a minimal
normal-world EL1 context (a plausible `TTBR/SCTLR/VBAR/SP`, PSTATE=EL1) and enters
a small stub we control. The stub sets `x16 = selector`, `x0–x7 = args`, executes
`genter`, and on return writes the result to a known location the HV reads. Most
control, least dependence on unknowns; the cost is constructing a normal-world
context SPTM will accept.

**Option A (fidelity, later): real kernel launch.** Let SPTM run its own
kernel-launch path and place our stub where it launches the normal world, then
have the stub `genter`. Higher fidelity, but needs the kernel-launch selector /
path — the open item from sub-step 1, cheaply obtainable by observing the first
`genter` once Option B works.

Recommendation: **B first** to make first contact with the guarded-call
interface, then **A** to confirm the real launch path and the launch selector.

## The stub

A tiny normal-world EL1 program: `mov x16,#<selector>; <set x0..x7>; genter;`
then publish the returned `x0` (to a fixed RAM cell the HV reads, or via an HVC we
retain purely for observation). **Start with a non-mutating/query selector** — the
goal of first contact is to observe the call → dispatch → gexit round trip and the
result, not to change monitor state. Only after the round trip is understood do we
try selectors that do work.

## Observability tradeoff (important)

Un-virtualizing GXF removes the staged-register interception that gave the
`VEL2-STAGE hvc=…` stream. Under real GXF+SPRR we observe via: EL2 single-step
tracing (MDSCR/SS, as the probe already does), selective EL2 traps
(HCR/SCTLR/specific registers), and reading guest memory. We should decide up
front which registers/events still trap to EL2 so first contact is legible — e.g.
keep a step trace across the `genter` boundary to watch the world switch and the
dispatcher, and snapshot the guarded per-CPU frame before/after.

## Prerequisites and safety

- **SPRR go-conditions met** (sub-step 2): enable only jointly with real
  `genter`, exact captured values/lock order, validate the six leaf classes at the
  enable-point snapshot, no user access.
- **HV retains control**: the HV is at EL2, above both worlds, so EL2 traps and
  single-step keep us in control even under real SPRR/GXF. Confirm the guest
  cannot disable our EL2 step/trap path.
- **Reversibility rehearsal** before first real `genter`: confirm clean HV exit,
  `chainload_preserve_boot` restores the installed boot, and no persistent/secure
  state (SEP, fuses, CTRR-locked regions) is written. Start non-mutating; bound
  the step budget; use a fresh-boot gate.

## Open questions / decisions before building

1. **Normal-world context SPTM expects.** SPTM saved and restores a kernel
   context (`ELR/SPSR/ESR/FAR/SP_EL0`, TTBR, VBAR). Option B must set up a
   context consistent enough that the dispatcher and the `gexit` return path work.
   Enumerate exactly what the type-0 path reads about the caller.
2. **Which selector for first contact.** Need one known non-mutating call.
   Absent the full selector map, candidates: a version/capability query. Decide
   from a targeted decode or accept discovery-by-observation.
3. **SPRR enable point.** Reproduce the monitor's own sequence vs enable at a
   synthetic point; the former is safer (matches the validated snapshot).
4. **Observability plan.** Which traps/steps to keep so first contact is legible
   without the staging stream.

## Gate to build/run

Option B stub + normal-world context spec + chosen non-mutating selector +
observability plan + reversibility rehearsal → first real-`genter` hardware run,
under a fresh-boot gate, bounded, non-mutating.

## Pre-idle dry run — validating Piece 1 (the real-SPRR/GXF-enable mechanism)

Piece 1 (`--real-guarded`, committed) un-virtualizes `genter`/`gexit` and applies
SPRR/GXF config for real via EL2 `u.msr`. Before trusting that path, one bounded
hardware dry run validates the **enable mechanism** and recovery — it does **not**
attempt a full guarded run (Piece 1 does not yet make the guarded register set —
`GXF_ENTRY/PABENTRY`, GL bank, `TPIDR_GL2` — real, so the monitor's first native
`genter` will fault; that is Piece 2).

**The one thing this run answers:** does an EL2 `u.msr` of `SPRR_CONFIG_EL1`
(and the permissions, `GXF_CONFIG_EL1`) apply to the **guest**, with the **HV
surviving** and retaining control — or does it hit the HV's own EL2 SPRR under VHE
and break us? That is the pivot point for the whole approach.

**Config:** `--real-guarded --allow-monitor-mmu --allow-live-ttbr
--emulate-zero-loops --relocate-boot-data --stage-el2-config
--stop-on-vector-entry --single-step-after ~7786000 --steps 16777216
--step-batch 256 --trace-window 8192`. No `--virtual-gxf`, no `--observe-sprr`,
no `back_page` (SPRR enable at ~7.786M precedes the region RMW, so no backing is
needed to reach it).

**Expected trajectory:** batch to ~7.786M → single-step → real SPRR enable
(`CONFIG 0x1→0xfb`, permissions applied) → real `GXF_CONFIG=1` → a few instructions
→ first **native `genter`** → fault (guarded regs not yet real) → vector/`0xDEAD`
→ `stop-on-vector-entry` halts → clean exit.

**Success criteria:**
1. The HV **survives** the SPRR enable — the callback keeps running and single-step
   continues past it (proves `u.msr` reached the guest, not EL2).
2. `report['sprr_real_enable']` is populated with the enable-point ttbr snapshot and
   applied permissions.
3. Read-back `u.mrs(SPRR_CONFIG_EL1)` after enable equals the written value.
4. The run reaches the native `genter` and **stops cleanly** (vector-entry), not a
   hang; proxy returns; installed boot intact (this is also the reversibility
   rehearsal for the enable path).

**Failure mode and pivot:** if the HV hangs/faults at the enable, `u.msr` is hitting
EL2's own SPRR — pivot to *not* rewriting `SPRR_CONFIG` (let the guest's native
`msr` apply it, validate via single-step). The fresh-boot gate + preserved
chainload guarantee recovery either way.

**Safety:** fresh-boot gate + one owner; single-stepped near the enable so we can
halt; `stop-on-vector-entry` bounds the tail; non-mutating (no region backing, no
service). Bounded and recoverable by construction.
