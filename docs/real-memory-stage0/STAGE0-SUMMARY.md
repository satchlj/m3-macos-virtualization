# Real-memory phase — Stage 0 summary (2026-09-10)

Wave 1 of Stage 0 is complete: four independent, read-only offline analyses of
the attempt 4–9 artifacts and the sptm image, run in parallel, no hardware
touched. This consolidates them and defines the one sequential hardware step that
follows. Source analyses:

- [region-map.md](region-map.md) — the monitor's context pointer table.
- [safe-dram-range.md](safe-dram-range.md) — where real backing frames come from.
- [mutation-and-extent.md](mutation-and-extent.md) — what the monitor writes and how it sizes memory.
- [sprr-permission-model.md](sprr-permission-model.md) — the SPRR model and hardware-SPRR go-conditions.

## Consolidated picture

**The structures are per-CPU ownership-descriptor tables.** The context base is
`TPIDR_EL2` (a per-CPU struct, stride `0x14c0`, 8 elements). It holds a table of
8 region pointers. The monitor initializes paired 16-byte descriptor slots with
a read-modify-write (word0 `|= valid`, word1 `|=` a permission/ownership bitmap).
The init is **straight-line over a fixed set of regions**, not an unbounded loop,
so backing that fixed set should clear the whole routine.

**Eight regions; three resolved offline, five need one walk.**

| Region | VA (this boot) | IPA | Backing pages |
|--------|----------------|-----|---------------|
| A | `0xfffffe0038020000` | `0x211050000` | 3 |
| B | `0xfffffe0038070000` | `0x211e40000` | 3 |
| C | `0xfffffe003802c000` | `0x211f00000` | 17 |
| D | `0xfffffe0034000000` | *unresolved* | TBD |
| E | `0xfffffdf000080000` | *unresolved* | TBD |
| F | `0xfffffdf000088000` | *unresolved* | TBD |
| G | `0xfffffdf00008c000` | *unresolved* | TBD |
| H | `0xfffffdf000038000` | *unresolved* | TBD |

A/B/C are confirmed two ways (the struct stores `{IPA, VA}` pairs, and a
`translate` walk reproduces them). D–H store only VAs; their IPAs need a stage-1
walk from a same-boot capture. The fault progression corroborates the map:
attempt-8 faulted at A+0x5008, attempt-9 (A backed) at B+0x9008 — each fault IPA
= region IPA + RMW offset.

**Backing frames come from a safe DRAM pool.** Recommended pool
`0x10100000000 .. 0x10140000000` (1 GiB) in the ~15 GiB free DRAM gap, clear of
the guest window, m1n1 image+heap, TZ0/TZ2 carveouts, and device MMIO. The region
IPAs sit *below* RAM base in an unmapped low-IPA hole, so R1 hands the monitor
real frames *from the pool*, mapped into stage-2 at the fixed region IPAs — the
mechanism `--back-page` already uses, just with real (not zeroed) frames.

**The monitor sizes memory from the ADT, which we control.** DRAM extent comes
from `/chosen` `dram-base`/`dram-size` (page count = `size >> 14`), and region
bases from `chosen/memory-map` — both in the ADT the probe pushes at chainload.
AMCC/CTRR only *lock* the region; they don't source the extent. This is a lever:
if any structure scales with `dram-size`, we can reconcile it with the pool we
supply. For this init routine the regions are individually sized by their
`{base,size}` descriptors, so backing the eight bounded regions should suffice
without touching the ADT; the lever is held in reserve.

**SPRR is W^X only in the guarded world** — relevant to R2, not R1. Every
captured leaf diverges native-vs-SPRR; ordinary-world collapses to read-only,
only the guarded world gives a coherent W^X monitor. Hardware SPRR must be
enabled *only jointly with a real guarded entry*, with the exact captured
register values and lock order — an R2 concern. R1 keeps virtual GXF and SPRR
off.

## Next sequential step: one gated hardware capture

The sequential chokepoint. One diagnostic run, **same config as attempt-9**
(virtual GXF, staged EL2 config, observe-sprr, monitor-mmu, live-ttbr; no SPRR
enable, no real backing), adding `--snapshot-leaf` per region VA. **No probe
change is required** — `--snapshot-leaf` already records each VA's resolved PA and
saves every table page its walk touches.

- Required (resolve D–H): `--snapshot-leaf` for
  `0xfffffe0034000000`, `0xfffffdf000080000`, `0xfffffdf000088000`,
  `0xfffffdf00008c000`, `0xfffffdf000038000`.
- Recommended (pin A/B/C to the same boot): `--snapshot-leaf` for
  `0xfffffe0038020000`, `0xfffffe003802c000`, `0xfffffe0038070000`.

Output completes the VA→IPA map for all eight regions (verifiable offline via the
saved pages) and reads their `{base,size}` for backing counts.

**Optional same-run extension (closes the R2 SPRR coverage gap):** the SPRR
analysis found three uncaptured `PXNTable` L2 sub-hierarchies the validator fails
closed on. If we identify one representative VA inside each (a short follow-on to
the region-map analysis), adding those `--snapshot-leaf` VAs closes the SPRR gap
in the *same* capture, saving a later hardware run. Not required for R1; worth
doing since captures are the serial cost.

## R1 design (once IPAs are in hand)

- Back the eight regions with real frames from the safe pool, mapped into stage-2
  at their IPAs: `--back-page 0x211050000:3` (A), `0x211e40000:3` (B),
  `0x211f00000:17` (C), plus D–H at resolved IPAs/counts. This needs a probe
  change: `--back-page` currently zeroes host scratch; R1 needs a "real frame"
  mode (allocate from the pool, do not zero, or zero-once-then-let-the-monitor-own).
- Keep virtual GXF and SPRR off (R1 is not R2).
- Because init is straight-line over these eight regions, backing all eight is
  expected to clear the init routine and reach the next dependency. Confirm clean
  HV exit and installed boot intact after the run (plan prereq 3).

## Stage 0 gate status

- [x] Prereq 2 (region map): enumerated; A/B/C resolved, D–H pending one capture.
- [x] Prereq 1 (SPRR model): decoded; R2 go-conditions defined; coverage gap known.
- [x] Safe real-DRAM range chosen.
- [~] Prereq 4 (mutation scope): characterized as ownership-descriptor RMW on
  managed DRAM; D–H base provenance is the remaining "expected content" question.
- [ ] Prereq 3 (reversibility): to confirm on the capture run (clean exit, boot
  intact) before any real backing.
- [ ] The one gated capture (above) → then Wave 2 offline completes the map → R1.

## Capture results — attempts 10 & 11 (2026-09-10)

The single snapshot capture (attempt-10) and one follow-up (attempt-11) turned in
a bigger result than planned.

**attempt-10** (attempt-9 config + 10 `--snapshot-leaf` VAs, observation only):
- **SPRR coverage gap closed.** All three PXNTable L3 sub-hierarchies were walked
  and their pages saved (this boot: `0x10019898000` / `0x1001989c000` /
  `0x100198a0000`). The gap VAs returned "Unmapped" only because their specific
  leaves are invalid; the table pages with their real leaves are captured, so
  Wave 2 can decode them offline.
- **Region map: 5 of 8 resolved.** A `0x211050000`, B `0x211e40000`, C
  `0x211f00000` (revalidated same-boot); newly **G `0x100198b8000`, H
  `0x10019864000`** (both in the monitor's own guest RAM). D/E/F were unmapped at
  the region-B-fault exit.

**attempt-11** (back A/B/C zeroed to advance; snapshot D/E/F/G/H): ran the **full
16,777,216-step budget with NO stage-2 fault**.
- **D, E, F are dormant.** Even at 16 M steps their VAs are never mapped; the
  monitor stores those pointers but does not dereference them in this run. Only
  A, B, C (low-hole, need backing) and G, H (guest RAM, pre-mapped) are actually
  accessed. So the map of *accessed* regions is complete.
- **Milestone: SPTM completes full initialization and parks in a WFE idle loop.**
  After init it reaches `wfe; b .-4` at `sptm/__TEXT_EXEC+0xf4b88`, waiting for an
  event (on a real system: secondary CPUs or a kernel call). Backing just A/B/C —
  with **zeroed** frames — was sufficient to clear the entire structure init and
  every subsequent dependency through to idle.

### What this means for R1 and beyond

- **R1 backing set is small: A, B, C** (`0x211050000:3`, `0x211e40000:3`,
  `0x211f00000:17`). D/E/F need no backing (dormant); G/H are already in guest RAM.
- **Zeroed backing sufficed through full init.** The RMW-on-zeroed fidelity
  concern did not block reaching WFE idle. Real-content backing may still matter
  for what the monitor does *after* it is woken, but is not required to complete
  init. This lowers R1's commitment: the "real-frame" `--back-page` mode is a
  refinement, not a blocker, for reaching idle.
- **New frontier: the WFE wake.** The monitor is idle waiting for an event. The
  next real question — the actual subject of the real-memory/real-execution phase
  — is what wakes it (secondary-CPU bring-up, an interrupt/doorbell, or a monitor
  call interface) and what it does next (launch the kernel below it, service a
  call). That is beyond Stage 0.

### Updated region map (accessed regions)

| Region | VA | IPA | Backing | Status |
|--------|----|----|---------|--------|
| A | `0xfffffe0038020000` | `0x211050000` | 3 | accessed (RMW) |
| B | `0xfffffe0038070000` | `0x211e40000` | 3 | accessed (RMW) |
| C | `0xfffffe003802c000` | `0x211f00000` | 17 | accessed (RMW) |
| D | `0xfffffe0034000000` | — | — | dormant (pointer stored, never mapped) |
| E | `0xfffffdf000080000` | — | — | dormant |
| F | `0xfffffdf000088000` | — | — | dormant |
| G | `0xfffffdf00008c000` | `0x100198b8000` | in guest RAM | accessed |
| H | `0xfffffdf000038000` | `0x10019864000` | in guest RAM | accessed |
