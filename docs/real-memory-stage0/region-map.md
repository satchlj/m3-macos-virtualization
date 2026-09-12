# Stage-0 region map — monitor context pointer table (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Stage-0 prerequisite 2 of the real-memory phase
([real-memory-phase-plan.md](../real-memory-phase-plan.md)): enumerate the SPTM
monitor's context pointer table (the structure regions it initializes) and
specify exactly what one future gated hardware snapshot must capture to complete
the VA→IPA map. **Offline, read-only.** All findings are derived from the
attempt-9 bundle (`artifacts/runs/observe-sprr/attempt-9/`), cross-checked
against attempt-8, using `scripts/trace_disassembly.py` and
`scripts/guest_pt.py` (`translate`). No hardware, device, or probe run was
performed.

## The context base is the per-CPU SPTM context struct (TPIDR_EL2)

The "context base register x9" is `TPIDR_EL2`. Across the run the monitor loads
it with `mrs x?, TPIDR_EL2` and also writes it with `msr TPIDR_EL2, x8`
(`0xfffffe00070df304`); in this boot its value is:

- **context base VA = `0xfffffe0007106200`** (held in x9/x20/x23/x24/x0 at the
  init sites). It is a normal high-half address that resolves through ttbr1 to
  **IPA `0x10017106200`** (sptm `__DATA`, guest offset `0x7106200`), i.e. the
  per-CPU struct lives in ordinary guest RAM the monitor owns.

It is one element of a per-CPU array with **stride `0x14c0` (5312) bytes**
(`madd x19, x21, x23, x8` with `w23=5312`, index `x21` in `0..8`; the primary
CPU's element equals the context base above). The pointer fields enumerated
below are the same offsets in every element.

This boot's monitor MMU controls (per-boot; do not hard-code):
`ttbr1 = 0x10017060000`, `ttbr0 = 0x10017064000`,
`tcr = 0x10800236511a511`, `mair = 0x0c0804ff00bb44ff`.

## Task 1 — enumerated context-pointer offsets

Method: scanned all 7,808,308 archived step events for every instruction whose
base register held the context-base value, then disassembled each site. The
table is **populated** in two blocks and **read back / RMW-initialized** later.
Populate site 1: `0xfffffe00070bd59c–…bd6d8`. Populate site 2 (per-CPU loop):
`0xfffffe00070df33c–…df4f4` and `0xfffffe00070dff10–…dfff8`. The stored values
were read directly from the trace register file.

Pointer-bearing slots (8-byte unless noted). "Kind" = IPA (guest-physical, no
walk needed) or VA (high-half, needs a stage-1 walk):

| Offset | Kind | Value (this boot) | Region | VA→IPA status |
|-------:|------|-------------------|--------|---------------|
| `0x0a48` | VA | `0xfffffdf000080000` | E | **unresolved** |
| `0x0a50` | VA | `0xfffffdf000088000` | F | **unresolved** |
| `0x0a58` | VA | `0xfffffdf00008c000` | G | **unresolved** |
| `0x12e0` | IPA | `0x211050000` | A (IPA) | n/a (is the IPA) |
| `0x12e8` | IPA | `0x211f00000` | C (IPA) | n/a (is the IPA) |
| `0x12f0` | IPA | `0x211e40000` | B (IPA) | n/a (is the IPA) |
| `0x12f8` | VA | `0xfffffe0038020000` | A | **resolved → `0x211050000`** |
| `0x1300` | VA | `0xfffffe003802c000` | C | **resolved → `0x211f00000`** |
| `0x1308` | VA | `0xfffffe0038070000` | B | **resolved → `0x211e40000`** |
| `0x1310` | VA | `0xfffffe0034000000` | D | **unresolved** |
| `0x1450` | VA | `0xfffffdf000038000` | H | **unresolved** |

Non-pointer fields at the same base (for completeness, not regions): byte flag
at `0x0` (`stlrb`, "initialized"), byte flag at `0x2`, `0x0a30`/`0x0a60` zeroed
bytes, count `0x100` at `0x12d0`, 16-bit `0` at `0x12d8`, count `0xe` at
`0x1438`, and zeroed fields at `0x1318`/`0x1440`(128-bit)/`0x1458`. The first
0x40 bytes are zeroed by `stp q0,q0,[ctx]` at `0xfffffe00070b1020`.

### How the table is filled (provenance)

Populate site 1 calls a name-keyed lookup three times
(`bl` at `…bd5d4/…bd610/…bd64c`, arg `x1` = a `__TEXT`/const descriptor-name
pointer) that returns a 16-byte `{base_ipa, size}` blob (`cmp w0,#1`;
`cmp size_field,#16`). It stores the **IPA** at `0x12e0/0x12e8/0x12f0`, then
calls an **IPA→VA map helper** (`bl` → `0xfffffe00070dc780`) whose return VA is
stored at `0x12f8/0x1300/0x1308`. So A/C/B are `{IPA, VA=map(IPA)}` pairs — the
struct carries both halves, which is why they are resolvable offline. Populate
site 2 (per-CPU loop, 8 iterations) fills D/E/F/G/H from **monitor-internal
physical globals** (`adrp`-loaded bases + `index<<14`, then the same map
helper); no adjacent IPA slot is stored for them, so their IPA is not in the
capture.

The later read-back / RMW initialization (the observation boundary) dereferences
`*(ctx+0x12f8)` and `*(ctx+0x1308)` and does OR-a-flag RMW into region A at
`+0x5000/+0x5008` and region B at `+0x9000/+0x9008`
(`0xfffffe00070bf8b8…bf948`).

## Task 2 — known VA→IPA pairs and what remains

Three regions are **fully resolved offline** — confirmed two independent ways:
(a) the IPA is stored beside the VA in the struct, and (b) `guest_pt.translate`
walking this boot's ttbr1 over the diagnostic-captured table pages reproduces it:

- **Region A**: VA `0xfffffe0038020000` → IPA `0x211050000` (L3), size `0x9010`.
- **Region B**: VA `0xfffffe0038070000` → IPA `0x211e40000` (L3), size `0xb028`.
- **Region C**: VA `0xfffffe003802c000` → IPA `0x211f00000` (L3), size `0x40088`.

(Region C is newly resolved here — it was not in the prior boundary note.)
Sizes are the `size` field of each `{base,size}` descriptor; backing bound =
`ceil(size/0x4000)` pages: A 3, B 3, C 17.

**Still needing VA→IPA resolution** (high-half VAs, no IPA stored, and
`translate` cannot reach them from the pages captured so far):

- **Region D**: VA `0xfffffe0034000000` — walk misses **L3 page `0x10019898000`**.
- **Region E**: VA `0xfffffdf000080000` — walk misses **L2 page `0x10017074000`**.
- **Region F**: VA `0xfffffdf000088000` — same L2 `0x10017074000`.
- **Region G**: VA `0xfffffdf00008c000` — same L2 `0x10017074000`.
- **Region H**: VA `0xfffffdf000038000` — same L2 `0x10017074000`.

(The `0x10017074000`/`0x10019898000` addresses are this boot's table pages, shown
only to prove the gap; the spec below is in VAs because ttbr1 is per-boot.)

### Corroboration from the fault progression

- attempt-8 backed only `0x211050000` (1 page) → faulted `Unmapped IPA 0x211055008`
  = region A `+0x5008` (first RMW).
- attempt-9 backed `0x211050000:16` (region A) → advanced past A, faulted
  `Unmapped IPA 0x211e49008` = region B `+0x9008` (next RMW).

Both fault IPAs equal `region_IPA + observed_RMW_offset`, confirming the
slot→region→IPA mapping and that init walks the table in order A, then B, then
(next) C, D, E–H.

## Task 3 — the single gated hardware capture that completes the map

The probe already has the needed mechanism: `--snapshot-leaf VA` reads the live
`TTBR0/TTBR1/TCR/MAIR` at exit, runs `guest_pt.translate(VA, …)`, and for **every
table page the walk touches** saves it as `inputs/leaf-<va>-<table>.bin`, while
recording `final_leaf_snapshots[VA] = {pa, level, descriptor}` and
`final_leaf_controls`. Verified: attempt-9's single `--snapshot-leaf` saved its
full L1→L2→L3 chain (`leaf-…-10017060000/…68000/…6c000.bin`). **No probe change
is required — only additional VAs.**

Spec for the one Stage-0 diagnostic run (same config as attempt-9:
`--virtual-gxf --stage-el2-config --observe-sprr --allow-monitor-mmu
--allow-live-ttbr`, no SPRR enable, no real backing), adding one
`--snapshot-leaf` per VA below:

1. **Unresolved regions (required):**
   `--snapshot-leaf 0xfffffe0034000000` (D),
   `--snapshot-leaf 0xfffffdf000080000` (E),
   `--snapshot-leaf 0xfffffdf000088000` (F),
   `--snapshot-leaf 0xfffffdf00008c000` (G),
   `--snapshot-leaf 0xfffffdf000038000` (H).
2. **Re-validation on the same boot (recommended):**
   `--snapshot-leaf 0xfffffe0038020000` (A),
   `0xfffffe003802c000` (C),
   `0xfffffe0038070000` (B) — so all eight VA regions are pinned to this boot's
   ttbr1 in one capture, not spread across boots.

What the capture yields and how it completes the map:

- `final_leaf_snapshots[VA].pa` gives each region's IPA directly; and
- the saved `inputs/leaf-<va>-<table>.bin` pages let `guest_pt.translate`
  reproduce every walk offline (root + all L1/L2/L3 along the path), so the map
  is verifiable, not just asserted.

Because the walk saves whatever table pages it reads, the per-boot table IPAs
(`0x10017074000`, its L3 children, `0x10019898000`, …) do **not** need to be
known in advance — they are discovered by walking the boot-invariant VAs. The
VAs above are the monitor's fixed high-half structure addresses and are the
correct stable key for the spec.

### Resulting real-DRAM backing set (for Stage R1, once IPAs are in hand)

Regions to back (`--back-page IPA:COUNT`), scattered, RMW semantics:
A `0x211050000:3`, B `0x211e40000:3`, C `0x211f00000:17`, plus D/E/F/G/H at the
IPAs the snapshot resolves (counts = `ceil(size/0x4000)`; D/E/F/G/H sizes to be
read from their `{base,size}` descriptors on the same run). These IPAs span
`0x211050000…0x211f00000+` (region-2/DRAM the monitor manages) — consistent with
the plan's prereq-4 note that only ordinary managed DRAM is acceptable to back.

## Open questions carried to R1

- Confirm D/E/F/G/H `{base,size}` (site-2 descriptors) to size their backing.
- The site-1 lookup is name-keyed against monitor const strings; the site-2
  bases come from physical globals seeded earlier in boot — their provenance
  (ADT vs. computed) is the remaining "whose values does RMW expect" question in
  the plan.
