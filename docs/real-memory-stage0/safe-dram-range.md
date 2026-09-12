# Safe real-DRAM range — Stage 0 (real-memory phase)

Offline analysis only. This determines a real host-physical DRAM range we could hand
the SPTM monitor in stage R1, plus the reserved regions it must not overlap. No
hardware was touched to produce this; all numbers are read from the attempt-9 bundle,
the captured host ADT, and the m1n1 boot memory map echoed in prior chainload logs.

Target machine: target M3 (M3, board J613), 16 GiB DRAM.

## Sources

- `artifacts/runs/observe-sprr/attempt-9/report.json` — `layout` (regions,
  `boot_data_copies`), `boot_data_relocations`, `guest_boot_data_audit`, `guest_base`,
  `guest_size`, `diagnostic_backed_pages`.
- `.../attempt-9/runs/*/inputs/host-device-tree.adt` — `/chosen dram-base=0x10000000000`,
  `dram-size=0x400000000` (16 GiB). (The host ADT `/chosen/memory-map` entries are
  unfilled `0xffff…` placeholders; the filled values live in the report audit.)
- m1n1 boot memory map (identical across `artifacts/evidence/2026-09-09/mmu-sptm/…` and
  `…/vel2-smoke/vel2-chainload.log.txt`): RAM base, top of normal RAM, TZ0, TZ2, and the
  Device-nGnRE / Normal-NC mappings. attempt-9's own `console.log` is the probe console
  and does not re-echo this map, but the values are hardware-stable for target M3.

## Authoritative machine map (real host physical)

```
MMU: RAM base:            0x10000000000
MMU: Top of normal RAM:   0x103de7a4000
MMU: Unmapping TZ0 region  0x103de7a4000 .. 0x103e06b4000
MMU: Unmapping TZ2 region  0x103e6db0000 .. 0x103ffdb0000
Device-nGnRE (MMIO):      0x5a0000000, 0x5c0000000, 0x800000000, 0xa00000000,
                          0xc00000000, 0xe00000000   (all BELOW RAM base)
Normal-NC (fb/uncached):  0x103ffe24000, 0x103ffe74000, 0x103ffeb4000,
                          0x103fff04000, 0x103fff70000, 0x103fffb8000 (inside top carveout)
/chosen dram-base/size:   0x10000000000 + 0x400000000  → dram end 0x10400000000
```

Normal (usable) DRAM is `[0x10000000000, 0x103de7a4000)` = `0x3de7a4000` (15.48 GiB).
Everything from top-of-normal-RAM to dram end (`0x103de7a4000 .. 0x10400000000`,
~34 MiB TZ0 + gap + 400 MiB TZ2 + framebuffer) is secure/reserved carveout.

## Ranges table

Legend: OWN = ordinary DRAM the monitor could be given; RSV = reserved, never hand over.

| Range (host PA / IPA)                | Size        | What it is                                   | Class |
|--------------------------------------|-------------|----------------------------------------------|-------|
| `0x00000000000 .. 0x10000000000`     | —           | Low IPA hole + device MMIO (Device-nGnRE blocks at 0x5a0000000, 0x5c0000000, 0x8/0xa/0xc/0xe00000000) | RSV (not DRAM) |
| `0x10000000000 .. ~0x1000e228000`    | ~226 MiB    | m1n1 image + 128 MiB heap (`Heap limit 0x1000e204000`); contains the boot-data copies below | RSV |
| ├ `0x10003e4c000 .. 0x10003eac000`   | 384 KiB     | **RTBuddySeg** (real low-DRAM home)          | RSV |
| ├ `0x10003eac000 .. 0x1000441c000`   | 5.44 MiB    | **SEPFW** (real low-DRAM home)               | RSV |
| ├ `0x1000441c000 .. 0x1000445c000`   | 256 KiB     | **preoslog** (real low-DRAM home)            | RSV |
| └ `0x1000e228000 .. 0x1000e268000`   | 256 KiB     | probe `--back-page` diagnostic scratch (16 pages, zeroed) | RSV (in-use by probe) |
| `0x10010000000 .. 0x1001d82c000`     | 216.17 MiB  | **isolated guest window** (`guest_base`+`guest_size`): installed boot-object copy + relocated boot data (see below) | RSV (this is the boot object + guest window) |
| `0x1001d82c000 .. 0x103de7a4000`     | 15.02 GiB   | **ordinary unused DRAM** — the pool to draw from | **OWN** |
| `0x103de7a4000 .. 0x103e06b4000`     | 31.1 MiB    | **TZ0** carveout (TrustZone secure)          | RSV |
| `0x103e06b4000 .. 0x103e6db0000`     | 103 MiB     | above top-of-normal-RAM (SoC carveouts / gap), excluded from usable RAM | RSV |
| `0x103e6db0000 .. 0x103ffdb0000`     | 400 MiB     | **TZ2** carveout (TrustZone secure)          | RSV |
| `0x103ffdb0000 .. 0x10400000000`     | 2.3 MiB     | top carveout incl. Normal-NC framebuffer pages | RSV |

### Inside the guest window `[0x10010000000, 0x1001d82c000)`

The loaded boot object blob is `layout.size = 0x982c000` (153.2 MiB) at `guest_base`,
i.e. `[0x10010000000, 0x1001982c000)`; `guest_size` extends the window to
`0x1001d82c000`. Notable sub-regions (IPA = `guest_base` + blob offset):

- TrustCache `0x10011eec000` (+0x60000), DeviceTree `0x10016f00000` (+0x104000),
  SPTM-ro/rx/rw `0x10017004000..0x10017128000`, entry `0x100170ac388`,
  BootArgs `0x10019218000`.
- Relocated boot data (from `boot_data_relocations`, real low homes → guest window):
  RTBuddySeg → `0x1001921c000`, SEPFW → `0x1001927c000`, preoslog → `0x100197ec000`,
  aop `__OS_LOG` → `0x10019268000`, mtp `__OS_LOG` → `0x10019264000`.

The whole window is the sandbox and must be treated as off-limits for the new pool.

## Where the monitor's structure IPAs fall

- region A: `0x211050000` (VA `0xfffffe0038020000`)
- region B: `0x211e40000` (VA `0xfffffe0038070000`); the run faulted on `0x211e49008`.

Both are **below RAM base** (`0x10000000000`) by ~0xfdee_xxxx_xxxx — i.e. they are **not
in normal DRAM and not in any reserved DRAM carveout** on this map. They sit in the low
IPA space (~`0x2.11 GB`), below even the lowest Device-nGnRE MMIO block (`0x5a0000000`),
in a hole m1n1's stage-2 leaves **unmapped** — which is exactly why the probe reported
`HV: Unmapped IPA 0x211e49008`. They span only `0x211050000 .. 0x211e49008` ≈ 14.6 MiB
apart but the two pages are non-contiguous, so no single contiguous IPA slab covers them.

Consequence for R1: the "safe real-DRAM range" is a pool of **host-physical DRAM pages**
we allocate; R1 then maps those pages into stage-2 **at the monitor's fixed low IPAs**
(`0x211050000`, `0x211e40000`, and any further ones the RMW walk reaches). The IPAs
themselves are not inside the DRAM pool — the pool only supplies the backing frames,
the way `--back-page 0x211050000:16` already backed region A with zeroed host scratch.
The difference in R1 is that the frames come from real, non-reserved DRAM (and may be
seeded with real content) instead of the 256 KiB zeroed diagnostic scratch.

## Recommended safe real-DRAM range

```
Primary:   0x10100000000 .. 0x10140000000   (host PA, 1 GiB, 16 KiB-aligned)
```

Reasoning:

- Lies wholly inside the OWN pool `[0x1001d82c000, 0x103de7a4000)`.
- Clearance below: `0xe27d4000` (~3.63 GiB) above the guest-window end `0x1001d82c000`
  — no chance of touching the boot object, its heap, the relocated boot data, or the
  probe scratch.
- Clearance above: `0x29e7a4000` (~10.5 GiB) below TZ0 start `0x103de7a4000` — far from
  every secure carveout (TZ0/TZ2), the framebuffer, and dram end.
- Does not overlap any Device-nGnRE MMIO block (all below RAM base) or the monitor
  structure IPAs (also below RAM base).
- 1 GiB is generous: region A needed only 16 pages (256 KiB); machine-wide page-ownership
  metadata for 16 GiB at 16 KiB granularity is on the order of low tens of MiB. 1 GiB
  leaves ample headroom for additional structures discovered during the RMW walk without
  a second allocation.

If a smaller footprint is preferred, `0x10100000000 .. 0x10108000000` (128 MiB) sits in
the same gap with the same clearances. Keep the base 2 MiB/16 KiB-aligned so it can host
whatever leaf/page granule the monitor expects.

## Reversibility note (prereq 3, carried into R1)

`scripts/chainload_preserve_boot.py` reloads from a fresh baseline and preserves the
boot-data spans (RTBuddySeg/SEPFW/preoslog) by copying them alongside the incoming
image and refusing if the staging allocation overlaps those spans. The recommended
pool is ~3.6 GiB clear of the guest window and all boot-data copies, so backing it does
not touch anything that chainload_preserve_boot restores. R1 must still confirm a clean
HV exit and an intact installed boot after the run before considering R2.

## Do-not-touch summary (for the R1 backing allocator)

- Below RAM base entirely: device MMIO + the low IPA hole (incl. the monitor's own
  structure IPAs — those get *mapped*, not carved from the pool).
- `0x10000000000 .. 0x1000e268000` — m1n1 image/heap + RTBuddySeg/SEPFW/preoslog real
  homes + probe scratch.
- `0x10010000000 .. 0x1001d82c000` — isolated guest window / installed boot object copy.
- `0x103de7a4000 .. 0x10400000000` — TZ0, TZ2, SoC carveouts, framebuffer (all above
  top-of-normal-RAM).
- Draw the pool only from `0x1001d82c000 .. 0x103de7a4000`; recommended slice
  `0x10100000000 .. 0x10140000000`.
</content>
</invoke>
