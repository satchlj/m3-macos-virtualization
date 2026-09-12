# Project status — 2026-09-11

The active frontier is Phase 5.3: SPTM dynamic-memory services under XNU. The
project is past early XNU entry and platform diagnostics, but is not at a macOS
boot or GPU bring-up milestone.

[Repository home](../README.md) · [Overview](OVERVIEW.md) · [Documentation index](README.md)

This is the latest **recorded** status in this snapshot, not a live hardware
status feed. “Observed” is limited to the pinned experiments described below.
Earlier plans and attempt notes retain their historical context.

## Phase 5 roadmap

| Area | Status | Evidence boundary |
| --- | --- | --- |
| 5.1 Early entry and static metadata | Bounded milestone observed | XNU entry, Mach-O/BootKC metadata, AuxKC absence encoding, and relocation dependencies were crossed on hardware. |
| 5.2 Console, diagnostics, and timers | Bounded bring-up coverage | Early console routing, physical timer handling, panic-log preservation, and required early mappings were exercised. These are compatibility mechanisms, not general peripheral support. |
| 5.3 SPTM dynamic-memory services | Active | Allocation, page selection, selector-1 guarded entry, exact return, and authoritative `XNU_DEFAULT` to `TXM_DEFAULT` and `XNU_PAGE_TABLE` frame-record transitions were observed on hardware. Runtime Stage-1 mutation remains open. |
| 5.4 Core peripherals | Upcoming | AIC, PMGR, and DART bring-up have not been established. |

## Latest verified milestone

Attempt 104 completed a bounded survey of the pinned XNU `sptm_retype` wrapper
on an M3/J613 and stopped on its fifth observed call:

- the target call requested `XNU_DEFAULT` (`0x0b`) to `XNU_PAGE_TABLE`
  (`0x14`) with flags `3` for physical frame `0x100187f4000`;
- selector-1 `genter`, native `gexit`, the post-service helper, authenticated
  wrapper return, and caller return all passed source/live-byte and translation
  gates;
- the authoritative record at `0xfffffdf000029fd0` changed type from `0x0b` to
  `0x14`, while its lock field and both adjacent records remained stable;
- the four preceding calls were `0x0b->0x29`, two `0x0b->0x23` calls, and
  `0x23->0x0b`;
- the five-call survey completed in 44.86 seconds within every bound;
- target return and proxy liveness checks passed.

This verifies a kernel-driven page-table-frame ownership transition, but not the
corresponding Stage-1 descriptor write or linkage into a live hierarchy. See
[the bounded evidence note](launch-prep/xnu-phase53-allocation-retype.md).

## What is established

- A bounded synthetic virtual-EL2 path runs on the physical M3.
- SPTM self-configuration, guarded-world transitions, TXM bootstrap, and XNU
  early execution have been observed through explicit gates.
- Host replay, page-table walkers, trace classifiers, immutable run manifests,
  cleanup checks, and source/live-byte guards reduce ambiguity in hardware runs.
- Firmware-side filtering and batching materially reduce serial round trips.

## What is not established

- General SPTM frame ownership-transfer semantics beyond the observed transactions.
- The runtime Stage-1 descriptor write corresponding to the verified page-table retype.
- A complete XNU platform bring-up or macOS boot.
- AIC, PMGR, DART, AGX firmware, graphics, multicore, sleep/wake, or production
  safety.
- Portability beyond the pinned revisions and observed M3/J613 environment.

Hardware evidence is retained outside Git. Small fixtures are synthetic or
redacted unless a document explicitly says otherwise.

## Follow the evidence

| Recorded stage | Supporting notes |
| --- | --- |
| Initial virtual-EL2 smoke and SPTM self-configuration | [Smoke result](vel2-hardware-smoke.md) · [Self-configuration result](sptm-self-configuration-result.md) |
| Guarded-memory experiments | [Stage 0 historical index](real-memory-stage0/README.md) |
| TXM launch and early XNU execution | [Kernel/platform evidence index](launch-prep/README.md) |
| Current allocation/retype milestone | [Attempts 103–104](launch-prep/xnu-phase53-allocation-retype.md) |

The next unestablished milestone is a verified runtime Stage-1 descriptor change
associated with the page-table retype. Later platform and GPU work should not be
reported as completed on the basis of the existing frame-record transition.

Documentation and code-organization tasks are tracked separately in the
[maintenance review](CODE-REVIEW.md). They do not advance hardware milestones.
