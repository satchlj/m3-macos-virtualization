# Project status — 2026-09-12

The bounded Phase 5.3 objective is complete and Phase 5.4 AIC observation is the
active frontier. The project is past early XNU entry and platform diagnostics,
but is not at a macOS boot or GPU bring-up milestone.

[Repository home](../README.md) · [Overview](OVERVIEW.md) · [Documentation index](README.md)

This is the latest **recorded** status in this snapshot, not a live hardware
status feed. “Observed” is limited to the pinned experiments described below.
Earlier plans and attempt notes retain their historical context.

## Phase 5 roadmap

| Area | Status | Evidence boundary |
| --- | --- | --- |
| 5.1 Early entry and static metadata | Bounded milestone observed | XNU entry, Mach-O/BootKC metadata, AuxKC absence encoding, and relocation dependencies were crossed on hardware. |
| 5.2 Console, diagnostics, and timers | Bounded bring-up coverage | Early console routing, physical timer handling, panic-log preservation, and required early mappings were exercised. These are compatibility mechanisms, not general peripheral support. |
| 5.3 SPTM dynamic-memory services | Bounded objective complete | One allocation/ownership chain, selector-3 L3 table installation, and selector-2 leaf mutation were observed with exact gates. General SPTM compatibility remains unestablished. |
| 5.4 Core peripherals | Active frontier | AIC initialization is next; PMGR and DART bring-up remain unestablished. |

## Latest verified milestone

Attempt 119 (`def50c86-5500-41b0-8d3d-517fa3f142c7`) completed the bounded
Phase 5.3 chain in 44.50 seconds. Root `0x10015060000` and VA
`0xfffffe17ec00c000` independently selected L3 table PA `0x100187f0000` and
slot `0x100187f0018`. The zero table changed only there, to descriptor
`0x4600100187f4683`, mapping owned PA `0x100187f4000`. Selector-3 and selector-2
services returned status zero; L2, ownership, FTE transition, authenticated
return, cleanup, and proxy-health gates passed.

This establishes one bounded dynamic Stage-1 mutation chain, not general SPTM
semantics or a macOS boot. The raw report, event journal, and archive remain
outside Git; their hashes and exact evidence boundary are recorded in the
[leaf-binding note](launch-prep/xnu-phase53-leaf-page-bind.md).

Attempt 147 separately validated the corrected three-site retype-survey HVC
accelerator. Fourteen calls passed the pointer-authenticated helper-return,
frame/FTE, exact-ERET, and GL1 counter gates; thirteen used the seven-site base
sequence and one used the complete four-site nested sequence. The same run
re-established descriptor and leaf completion, completed 20 exact PPERM windows
(17 memcpy and three atomic), and returned cleanly at the 90.29-second watchdog
boundary. No AIC access was observed, mapped, read, or written. This improves the
feedback path but does not widen the Phase 5.3 evidence claim. See the
[allocation/retype note](launch-prep/xnu-phase53-allocation-retype.md#corrected-accelerator--attempt-147).

## What is established

- A bounded synthetic virtual-EL2 path runs on the physical M3.
- SPTM self-configuration, guarded-world transitions, TXM bootstrap, and XNU
  early execution have been observed through explicit gates.
- Host replay, page-table walkers, trace classifiers, immutable run manifests,
  cleanup checks, and source/live-byte guards reduce ambiguity in hardware runs.
- Firmware-side filtering and batching materially reduce serial round trips.

## What is not established

- General SPTM frame ownership-transfer semantics beyond the observed transactions.
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
| Completed bounded Phase 5.3 chain | [Attempts 111–119](launch-prep/xnu-phase53-leaf-page-bind.md) |

The next frontier is a bounded, source/live-verified AIC initialization observation. Later PMGR, DART, GPU, and platform work should not be reported as completed from the Phase 5.3 result.

Documentation and code-organization tasks are tracked separately in the
[maintenance review](CODE-REVIEW.md). They do not advance hardware milestones.
