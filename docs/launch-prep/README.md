# Kernel and platform bring-up notes

This directory records the hardware path from SPTM/TXM launch through early XNU
platform initialization. It is supporting evidence, not a linear runbook. For the
current frontier and limitations, read [project status](../STATUS.md).

## Milestone chain

1. SPTM constructed the guarded launch context and entered TXM.
2. TXM service returns reached the native `gexit` boundary.
3. An exact PSTATE correction allowed XNU to retire instructions at physical EL1.
4. Bounded compatibility handlers crossed early system-register, timer, diagnostic
   carveout, peripheral-mapping, and temporary PPERM operations.
5. XNU entered the TXM command path and then completed a Phase 5.3
   allocation/retype guarded round trip.

## Key evidence notes

- [TXM launch correction](world-switch-is-the-launch.md)
- [First TXM SVC](txm-first-svc-2026-09-11.md)
- [XNU launch mode](xnu-gexit-mode-audit.md)
- [XNU entry prefix](xnu-entry-prefix.md)
- [Physical timer control](xnu-physical-timer.md)
- [Panic-log carveout](xnu-panic-carveout.md)
- [Temporary permission window](xnu-pperm-window.md)
- [TXM context-entry gate](xnu-txm-context-entry-one-step.md)
- [Firmware TPIDR fast shadow](xnu-tpidr-gl2-fast-shadow.md)

Other files capture narrower hypotheses, negative results, and corrections. Dated
notes may use attempt-specific addresses and are valid only for the pinned payload
identity stated in that note. They do not establish portability or a macOS boot.
