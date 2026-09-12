# Documentation index

The notes retain failed hypotheses and evidence boundaries because those are
important in low-level bring-up. This index is the shortest route through them.

## Start here

1. [Current status](STATUS.md)
2. [Safety and evidence model](SAFETY.md)
3. [Virtual EL2 architecture](virtual-guarded-world.md)
4. [SPTM self-configuration result](sptm-self-configuration-result.md)
5. [Real-memory phase plan](real-memory-phase-plan.md)
6. [Kernel launch and XNU notes](launch-prep/README.md)
7. [Phase 5.3 allocation/retype evidence](launch-prep/xnu-phase53-allocation-retype.md)
8. [Speed retrospective](speed-retrospective.md)

## Reproducibility and tooling

- [Experiment automation](experiment-automation.md)
- [Automated probe pipeline](probe-pipeline.md)
- [Accelerated fresh-boot gate receipts](fresh-gate-receipt.md)
- [Native step batching](native-step-batching.md)
- [Free-run watchdog](free-run-watchdog.md)
- [Offline debug/replay model](offline-debug-model.md)
- [Offline translation validation](offline-translation-validation.md)
- [Trace disassembly](trace-disassembly.md)
- [Artifact policy](artifact-storage.md)

## Architecture and permissions

- [MMU and SPTM progress](mmu-sptm-progress.md)
- [SPRR permission audit](sprr-permission-audit.md)
- [SPRR leaf decoding](sprr-leaf-permissions.md)
- [Live translation-root switches](live-ttbr-switches.md)
- [Boot-data relocation](boot-data-relocation.md)
- [Stage 0 evidence index](real-memory-stage0/README.md)

The dated per-attempt notes under `launch-prep/` and `real-memory-stage0/` are
supporting evidence, not current instructions. Where an older note conflicts with
`STATUS.md`, the status document wins.
