# Documentation index

[Repository home](../README.md) · [Contributing](../CONTRIBUTING.md)

## Choose a reading path

| Purpose | Suggested route |
| --- | --- |
| First visit | [Overview and glossary](OVERVIEW.md) → [Current status](STATUS.md) |
| Evaluate the latest result | [Status](STATUS.md) → [Leaf-binding evidence](launch-prep/xnu-phase53-leaf-page-bind.md) → [Evidence labels](SAFETY.md) |
| Explore or contribute code | [Script map](../scripts/README.md) → [Test guide](../tests/README.md) → [Maintenance review](CODE-REVIEW.md) |
| Set up sources | [Setup guide](../setup/README.md) → [Test prerequisites](../tests/README.md) |
| Follow earlier research | [Stage 0 index](real-memory-stage0/README.md) → [Kernel/platform index](launch-prep/README.md) |

## How to interpret these notes

[STATUS.md](STATUS.md) is the single current milestone summary. Historical notes
preserve failed hypotheses, earlier frontiers, attempt-specific commands, and
corrections. They are supporting evidence, not current installation instructions.
A design or proposed experiment is not a verified result. When a historical note
conflicts with the status summary, follow the latter and its linked evidence.

The [artifact policy](artifact-storage.md) explains which raw evidence and inputs
are excluded from a fresh clone. Reading a result note is not the same as
independently replaying its retained evidence.

## Orientation and project policies

- [Project overview](OVERVIEW.md)
- [Project status — 2026-09-11](STATUS.md)
- [Safety and evidence model](SAFETY.md)
- [Code organization and maintenance review](CODE-REVIEW.md)
- [Local artifact storage](artifact-storage.md)
- [Public source release review — 2026-09-11](PUBLIC-RELEASE-REVIEW.md)

## Host analysis and evidence management

- [Experiment automation foundation](experiment-automation.md)
- [Offline guest debug model — 2026-09-09](offline-debug-model.md)
- [Offline translation and exception validation — 2026-09-09](offline-translation-validation.md)
- [Trace disassembly annotation](trace-disassembly.md)
- [Non-step event summary of a finalized bundle](trace-events-summary.md)
- [XNU/SPTM map-progress classifier](xnu-map-progress-classifier.md)
- [Verified pipeline import](pipeline-import.md)
- [Fetching a pipeline attempt from the USB host](pipeline-fetch.md)
- [Stop at the first recorded guest vector visit](guest-exception-stop.md)

## Research infrastructure and experimental design

- [Local loader patch](loader-patch.md)
- [Automated probe pipeline](probe-pipeline.md)
- [Accelerated fresh-boot gate receipt](fresh-gate-receipt.md)
- [Bounded native step capture](native-step-batching.md)
- [Free-run watchdog (2026-09-11)](free-run-watchdog.md)
- [Guarded continuation protocol](guarded-pause.md)
- [Guarded target reboot](reboot-helper-design.md)
- [Boot-data relocation experiment](boot-data-relocation.md)
- [Bounded live translation-root switches](live-ttbr-switches.md)
- [SPRR-aware leaf permission decoding](sprr-leaf-permissions.md)
- [Exact SPRR permission representability](sprr-permission-audit.md)
- [Observation-only SPRR staging](sprr-observation.md)

## Historical investigations and results

- [First proxy findings — 2026-09-09](first-proxy-findings.md)
- [Guest boot first: evidence and next experiment](guest-experiment.md)
- [Monitor bootstrap investigation — 2026-09-09](monitor-bootstrap-requirements.md)
- [MMU and SPTM progress — 2026-09-09](mmu-sptm-progress.md)
- [Observation-grade virtual guarded world](virtual-guarded-world.md)
- [Virtual EL2 hardware smoke — 2026-09-09](vel2-hardware-smoke.md)
- [SPTM self-configuration under observation — result (2026-09-10)](sptm-self-configuration-result.md)
- [What the observation-only SPRR run showed](sprr-observation-findings.md)
- [Real-memory phase — plan (drafted 2026-09-10)](real-memory-phase-plan.md)
- [Upstream reuse audit — September 9, 2026](upstream-reuse-2026-09-09.md)
- [Speed retrospective — how to do the same work faster](speed-retrospective.md)

## Complete evidence directories

- [Stage 0 and guarded-memory notes](real-memory-stage0/README.md): all plans,
  observations, corrections, and attempts in that directory.
- [Kernel and platform notes](launch-prep/README.md): all launch, diagnostic,
  compatibility, and allocation/retype notes.

## Machine-readable reference files

- [Upstream audit snapshot](upstream-audit-2026-09-09.json), interpreted by the
  [upstream reuse review](upstream-reuse-2026-09-09.md).
- [Python dependency license inventory](python-dependency-licenses.json),
  interpreted by the [public release review](PUBLIC-RELEASE-REVIEW.md).

The root [license guide](../LICENSES.md) and [third-party notices](../THIRD_PARTY_NOTICES.md)
apply to the source snapshot. The documentation checker verifies that these
indexes reach every Markdown page and that every Python script appears in the
script map.
