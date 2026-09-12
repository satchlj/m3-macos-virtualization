# Stage 0 and guarded-memory research notes

[Documentation index](../README.md) · [Current status](../STATUS.md)

This directory records the earlier memory/guarded-execution research arc. Its
plans and attempt-specific open questions are historical. The project has since
recorded TXM/XNU execution and Phase 5.3 allocation/retype results; see
[the current status](../STATUS.md) and [later kernel notes](../launch-prep/README.md).

The earlier index described attempt 17 as the frontier. That is superseded: this
directory also contains attempts 18–24. Those notes preserve confirmations,
negative results, and revisions to the initial hypotheses.

## Complete note index

Titles describe each note’s original scope. Proposed next steps, addresses, and
commands inside a note belong to its recorded attempt and are not current setup
instructions. Use the evidence labels in [SAFETY.md](../SAFETY.md).

| Note | Original subject |
| --- | --- |
| [STAGE0-SUMMARY.md](STAGE0-SUMMARY.md) | Real-memory phase — Stage 0 summary (2026-09-10) |
| [attempt-17-divert-analysis.md](attempt-17-divert-analysis.md) | attempt-17 divert analysis — the post-genter spin at 0x100033f1a00 (2026-09-10) |
| [attempt-17-real-genter.md](attempt-17-real-genter.md) | attempt-17 — first real guarded execution (native genter worked) (2026-09-10) |
| [attempt-18-divert-confirmed.md](attempt-18-divert-confirmed.md) | attempt-18 — divert confirmed: guarded instruction-abort on unset guarded vectors (2026-09-10) |
| [attempt-19-trigger-syndrome.md](attempt-19-trigger-syndrome.md) | attempt-19 — the divert trigger: SPTM's first guarded msr is undefined (2026-09-10) |
| [attempt-20-guarded-roundtrip.md](attempt-20-guarded-roundtrip.md) | attempt-20 — GL2 shadow works: first complete guarded round-trip (2026-09-10) |
| [attempt-23-first-contact.md](attempt-23-first-contact.md) | attempt-23 — first contact: a real guarded service call into SPTM (2026-09-10) |
| [attempt-24-multi-call.md](attempt-24-multi-call.md) | attempt-24 — multi-call driver works; idle rejects general SPTM calls (2026-09-10) |
| [call-abi.md](call-abi.md) | SPTM guarded-call ABI — dispatch map (2026-09-10, sub-step 1) |
| [first-contact-build-spec.md](first-contact-build-spec.md) | First-contact genter driver — finalized build spec (2026-09-10) |
| [first-contact-spec.md](first-contact-spec.md) | First real genter — contact spec (2026-09-10, final prep) |
| [genter-driver-design.md](genter-driver-design.md) | genter driver — design (2026-09-10, sub-step 3) |
| [guarded-percpu-init.md](guarded-percpu-init.md) | SPTM guarded per-CPU init sequence (from attempt-20, 2026-09-10) |
| [multi-call-reversibility.md](multi-call-reversibility.md) | Multi-call reversibility — safety plan for the first mutating guarded call (2026-09-10) |
| [multi-call-runbook.md](multi-call-runbook.md) | Multi-call run — ready-to-go runbook (2026-09-10) |
| [mutation-and-extent.md](mutation-and-extent.md) | Stage-0 — what the monitor mutates, and how it learns physical extent |
| [real-enable-mechanism.md](real-enable-mechanism.md) | Real SPRR/GXF enable — mechanism resolution (2026-09-10) |
| [region-map.md](region-map.md) | Stage-0 region map — monitor context pointer table (2026-09-10) |
| [safe-dram-range.md](safe-dram-range.md) | Safe real-DRAM range — Stage 0 (real-memory phase) |
| [service-selector-map.md](service-selector-map.md) | SPTM guarded-call service = a GXF world-transition state machine (2026-09-10, complete) |
| [sprr-permission-model.md](sprr-permission-model.md) | Stage-0 offline SPRR permission model |
| [wake-path.md](wake-path.md) | Wake-path analysis — how SPTM leaves the WFE idle (2026-09-10) |
