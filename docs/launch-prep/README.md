# Kernel and platform research notes

[Documentation index](../README.md) · [Current status](../STATUS.md)

This directory records progress from monitor launch through early kernel and
platform diagnostics. The latest recorded milestone is the
[completed bounded Phase 5.3 leaf binding](xnu-phase53-leaf-page-bind.md). Read
[the current status](../STATUS.md) for what that establishes and what remains open.

The earlier plans, blocked attempts, and corrections are retained as evidence.
This is not a linear runbook or a claim of a successful macOS boot.

## Complete note index

Titles describe each note’s original scope. Proposed next steps, addresses, and
commands inside a note belong to its recorded attempt and are not current setup
instructions. Use the evidence labels in [SAFETY.md](../SAFETY.md).

| Note | Original subject |
| --- | --- |
| [attempt-25-launch-blocked.md](attempt-25-launch-blocked.md) | attempt-25 — ENTER_GUEST panics from idle: SPTM never reaches launch-ready (2026-09-10) |
| [attempt-27-plan.md](attempt-27-plan.md) | attempt-27 — clean real-guarded boot with the full region set |
| [attempt-44b-breakpoint-panic.md](attempt-44b-breakpoint-panic.md) | Attempt 44b: VBAR worked; the TXM breakpoint caused the panic |
| [harness-inventory.md](harness-inventory.md) | Launch harness — what already exists (2026-09-10) |
| [launch-clues.md](launch-clues.md) | Current handoff clues (attempts 48–49, 2026-09-11) |
| [launch-requirements.md](launch-requirements.md) | SPTM XNU-launch requirements (decoded 2026-09-10) |
| [panic-root-cause-slide.md](panic-root-cause-slide.md) | Boot panic root cause: SPTM can't look up the 'slide' image region (2026-09-10) |
| [post-txm-svc-path.md](post-txm-svc-path.md) | Post-TXM return and the XNU GEXIT handoff |
| [sptm-panics-not-idles.md](sptm-panics-not-idles.md) | CORRECTION: 0xf8b88 is SPTM's panic halt, not a WFE idle (2026-09-10) |
| [txm-first-svc-2026-09-11.md](txm-first-svc-2026-09-11.md) | TXM's first post-relocation operation is an SVC |
| [txm-svc-return-catalog.md](txm-svc-return-catalog.md) | Pinned TXM SVC return catalog |
| [vbar-gl1-redirect-audit.md](vbar-gl1-redirect-audit.md) | VBAR_GL1 redirect audit (attempts 18–42) |
| [world-switch-is-the-launch.md](world-switch-is-the-launch.md) | Correction: the first world-switch eret enters TXM (2026-09-11) |
| [xnu-apple-physical-timer.md](xnu-apple-physical-timer.md) | Apple physical-timer frontier after attempt 65 |
| [xnu-dockchannel-mmio.md](xnu-dockchannel-mmio.md) | First XNU peripheral mapping |
| [xnu-entry-prefix.md](xnu-entry-prefix.md) | XNU entry prefix audit, 2026-09-11 |
| [xnu-gexit-mode-audit.md](xnu-gexit-mode-audit.md) | XNU launch state audit, 2026-09-11 |
| [xnu-m3-ahcr-compat.md](xnu-m3-ahcr-compat.md) | XNU M3 AHCR diagnostic compatibility |
| [xnu-panic-carveout.md](xnu-panic-carveout.md) | XNU preserved panic-log memory |
| [xnu-parser-abort-attempt58.md](xnu-parser-abort-attempt58.md) | Attempt 58 XNU parser abort |
| [xnu-phase53-allocation-retype.md](xnu-phase53-allocation-retype.md) | XNU Phase 5.3 allocation and SPTM retype evidence |
| [xnu-phase53-descriptor-bind.md](xnu-phase53-descriptor-bind.md) | Selector-3 L3 table installation evidence |
| [xnu-phase53-leaf-page-bind.md](xnu-phase53-leaf-page-bind.md) | Completed bounded selector-2 leaf binding evidence |
| [xnu-physical-timer.md](xnu-physical-timer.md) | XNU early physical timer control |
| [xnu-pmcr1-bank-collapse.md](xnu-pmcr1-bank-collapse.md) | XNU PMCR1 EL12 bank collapse |
| [xnu-pperm-window.md](xnu-pperm-window.md) | XNU pmap bootstrap permission window |
| [xnu-socd-trace.md](xnu-socd-trace.md) | Private SOC diagnostic trace buffer |
| [xnu-tpidr-gl2-fast-shadow.md](xnu-tpidr-gl2-fast-shadow.md) | Opt-in TPIDR_GL2 firmware fast shadow |
| [xnu-txm-context-entry-one-step.md](xnu-txm-context-entry-one-step.md) | Exact TXM context-entry one-step gate |
