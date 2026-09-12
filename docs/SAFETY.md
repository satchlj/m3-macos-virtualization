# Safety and evidence model

This repository controls an experimental bare-metal runtime. Hardware commands
can reboot a target, replace its RAM-resident m1n1 image, or leave a guest stopped
in a non-resumable state. Nothing here is production-ready.

## Hardware rules

- Use a dedicated test installation and preserve the known-good installed m1n1
  baseline.
- Have exactly one process and one person own the USB proxy.
- Start every mutating attempt from a fresh boot and rerun the complete identity,
  payload, memory-layout, and cleanup gate.
- Never infer a successful guest boot from proxy liveness, a build, serial output,
  an entry event, or synthetic replay.
- Treat every physical address and firmware/register workaround as specific to
  the pinned build and board until independently validated.
- Preserve pre/post state and require exact cleanup readback for temporary timer,
  redirect, permission, and firmware-fast-path state.

The corrected reboot helper clears the PMU panic breadcrumb before requesting a
watchdog reset. A direct `p.reboot()` without that prerequisite previously caused
iBoot to demote the selected boot object. Even the corrected helper can boot the
default macOS volume instead of m1n1; use it only with explicit target-owner
authorization and local recovery access.

## Evidence labels

- **Hardware verified:** observed in a bounded physical-target run with source or
  byte identity checks and a clean-return record.
- **Replay verified:** real host callback/control code exercised against recorded
  or synthetic events; no CPU or hardware semantics are implied.
- **Source derived:** inferred from pinned public source or payload metadata.
- **Hypothesis:** a proposed mechanism or experiment, not a result.

Large/raw evidence is excluded from Git. A technical note may quote addresses,
hashes, or small decoded structures needed to reproduce a claim, but should not
embed Apple payload bytes or private machine identifiers.
