# Offline guest debug model — 2026-09-09

The cross-machine pause stopped at a guest MDSCR_EL1 read. The Python SPTM probe
now handles that access through a separate guest debug model. The retained
hardware checkpoint is unchanged: this change has only been tested offline.

Follow-up: [translation and exception validation](offline-translation-validation.md)
extends the virtual endpoint to synthetic guest RAM and translation banks. The
current suite has 134 passing tests.

## Supported contract

`scripts/guest_debug.py` defines a deliberately disabled-debug guest profile.
MDSCR reads return zero and zero writes are accepted. Every nonzero write stops
with `unsupported-guest-debug-control`; it does not silently accept requests for
single stepping, breakpoints, or other unimplemented debug behavior. Zero is a
chosen initial guest state, not a claim about the M3's architectural reset value.

The existing OSLAR zero-write handler is part of this model too. It records an
observed guest unlock; reads and nonzero writes stop. This is not a complete
OS-lock model. Guest state is created afresh for each probe.

The model has no physical-register or proxy interface. The exception callback
writes only the destination guest register for a read (discarding XZR), advances
PC by four, re-arms the host's saved single-step flag, and serializes the reply.
Guest writes cannot change physical MDSCR/MDCR or the host lock. The probe's
existing physical tracing setup and cleanup remain separate from these accesses.

## Public-source basis

The pinned public m1n1 implementation shadows MDSCR in per-CPU guest storage
because the physical register is needed for hypervisor breakpoints and stepping:
[hv_exc.c at 1c98fd0](https://github.com/AsahiLinux/m1n1/blob/1c98fd09817cede0043d25c95fb540dbd683ef18/src/hv_exc.c#L303).
The experimental virtual EL2 path forwards the unhandled trap to the Python probe,
which previously had no corresponding guest shadow handler.

[Arm's self-hosted debug guide, sections 6.4 and 7](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/Arm%20V8A%20self-hosted%20debug.pdf?revision=f7748055-6083-497c-ac7a-1752cb6496fa)
describes software-step enablement and debug exception controls. These controls
affect execution, so accepting arbitrary register values without implementing
their effects would be misleading. The narrow zero-only policy is our research
probe restriction, not an architectural restriction on MDSCR.

## Virtual exception endpoint

`scripts/replay_debug_probe.py` loads the actual nested `stopped` callback from
the probe's AST, preserving its catches, budget enforcement and final reply.
It does not call `main` or initialize a target. Its in-memory transport uses the
real upstream `ExcInfo` serializer; attempted ProxyUtils hardware accesses fail.
This is callback/transport-contract testing, not CPU or USB emulation.

The default input is the checksum-verified retained timer trace. Exactly two
debug exits are replayed: OSLAR unlock at event 2 and MDSCR read at event 392.
The other 391 events are explicitly not replayed. The latter read returns zero
in X12 and resumes at the next instruction, but no next instruction is executed.

```sh
source setup/activate.sh
python -m unittest discover -s tests -v
python scripts/replay_debug_probe.py --report local/reports/debug-replay.json
```

Fifteen new tests cover the observed exit, all 32 register encodings for reads
and zero writes, rejection of every nonzero bit, per-probe state, old OSLAR
behavior, unknown accesses, budget termination, and a failed context write that
must still send exactly one EXIT_GUEST reply. This initial follow-up brought the
suite to 77 passing tests; see the linked follow-up for the current 134-test suite.

## Further target-free work

- The linked follow-up implements fake guest RAM/register banks, translation
  checks and exception-transition tests. It preserves unsupported boundaries.
- Build differential tests against pinned public emulator semantics for each
  narrowly implemented register or page-table feature.

No complete virtual M3 target has been established by this work. SPRR permission
activation, GXF transitions, live translation changes, and macOS guest boot
still require additional implementation and target validation. Do not remove
those stop boundaries on the strength of this replay.

When hardware is available, follow the fresh-baseline and image-verification
procedure in the pause checkpoint. This change is Python-only; native patches
and build hashes are unchanged. The next bounded probe can test whether the new
MDSCR response is sufficient to reach the next monitor operation.

## TDCC follow-up after the Neo hardware trace

The 395-event Neo trace ended at an MDSCR write of `0x1000`. The model now accepts zero or TDCC-only (`1 << 12`) and returns the shadow on reads. SS/KDE/MDE and all other bits remain rejected. DCC register accesses remain unsupported stops, not emulated channel activity or virtual exception delivery. This narrow contract does not enable EL0 workloads.

[QEMU's debug access implementation](https://raw.githubusercontent.com/qemu/qemu/master/target/arm/debug_helper.c) extracts MDSCR bit 12 as TDCC and applies its trap to EL0 DCC accesses. The pinned m1n1 guest MDSCR shadow remains the precedent for separating it from physical stepping. Our probe keeps its physical debug trapping enabled and never copies this guest shadow into the physical register.

The exact observed write now replays successfully, readback returns `0x1000`, a zero write clears it, and a subsequent DCC access still stops. All 166 tests pass. This supersedes the original zero-only restriction above.
