# Bounded native step capture

`sptm_entry_probe.py --step-batch 64` opts into native capture of ordinary
software-step exceptions after the monitor MMU has passed validation. The
default is zero (the existing host callback path). A matching experimental
runtime must first be built, RAM-loaded and verified. This feature has passed
host tests, arm64 builds on both the coordinator and Neo, and the M3 hardware
checks described below.

The runtime records up to 256 events in caller-owned RAM outside the guest.
Each little-endian 312-byte record contains PC, ESR, FAR, saved PSTATE, 32
register slots and three stack-pointer slots. Only lower-EL AArch64 step
exceptions (EC 0x32) from physical EL1t/EL1h are accepted. The runtime re-arms
single stepping without advancing PC or emulating the guest instruction.
Other exceptions and the first step after a full buffer return to the host.

The host drains and validates the complete batch before processing that
callback, checking the event budget, or acknowledging the buffer. It appends
records in order to the same trace archive used by unbatched runs. Each new
batch is limited by the remaining event budget. The terminal budget callback
is retained as an additional notification, as in existing reports.

Configuration is per CPU and is cleared on virtual-EL2 reset. Proxy commands
0xc13 and 0xc14 configure the buffer and read its count. Capacity zero disables
capture; a nonzero capacity requires active virtual EL2 and an aligned buffer.
The probe currently uses one guest CPU. Read or configuration failures stop
the probe and mark the capture incomplete. Checkpoints use elapsed event
counts so batching cannot skip every checkpoint by crossing a modulo boundary.

This changes host interruption overhead and guest timing. Architectural trace
comparison is required before relying on it; timing equivalence is not claimed.
The first hardware gate is `scripts/step_batch_smoke.py`: run with capacity
zero, eight and 256 on the same new runtime. It executes 64 known additions,
checks every post-instruction PC and x0 value, verifies the terminal HVC, and
requires a clean proxy return. Capacity eight exercises full-buffer handoff;
256 exercises draining a partial batch at a non-step exception. Follow with
a small unbatched/batched SPTM pair, comparing control flow and guest state,
then a longer measured run.
An old runtime does not gain this capability by updating Python alone.

## M3 validation on September 9

After a fresh dedicated-test boot, RAM image verification and the transition
smoke test passed. All three synthetic cases passed: capacity zero, eight and
256. The latter two captured 57 and 64 native events respectively, checking
both full-buffer handoff and partial-buffer drain at HVC.

The 4096-event SPTM pair matched all 4097 control-flow records. The batched run
then matched a subsequent unbatched control **exactly**, including registers,
stack, fault address and saved PSTATE. The initial unbatched run differed in
seven transient register snapshots: the APCTL guest bank and HID16 read
changed after the first monitor attempt. These are retained observations of
state persistence, not an established reset model. The probe now records
initial/final APCTL_EL12 and HID16_EL1 values without changing HID16 itself.

The complete 2,097,153-event control-flow comparison also matched, with no
divergence. The batched attempt took 113.879 seconds including setup and
capture (97.141 seconds inside guest execution/capture), versus 2156.579
seconds for the prior unbatched attempt: **18.9 times faster end to end**.
The long comparison is explicitly control-flow-only, not full-state or
timing equivalence. Both attempts stopped at their budgets with clean proxy
returns; neither reached XNU. Evidence is in
`evidence/2026-09-09/native-batching/`.

The portable native buffer tests cover filtering, ordering, reset and capacity.
Host tests cover malformed reads/counts and draining before the terminal
budget callback. Hardware checks supplement these tests; they do not establish
general monitor virtualization or correctness of future unsupported paths.
