# XNU early physical timer control

Attempt 64 (`27f6291d-4f53-4f87-bac9-82526e87735c`) reached runtime
`0xfffffe002bf923b0`, linked `0xfffffe000bf923b0`, instruction `0xd51be228`
(`msr CNTP_CTL_EL0, x8`). Syndrome `0x6232f904` describes this trapped
system-register write. Both the preceding instruction and captured register
state establish `x8=2`: disable and mask the guest physical timer. FAR belongs
to an earlier memory access and is not meaningful for this trap.

The pinned hypervisor's `src/hv_exc.c` explicitly maps `CNTP_CTL_EL0` to
`CNTP_CTL_EL02` in its architectural ECV timer handling. The native XNU
callback needs the same guest-bank behavior. The host `CNTP_CTL_EL0` bank
must not be used for this operation. The continuation is restricted to the
verified source instruction, runtime location, exact syndrome, and value.
Guest-bank state is saved for verified restoration after guest return and VEL2
deactivation. Cleanup
restores and compares only ENABLE and IMASK (mask 3); ISTATUS is dynamic and
read-only. The trapped architectural instruction advances by four bytes after
the write. The guest EL02 alias is distinct from the physical timer used by
the hypervisor watchdog.

The run captured 9356 events and returned with timer restoration and proxy
health verified. Its stage-2 dockchannel mappings and private panic-carveout
copy repeated successfully. The timer continuation passed exact callback replay, mismatch rejection, and
cleanup tests. The full activated suite passes 388 tests, one skipped. Attempt
65 verified the continuation on hardware; full platform boot is not established.

Attempt 64 transfer archive SHA-256:
`9c9a1dbf69634f421b0b4da3de69a4bf62663ff6d8255e30a869e0cd5cbb63ab`.
The archived report and event journal preserve the original trapped write.


## Hardware validation — attempt 65

Run `fdc44c2b-53dd-40f3-9b5f-4bb9c37de013` performed the guest-bank write and
advanced to the immediately following Apple-specific timer instruction at
`0xfffffe002bf923b4`, ESR `0x62387d1a`. It captured 9357 events in 93.66 seconds,
returned cleanly, and left the proxy alive. Cleanup saved prior raw value 7,
restored writable value 3, read raw value 7 back, and verified control bits 3.
This exercises the dynamic-status masking on hardware. The host timer bank
was not touched by this callback or its cleanup. Existing AGT redirection
restoration also passed. The next Apple-specific timer contract remains under
investigation, with current RAM retained.

Event-journal SHA-256:
`98908b75dbcbca4e1886344554111cb28b6eaaf6d880d58d97c947efe1dca4fa`.
Transfer-archive SHA-256:
`9ef6b852c77bca67f1fb214737d08d48dec857d1e3c8e4d300027c48e88692cc`.
See [the Apple timer evidence](xnu-apple-physical-timer.md) for the next stop.
