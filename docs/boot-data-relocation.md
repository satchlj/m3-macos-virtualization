# Boot-data relocation experiment

The resumed short capture `2914d855-539f-4f32-853f-6ec79cc77d18`
preserved both ADTs. Its `RTBuddySeg` starts at `0x10002378000`, matching
this boot's unknown `[AFK` loader payload. RTBuddySeg, SEPFW and preoslog
remain outside the probe's guest RAM. The earlier fault used the analogous
loader address from the previous boot; confirmation against the new long
control is pending.

`--relocate-boot-data` is an opt-in bounded experiment. It copies these three
named memory-map inputs from declared host RAM into reserved guest RAM before
the scratch area. Overlapping page ranges are merged to preserve aliasing.
The exact copied bytes are captured in the run bundle. The selected memory-map
addresses and fully contained firmware segment physical/remap aliases move
together; IOVA values remain unchanged. Other firmware and device ranges are
not copied or mapped. Partial overlaps, malformed metadata, external remaps,
out-of-RAM reads and copies above 32 MiB are rejected.

This does not execute firmware, grant device MMIO, remove monitor checks or
claim complete guest isolation. It tests whether stale retained boot inputs
cause the observed metadata-address wrap. Native runtime code is unchanged.
Synthetic tests cover overlap, bounds, real ADT serialization, pointer aliases
and rejection without partial tree mutation. Hardware validation is pending.

The resumed 6.5M control reproduced ESR `0x96000005` at the same faulting
PC. Substituting its `RTBuddySeg` address into the prior wrapped-offset
calculation exactly produces FAR `0xfffffe10091ecde2`.

A first relocation attempt lost USB during a host-memory read before guest
execution. The target returned to the installed baseline. Inspection found
that the standard RAM chainloader copies SEPFW/preoslog but leaves RTBuddySeg
and its firmware-log aliases at their original addresses, now overlapping
the incoming runtime. The precise cause of the reset is not established.

`scripts/chainload_preserve_boot.py` stages all three boot inputs and their
contained aliases before RAM reload. It uses the public upstream reload stub,
preserves copied bytes in a new capture directory, and requires the original
`[AFK` marker. Use only on a fresh installed baseline, never a post-HV runtime.
It does not change the installed boot object. The probe now bounds each
boot-data USB read to 64 KiB. Hardware validation remains pending.


The preserving loader has now passed on hardware, followed by immutable image
verification, transition smoke and 64-addition batching. Short attempt
`495f989a-c9e0-445f-9209-85c0552e9370` stopped at its 4096-event budget and
returned to the proxy. All 6,356,992 boot-input bytes matched the loader's
staged capture exactly, including `[AFK`. The longer correction run is pending.
The expanded offline suite passes 204 tests.
