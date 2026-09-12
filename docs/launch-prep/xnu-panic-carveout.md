# XNU preserved panic-log memory

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Attempt 62 stopped at runtime `0xfffffe002bf3f3f4`, `ldr w9, [x0]`, with
ESR `0x93890006` and FAR `0xfffffe003a014000`. Its saved guest tables resolve
that address to physical `0x103e6c28000`. The host and guest device trees bind
that physical range to `/chosen/carveout-memory-map/region-id-98`, size
`0x188000`, matching `embedded-panic-log-size`.

A read-only continuation check verified the current proxy and loaded image.
The first header diagnostic rejected an incorrect root-level device-tree path
before reading the carveout. The corrected diagnostic verified the run and
manifest, immutable loaded image sections, archived and live device-tree
identity, and the exact region tuple before reading 64 bytes.

The captured header is all zero, SHA-256
`f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b`.
Artifacts are under attempt 62 as
`panic-carveout-diagnostics-retry.json` and
`panic-carveout-diagnostics-retry-panic-carveout-header.bin`.
The proxy remained responsive and no guest execution resumed. A zero header
is not evidence that the remaining region is empty.

The continuation design preserves the existing guest IPA and device-tree tuple.
It copies all `0x188000` bytes (98 pages) into a separate aligned private
allocation outside the isolated guest identity-mapped range, verifies source
and destination hashes, then maps the guest's carveout IPA to that private
copy. This keeps SPTM's external-carveout classification and sends subsequent
guest writes to private memory. It does not map writes to the original PRAM.
Retargeting the device-tree tuple into managed guest RAM would change the
address classification and is not justified by the header capture alone.

The full source data need only exist transiently and in the private target
copy; persistent evidence consists of byte counts, identities and hashes,
plus the small header capture. Attempt 63 verified the preserved-copy
continuation on hardware.

The implementation is explicit opt-in via `--xnu-private-panic-carveout`,
requiring native XNU continuation and stage-2 handling. It admits only the
pinned first-read instruction, runtime PC, syndrome, virtual address, and
translated original IPA. Replay verifies all 98 pages target the private
allocation and that stage-2 invalidation follows the map. Mismatches stop.

After a successful guest return, the private backing and stage-2 entries remain
in target RAM with VEL2 deactivated; they are not reused for another guarded
run. The next full reboot resets that lifetime. No original-carveout write is
performed by the copy or mapping path. The full activated suite passes 385
tests, one skipped.

## Hardware result — attempt 63

Run `c584e281-144a-4982-a1cd-4273937b9848` copied and verified all
1,605,632 bytes, mapped all 98 pages at the exact recorded read fault, and
continued execution. Source and destination SHA-256 both were
`887e52bffa1178d099f34189fad2d4c179ec6e5ed34cb27d00cd10732e1e8b92`.
The report verifies the private allocation is outside the original carveout
and guest identity-mapped allocation. No raw full-source artifact was saved.

The 90-second watchdog returned after 9052 events with the proxy alive and
timer state restored. Its `hang` label denotes budget expiry here, not a
proved loop: all 362 selector-2 `MAP_PAGE` calls used distinct virtual
addresses advancing by 16 KiB, from `0xfffffe003a000000` through
`0xfffffe003a5a4000`, with fixed root `0x10015060000` and flags 1.
The actual watchdog event is index 9051 at SPTM PC `0xfffffe00070a452c`.
The older `handoff.last_pc` field is maintained by the handoff observer. It is
updated during bounded handoff steps and terminal native-exception paths, but
not for every serviced callback or watchdog stop, so it must not be used as
the final stop location.

The archive SHA-256 is
`9916764fbaa8f8ce8a357bdaf332f47e4ebe149c8400ffede7e042433f17f4bd`;
the event archive SHA-256 is
`18dd563c3969e5cf9b1f74bea7007d17cf9c80e5a74b8d5551065ea42ab1ba2a`.
The next discriminant is an otherwise unchanged run with a 180-second budget.

The pipeline now reports the final retained `stop_event` and bounded activity
counts independently of `handoff.last_observed_pc`. The legacy `last_pc` alias
is retained with an explicit handoff-observer scope label for compatibility.
Activity counts alone do not establish forward progress; the monotonic mapping
addresses above supply the stronger evidence for this run.


## Repeat continuation — attempt 64

Run `27f6291d-4f53-4f87-bac9-82526e87735c` repeated the private-copy and
mapping successfully with the same source/destination hash. XNU passed the
mapping walk and stopped on a new native exception at `0xfffffe002bf923b0`,
ESR `0x6232f904`, after 87.93 seconds, before the 180-second watchdog limit.
The complete journal contains 9356 events, SHA-256
`7234f06aa1889cd7c31a79c8bf5796dd4eb76684355e487062cced145f0ffed1`.
Guest return, timer restoration, and proxy health are verified. Current target
RAM is retained for classification of this next stop.
