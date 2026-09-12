# First XNU peripheral mapping

After the absent-AuxKC fix, attempt 59b stopped on the first observed dockchannel
UART access: runtime PC `0xfffffe002b6b6fac`, instruction `ldr w22, [x0]`,
ESR `0x93960006`, FAR `0xfffffe003a010000`. The saved guest page tables map
that VA to physical `0x2e410c000`. The archived device tree identifies this as
`/arm-io/dockchannel-uart` register range 1, length `0x1000`; the dockchannel
model identifies it as the interrupt mask/flag bank.

`--xnu-dockchannel-uart-mmio` requires native XNU continuation and stage-2
handling. It verifies the pinned instruction and device-tree identity/range,
and only activates on the exact observed PC, ESR, FAR, and a translated address
inside that 4 KiB device range. It installs one identity mapping using the
existing hypervisor memory attributes, preserving the guest's device type,
and completes the stage-2 TLB invalidation sequence before retrying.

The hardware mapping granule is 16 KiB. The mapped span is
`0x2e410c000..0x2e4110000`: the named 4 KiB register bank plus 12 KiB of the
enclosing PMGR window with no other named child register range. This is real
MMIO passthrough, including subsequent writes; it is not emulation of the
peripheral. The FIFO bank, parent PMGR region, and other arm-io ranges are not
mapped by this option. The USB proxy uses separate hardware.

Matching and nonmatching faults are replayed through the production callback,
including map ordering and the stage-2 TLB barrier. The full activated suite
passes 376 tests, with one skipped. Hardware validation is recorded below.

Attempt 60 (`64328546-78cf-4f93-b3f5-c2a1fe0b87f8`) activated the exact
IRQ-page mapping, retried the read successfully, and advanced to a different
MMIO write: `PC=0xfffffe002b6b740c`, `ESR=0x93810047`,
`FAR=0xfffffe003a000008`, write value `0x83d600`. That second access remains
stopped for its own device/range diagnosis. The full archive has 2248 events
and no panic console. The guest returned, the timer guest bank was restored
and verified, and the proxy remained responsive.

## Second observed mapping trigger

The same explicit option now uses a two-entry catalog. The second entry
verifies `str w1, [x0]` at runtime `0xfffffe002b6b740c`, ESR `0x93810047`,
and FAR `0xfffffe003a000008`, translating inside the first page of device-tree
reg0. It maps `0x2e4128000..0x2e412c000`, wholly inside reg0's declared
64 KiB span. Subsequent reg0 pages remain unmapped. The observed offset `+8`
is unnamed in the pinned m1n1 model, so its hardware semantics remain unknown;
this is a native XNU config-window write, not a modeled register operation.
Both catalog entries retain exact source and fault checks plus the shared
stage-2 TLB invalidation. Production replay covers both and rejects an address
in the next reg0 page.

Attempt 61 (`35db75f5-9aa0-4de6-b5d0-f4d18d7ff8ab`) activated both
entries and completed the config-window write. It then stopped on another read
at the same generic read instruction, now ESR `0x93960007` and
FAR `0xfffffe003a00c01c`. That address remains outside the admitted pages.
The guest returned cleanly, timer restoration was verified, and the proxy
remained alive; the full 2249-event archive contains no panic console.

## Third observed mapping trigger

Attempt 61's new read translates to physical `0x2e413401c`, reg0 offset
`0xc01c`. The third catalog entry admits only that exact translated address,
PC `0xfffffe002b6b6fac`, ESR `0x93960007`, and FAR `0xfffffe003a00c01c`.
It maps only `0x2e4134000..0x2e4138000`, the last 16 KiB of the declared
reg0 range. The two middle reg0 pages remain excluded.

The pinned m1n1 layout identifies this as Data bank 1B. Interpreting offset
`0x1c` as RX_8 uses the repeated data-bank layout; m1n1's UART helper directly
instantiates bank 1A instead. The report marks this register identification as
an inference. Reads may consume receive data, and the full mapped page exposes
its other data registers. All three exact triggers use the same mapping and
TLB-coherence path; replay rejects crossed ESR/FAR tuples at the shared read PC.

Attempt 62 (`2c2a3857-b3ca-4d85-88bc-8a9fe1b17960`) successfully
activated all three mappings and progressed to a new stop at
`0xfffffe002bf3f3f4`. The finalized archive contains 4131 events and no
SPTM character-console output. The guest returned cleanly, timer restoration
was verified, and the proxy remained alive. This establishes progress through
the three observed device accesses, not complete UART or macOS initialization.
The full activated suite passes 377 tests with one skipped.

The attempt-62 stop is now classified separately from UART MMIO. Its
`ldr w9, [x0]` has ESR `0x93890006`, FAR `0xfffffe003a014000`, and
saved-table translation to `0x103e6c28000`. Archived device trees identify that
physical base as carveout-memory-map region-id-98, size `0x188000`, matching
the embedded panic-log size. The surrounding startup code looks up PRAM and
checks panic-buffer magic values. This is a preserved platform-memory read,
not another dockchannel register. The probe deliberately has not backed or
passed through that firmware carveout. Its next investigation must preserve
existing contents; ordinary zero-backed guest-RAM handling is inappropriate.
