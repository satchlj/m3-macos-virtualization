# Attempt 58 XNU parser abort

Attempt 58 reached XNU native execution after the bounded AHCR diagnostic NOP
and PMCR1 bank collapse. It then panicked with an early-stack diagnostic at
runtime PC `0xfffffe002bfb4d94`. The instruction is `ldr w8, [x24]` in the
`__TEXT_BOOT_EXEC` Mach-O load-command parser.

The final exception bank records `ESR_EL12=0x96000006`,
`FAR_EL12=0xfffffe00fd91e47f`, `ELR_EL12=0xfffffe002bfb4d94`, and
`SPSR_EL12=0x4013c4`. The saved state at `0xfffffe002c563cb0` confirms x24 is
exactly the FAR value. ESR is a level-2 read translation fault. The parser had
incremented x22 to command index 1 after adding command 0's alleged `cmdsize`
to x24. The resulting x24 is misaligned, which cannot result from a valid
Mach-O command chain.

The read-only saved-state artifact is
`saved-state-diagnostics-va-fffffe002c563cb0.bin`, 1024 bytes, SHA-256
`6e7e27c14e750267670bfbf55bc28b22af5d10dac795d5902f69affe07750483`.
Its metadata records live final EL12 translation controls and two owned-RAM
physical spans. No guest was resumed and no guest memory was written.

A second read captured 512 bytes at x1/x25,
`0xfffffe00288ec000`. Artifact
`macho-header-diagnostics-va-fffffe00288ec000.bin` has SHA-256
`311d5b9dd59fb90afe19f0d31818b9542a71780f55f161b1413cd3b16e05b9e5`.
It is byte-for-byte identical to the pinned kernelcache `__TEXT_EXEC` bytes at
file offset `0x18e8000`. It begins executable instructions, not Mach-O magic.
The parser therefore received `__TEXT_EXEC` as both its primary Mach-O header
argument x0 and its x1 adjustment base, then consumed instruction words as
`ncmds` and `cmdsize`. The captured bytes rule out mutation of that region after
load.

A third read captured the separately loaded runtime image vmin
`0xfffffe0027004000`, corresponding to pinned kernelcache file offset zero.
Artifact `actual-header-diagnostics-va-fffffe0027004000.bin` is 512 bytes with
SHA-256 `a5aca0be383cc3e07057a26cd6bd1cdf0a8ff7afc23a68aaa13cf8c91ee87b10`.
It contains the valid `feedfacf` fileset header, `ncmds=0x16c`, command 0
`LC_UUID` with `cmdsize=0x18`, and command 1 `LC_BUILD_VERSION` with
`cmdsize=0x18`. Only two captured bytes differ from pinned file offset zero,
both consistent with the runtime relocation pass. Thus the image contains a
usable outer Mach-O header while the parser consumes `__TEXT_EXEC` instead.

The failed call is AuxKC initialization, not primary-KC initialization. The call
at linked `0xfffffe000b8074cc` loads x0 and x1 from adjacent globals
`0xfffffe0007d39940` and `0xfffffe0007d39948`, then calls the immediate parser
wrapper at `0xfffffe000b805dbc`. Live read-only capture shows that both globals
contain `0xfffffe00288ec000`. The wrapper passes x1 through unchanged at linked
`0xfffffe000b8062c4` to parser entry `0xfffffe000bfb4cf8`. The nearby call at
`0xfffffe000bf89a78` is not the pointer producer: it copies the literal
`mapping_free_prime` into a 32-byte logging argument block, which is consumed by
the trace call at `0xfffffe000bf89a8c`. That trace call is followed by a
separate no-argument queue-drain call at `0xfffffe000bf89a90`. The exact caller
that supplies the parser values is therefore established independently of that
logging sequence. The parser does not synthesize the bad pointer.

The producer chain is also established. Early XNU code copies the 0x340-byte
SPTM XNU-bootstrap block into persistent state at linked
`0xfffffe000bf91cbc`. At the attempt-55 trap, x21 is
`0xfffffe00071002c0`, proving that this second XNU-entry input is the copy source.
Its live fields at offsets 0x2d8, 0x2e0, and 0x2e8 are already all
`0xfffffe00288ec000`; they are the AuxKC base, Mach-O header, and end fields.
The installed macOS 26.5 SDK header
`/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/platform/sptm/sptm_xnu.h` defines these members in
the 0x340-byte `sptm_bootstrap_args_xnu_t`; compiled layout inspection gives
the same three offsets.
Later code at linked `0xfffffe000b807d28` through `0xfffffe000b807d50` copies
those fields to the parser globals.

Pinned SPTM disassembly shows why the absent AuxKC acquired that address. Its
bootstrap constructor looks up `AuxKC-rw`, `AuxKC-ro`, and `AuxKC-le` and uses
their address values to build the three fields. The harness emits every absent,
zero-size AuxKC memory-map tuple as `(guest_base + shared_offset, 0)`. That
shared offset is also the start of `BootKC-rx`; after SPTM translation it becomes
`0xfffffe00288ec000`. Zero size therefore does not make these address values
inert. The causal requirement is that absent AuxKC input produce zero AuxKC
fields in the XNU bootstrap block. The preserved iBoot device tree represents
absent AuxKC regions with the all-ones address/size sentinel; SPTM recognizes
that sentinel without admitting the region to its ordered range set. The loader
must retain that sentinel instead of replacing it with a shared nonzero
placement. It does not justify changing the primary KC header, parser, or
segment placement.
Attempt 51 already traversed a valid header earlier, so this is a later parser
invocation rather than evidence that the initial BootKC region contract was
wrong. It does not justify changing the parser, BootKC-rx placement, or the
loaded image.

All supplemental reads and their metadata/table pages are archived separately
from the original run as `artifacts/runs/observe-sprr/attempt-58-supplemental.tar.gz`,
11,068 bytes, SHA-256
`e2f52855f60a916c5ef431dc35e9bf87560b44f437425a211adb637ffc1f154b`.
The complete investigation set, including all headers, saved state, bootstrap
inputs, live code, and producer fields, is archived as
`artifacts/runs/observe-sprr/attempt-58-investigation.tar.gz`, 14,133 bytes,
SHA-256
`ae3280d508c54d1a15dd6487b31aba7e553498dc7ea328dab2332112775c6b8c`.

## Hardware validation of absence sentinel

Attempt 59 stopped before guest execution because the extracted map-emission
helper referenced a locally scoped tuple serializer as a global. Passing the
serializer explicitly fixed that host-side error. Attempt 59b
(`d04d6c9b-be76-41ee-8fa9-cbf5288d98c7`) then completed SPTM/TXM launch and
passed the AuxKC parser failure. Its report records the emitted all-ones
AuxKC tuples. A bounded read of the original SPTM bootstrap block at
`0xfffffe0007100598` confirms all 24 bytes are zero: `auxkc_base`, `auxkc_mh`,
and `auxkc_end` are absent as intended.

No panic console was emitted. XNU reached a new hypervisor-side data abort at
`PC=0xfffffe002b6b6fac`, `ESR=0x93960006`, `FAR=0xfffffe003a010000`.
The run returned cleanly, the timer guest bank was restored and verified, and
the proxy remained responsive. This closes the AuxKC input bug; the new access
requires its own mapping diagnosis. Full suite after the correction: 372 tests,
one skipped.
