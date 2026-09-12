# Apple physical-timer frontier after attempt 65

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Attempt 65 (`fdc44c2b-53dd-40f3-9b5f-4bb9c37de013`) first serviced the
architectural `CNTP_CTL_EL0` write through the guest `CNTP_CTL_EL02` bank.  The
run then stopped cleanly at runtime PC `0xfffffe002bf923b4` with ESR
`0x62387d1a`.  The pinned kernelcache word at linked PC
`0xfffffe000bf923b4` is `0xd519fd88`, decoded as
`msr S3_1_C15_C13_4, x8`; `x8` is 2, loaded by the preceding
`mov w8, #2`.  These instruction, PC, syndrome, and value facts are directly
established by the pinned payload and attempt-65 report.

The prior architectural timer continuation worked on hardware.  Its cleanup
observed guest `CNTP_CTL_EL02=7`, restored writable bits 1:0 to 3, read back 7,
and verified the masked value.  The run captured 9,357 events, returned from
the guest, and left the proxy alive.  This does not establish behavior for the
new Apple register.

The pinned kernelcache supplies direct evidence for a distinct bank at
`S3_4_C15_C4_3`.  At linked PC `0xfffffe000b831824`, it reads that register
and saves it in a timer-context block beside:

- `S3_4_C15_C4_4`
- `S3_4_C15_C4_1`
- `S3_4_C15_C2_7`

At linked PC `0xfffffe000b835808`, it restores `S3_4_C15_C4_3` from the
corresponding slot beside those same registers.  The kernelcache contains four
writes to `S3_1_C15_C13_4`; each follows an architectural
`CNTP_CTL_EL0=2` write.  This establishes that XNU treats the two timer
families in parallel and preserves a separate `S3_4_C15_C4_3` state.

A recovered, non-primary Apple system-register catalog names
`S3_1_C15_C13_4` as `AGTCNTP_CTL_EL0` and `S3_4_C15_C4_3` as
`AGTCNTP_CTL_EL02`.  Neither the pinned m1n1 source, installed Kernel.framework
headers, pinned SPTM headers, nor Apple's published XNU `proc_reg.h` defines
these names or an EL0-to-EL02 trap rule.  The catalog name is therefore useful
for searching, but is not sufficient provenance for implementation.

The available evidence does **not** yet establish:

- that attempt 65 must be serviced by writing `S3_4_C15_C4_3`;
- which control register causes the EL0 encoding to trap or redirect;
- which bits of the Apple control register are writable or dynamic; or
- that value 2 has architectural `CNTP_CTL`'s disable-and-mask meaning.

An exact architectural compatibility claim requires stronger routing and bit
evidence. A bounded diagnostic hypothesis remains possible: capture the
candidate guest bank read-only, restrict any later experiment to the exact
observed instruction and value, preserve its prior state, and report the
inferred routing explicitly. Successful continuation would establish behavior
on this M3, not a general architectural contract. A physical
`S3_1_C15_C13_4` pass-through or a zero/shadow result is not justified by the
current evidence.


The retained attempt-65 diagnostic verified the completed run/runtime identity
and immutable image, then read candidate `S3_4_C15_C4_3` twice. Both raw values
were 6; the guest was not resumed and the proxy remained alive. This establishes
readability and the observed state, not writable-bit semantics or alias routing.
The supplemental artifact is `attempt-65-apple-timer-diagnostics.tar.gz`,
SHA-256 `b15b7718815e917d4d1bf89b1430dc8e4c2729fe04e0dae0bba0dad9c84dc27a`.

The next bounded experiment uses an explicit diagnostic flag, checks the exact
recorded stop and prior raw candidate value 6, writes only requested value 2
to the candidate guest bank, captures full readback, and advances four bytes.
It preserves the full prior value for restoration after VEL2 deactivation.
No architectural control-bit mask is borrowed for the Apple register. Any
full-value restoration mismatch is reported rather than explained away.
The physical `S3_1` timer bank is excluded from this experiment.


The opt-in is `--xnu-apple-physical-timer-hypothesis` (pipeline key
`xnu_apple_physical_timer_hypothesis`), requiring native XNU continuation.
The full activated suite passes 392 tests, one skipped. Callback replay covers
source, syndrome, PC, requested-value, and prior-value mismatches without a
candidate-bank write; cleanup tests preserve full raw values and do no I/O
when the guest has not returned. Attempt 66 is the first hardware experiment.

Pinned lookahead after the trapped write reaches `_PE_parse_boot_argn` for
`aprr_jit` at linked `0xfffffe000bf923cc`, followed by memory/global
initialization. No additional unusual register access was identified in the
next approximately 1.1 KiB of this function. A later stop must be classified
from its own evidence; another timer substitution is not covered by
this experiment's predicate.


## Hardware result — attempt 66

Run `1755ffa6-2b38-4d70-9db0-7716b2838a26` admitted the exact predicate and
observed prior raw value 6. The requested write of 2 read back 6. XNU continued
past timer setup to a new memory access at `0xfffffe002b72118c`, syndrome
`0x93890046`, FAR `0xfffffe003a61d014`, after 101.21 seconds and 9924 events.
Full raw restoration wrote 6 and read 6 back exactly. Architectural timer and
AGT redirection restoration also passed, the guest returned, and the proxy
remained alive.

This result supports the bounded continuation on this M3. Unchanged raw
readback is consistent with the hypothesized status-bit behavior, but does
not by itself prove writable-bit semantics or architectural alias routing.
Both remain explicitly unestablished in the report.

The complete event journal SHA-256 is
`66c4fe652c1a083bd22dd8b29abdf3e8dd3284e039137627a500169ba2bf24d0`.
Current target RAM is retained for the next memory-access diagnosis.
