# XNU Phase 5.3 allocation and SPTM retype evidence

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

## Verified result

Attempt 103 (`b3ebd725-42d8-474a-b5ec-b191c8326046`) completed a bounded
seven-stage allocation/retype trace on an M3/J613 target. Each terminal was
checked against the pinned source word, live instruction word, L3 mapping and
access flag, and the firmware step-filter contract.

The run observed an owned 16 KiB frame at physical address `0x100187fc000`, then
an SPTM retype call with old type `0x0b`, new type `0x29`, and flags `0`.
Selector-1 `genter` crossed the XNU/SPTM service path and returned after 1,290
filtered steps.

SPTM's runtime frame-table base resolved to `0xfffffdf000000000`. The derived
16-byte record was `0xfffffdf000029ff0`, exactly equal to the service result.
Its stable contents changed from:

```
00000b00000000000000000000000000
```

to:

```
00002900000000000000000000000000
```

Only byte 2 changed: `XNU_DEFAULT` (`0x0b`) to `TXM_DEFAULT` (`0x29`). Bytes
0--1 are the `in_flight_ops` lock field; byte 2 is the portable type field;
bytes 3--15 are type-specific metadata.

The guest returned cleanly and the proxy remained responsive. Guest execution
took 48.85 seconds and retained 10,289 events.

## Attempt 104: XNU page-table-frame retype

A following bounded survey pinned calls to the XNU `sptm_retype` wrapper and
completed five transactions in 44.86 seconds. The fifth call was the primary
target:

- caller callsite `0xfffffe002b7eefe4`, source/live word `0x941e2d33`;
- physical frame `0x100187f4000`;
- exact arguments `x0=0x100187f4000`, `w1=0x0b`, `w2=0x14`, `x3=0x3`;
- selector-1 `genter`, native `gexit`, the post-service helper, authenticated
  wrapper return, and caller return;
- authoritative FTE VA `0xfffffdf000029fd0`, derived from the live frame-table
  base pointer.

The stable center record changed from:

```
00000b00000000000000000000000000
```

to:

```
00001400030000000000000000000000
```

Bytes 0--1 (`in_flight_ops`) remained zero. Byte 2 changed from `XNU_DEFAULT`
to `XNU_PAGE_TABLE`; the post-retype type-specific metadata contains the call's
flags value `0x3`. Both adjacent records were stable. The wrapper entry,
selector, `genter`, `gexit`, post-service helper, wrapper return, caller branch,
frame-table base, and table translations passed their source/live/L3/access and
filter-contract gates.

The four earlier calls were `0x0b->0x29`, two `0x0b->0x23` calls, and
`0x23->0x0b`. The target was reached after 131,554 aggregate forwarded steps
and 36 rearms, far below the configured limits. The guest returned cleanly,
cleanup passed, and the proxy remained responsive.

## Scope

These runs establish a kernel-driven allocation and two exact SPTM-mediated
frame ownership transfers, including an `XNU_PAGE_TABLE` transition. They do
not identify or verify the corresponding Stage-1 descriptor write, prove that
the page is linked into a live table hierarchy, establish general dynamic
page-table services, complete kernel bring-up, boot macOS, or support the GPU.
Large raw run artifacts are intentionally excluded from this repository.

## Three-site HVC survey accelerator — attempt 143

The survey feedback path now has an opt-in, late-live accelerator for three
source-pinned instructions in the common retype wrapper: PRE at linked
`0xfffffe000bf7a4b8`, GENTER at `0xfffffe000bf7a4c0`, and POST at
`0xfffffe000bf7a4cc`. The isolated live image is patched only after the
allocation proof and wrapper/source/readback gates pass. Strict ordering,
caller-frame and FTE checks, exact native ERET continuations, seven base GL1
counter deltas, an optional all-or-none four-site nested GL1 sequence, bounded
call counts, idempotent restoration, and teardown disablement remain mandatory.

Attempt 143 installed and read back all three exact HVC words, accepted six
single-step-off native world continuations, and completed the PRE callback. It
then stopped cleanly at the GENTER gate because the first helper return check
compared the full pointer-authenticated link register. No retype call completed,
so this run adds no descriptor, leaf, or AIC evidence. The result narrows the
next experiment to a source- and range-pinned authenticated-return comparison;
it does not relax any ownership, FTE, counter, or cleanup gate. All three live
words were restored and both firmware accelerators were disabled before exit.
Only this bounded summary is published; the run configuration, report, event
journal, device details, and payloads remain outside Git.

## Corrected accelerator — attempt 147

The helper-return gate now reconstructs the canonical kernel address from the
authenticated link register's low 40-bit VA payload and still requires an exact
match to the source-pinned return PC. Exact HVC-owned ERET transitions retain
their source instruction, target mapping and bytes, translation roots, and
banked PSTATE as bounded certificates; only an identical later transition can
use the replay lane.

Attempt 147 completed 14 retype calls and 15 exact native ERET continuations.
Every call crossed each of the seven base GL1 redirect sites once with no
forwarded access. Thirteen calls had no nested sequence; one crossed all four
nested sites exactly once. A partial or repeated nested sequence remains a
fail-closed rejection.

The run also re-established the bounded descriptor and leaf-binding result and
completed 20 exact permission windows: 17 memcpy-family and three atomic-family
windows. It returned cleanly when the 90.29-second watchdog fired at a host
callback boundary, restored the temporary live-image changes, disabled the
firmware accelerators, and retained a responsive proxy. No AIC access was
observed, mapped, read, or written. This is accelerator and continuation
evidence, not a new general SPTM or AIC result. The raw configuration, report,
event stream, target identifiers, proprietary inputs, and archive digests are
not published.
