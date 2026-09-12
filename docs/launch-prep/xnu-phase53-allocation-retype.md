# XNU Phase 5.3 allocation and SPTM retype evidence

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
