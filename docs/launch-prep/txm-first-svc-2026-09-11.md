# TXM's first post-relocation operation is an SVC

Offline inspection of attempt 40 identified its original trigger as TXM's first
`svc #0`, rather than an Image4 panic. Attempt 45 then confirmed that path on
hardware with the corrected guarded VBAR and no instruction patch.

## Payload evidence

The verified TXM payload SHA-256 is
`df750ed7e0cb8f9ceff6e0d78a58b0442668367cdd896d39334b60fa09e67cef`.
Runtime base `0xfffffe0017004000` corresponds to file offset zero and linked
base `0xfffffff017004000`. Raw words were decoded with Homebrew `llvm-mc` via
`scripts/trace_disassembly.py`; no target access was used for this analysis.

```text
0xfffffe0017070048  bl      0xfffffe001706c000  ; relocation
0xfffffe001707004c  bl      0xfffffe0017068000
0xfffffe0017070050  mov     x0, x20
0xfffffe0017070054  b       0xfffffe0017027e14  ; main initialization

0xfffffe0017068000  pacibsp
0xfffffe0017068004  mov     x16, #1
0xfffffe0017068008  movk    x16, #1, lsl #32
0xfffffe001706800c  svc     #0
0xfffffe0017068010  retab
```

Therefore the relocation-return breakpoint at `0xfffffe001707004c` needs only
five single-step transitions to approach this SVC. A before-SVC capture should
record the normal and guarded vector bases, guarded state, stack pointers, and
normal/guarded exception banks. An after-SVC capture should establish which
vector is selected before allowing it to execute further.

## Attempt 40 evidence

Run `29dcd942-e1ad-4e15-81a0-d2d23693a896` ended with:

| Register | Observed value | Interpretation |
| --- | --- | --- |
| x16 | `0x100000001` | Exactly the selector constructed by the SVC stub |
| x30 | `0x80f7fe0017070050` | PAC-bearing link consistent with the stub's caller |
| x14 | `0xfffffe001700a36f` | Pointer to the Image4 build-path string |
| x15 | `0x636f` | Image-relative offset of that same string |
| VBAR_GL1 | `0x10003611800` | Host vector address, not the staged SPTM vector |
| ELR_GL1 | `0x10003611a00` | Recursive vector instruction abort |
| ESR_GL1 | `0x86000005` | Later instruction abort; original SVC syndrome is lost |

The x14/x15 values are consistent with scratch left by the pointer relocation
routine, which computes `x14 = base + offset`. They are not evidence that
Image4 diagnosed a failure. The simultaneous selector and link-register match
is much more specific evidence for the SVC stub.

## Concrete harness mismatch

`scripts/sptm_entry_probe.py` redirects `SPSR_GL1`, `ASPSR_GL1`, `ELR_GL1`, and
`ESR_GL1` through the corresponding guest bank aliases in real-guarded mode,
but its `real_redirect` set omits `VBAR_GL1`. Both guest vector writes in attempt
40 were recorded as `staged-apple-register`:

| SPTM PC | Requested VBAR_GL1 |
| --- | --- |
| `0xfffffe00070b0be8` | `0xfffffe00070ad000` |
| `0xfffffe00070b0c58` | `0xfffffe00070a8000` |

The final staged value is thus `0xfffffe00070a8000`, while the live bank still
contains the host vector. The Python `HV.MSR_REDIRECTS` table already contains
`VBAR_GL1: VBAR_GL12`. Applying that alias in real-guarded mode is a concrete
candidate fix, subject to a bounded hardware check. This analysis does not
claim that the VBAR correction alone makes SVC dispatch work; the exact
guarded/normal routing and SPTM service contract must be observed next.

`FAR_GL1` and `AFSR1_GL1` are also currently staged rather than redirected.
They may matter for accurate fault handling later, but are not needed to
explain the vector-base mismatch seen here.

The requested SPTM vector at `0xfffffe00070a8400` (base plus `0x400`, lower-EL
synchronous entry) branches to `0xfffffe00070a5e28`. That handler explicitly
recognizes ESR exception class `0x15` and immediate zero, then routes the
ordinary selector class through `0xfffffe00070a639c`. It saves the lower-world
context and calls SPTM's C service with `x0 = 2`, `x1 = x16`. This is direct
payload evidence that SPTM has a real handler for this SVC; the harness should
deliver the exception there rather than synthesize a successful service return.
The vector-path raw disassembly is saved in
`artifacts/txm-first-svc-sptm-vectors.txt`.

## After SVC return

Attempt 45 (`ab5a42b5-dfc5-4964-8a54-4ef5556568a4`) applied both SPTM VBAR
writes through `VBAR_GL12` and verified their live readback. TXM completed
relocation, issued the authentic SVC with `x16 = 0x100000001`, and entered the
expected SPTM handler. SPTM dispatched the service at runtime
`0xfffffe00070c082c`, called its helper for `"TXM-rx"`, atomically set bootstrap
stage bit 14, then
restored `SPSR_GL1 = 0x600013c0` and `ELR_GL1 = 0xfffffe0017068010`.
That return target is the original TXM `retab` (`0xd65f0fff`) immediately after
the SVC. The probe stopped only because interior verified ERET returns were not
yet in its continuation allowlist.

Attempt 46 (`cfbea2a6-6552-4e3e-9b4e-617791c8cb68`) consumed that return once,
continued TXM initialization, and reached a second authentic service return at
runtime `0xfffffe00170532d8` (linked `0xfffffff0170532d8`), again an original
`retab`, with `SPSR_GL1 = 0x200013c0`. The selector state identifies service
`0x100000003`. The native continuation allowlist contains these two exact linked
sites, verifies their loaded payload bytes and PSTATE, and bounds repeats per
site. Attempt 47 proved selector `0x100000003` legitimately repeats; a global
generic `retab` rule would be unsafe because the payload contains 821 unrelated
`retab` instructions. See `docs/launch-prep/txm-svc-return-catalog.md`.

Attempt 44b is excluded from the firmware conclusion. Its software HVC
breakpoint at TXM `+0x4c` stayed inside guarded exception routing and caused an
artificial SPTM panic before the natural BL/SVC could run. The pipeline now
rejects that breakpoint control unconditionally; see
`docs/launch-prep/attempt-44b-breakpoint-panic.md`.

Attempt 48 (`33a9fa59-c841-4baf-b4c7-d8ebda7254fa`) carried this path through
45 exact TXM returns and native `gexit`. SPTM transferred to XNU entry
`0xfffffe002bfb0000`, where the first fetch took a level-3 instruction-permission
fault. Attempt 49 (`10e559ef-3a8c-495f-b52a-b6a05accc168`) stopped cleanly at
the verified pre-`gexit` boundary with `stop_reason handoff-xnu-entry`. See
`docs/launch-prep/post-txm-svc-path.md` for the complete continuation.

Private reproducible evidence:

- `artifacts/txm-post-relocation-code.txt`: compact entry, SVC, and main disassembly.
- `artifacts/txm-first-svc-evidence.json`: extracted run identity, final registers,
  staged VBAR writes, and exact Image4 string.
- `artifacts/runs/observe-sprr/attempt-40/report.json`: source live observations.

No USB operation, target mutation, firmware build, or probe-code change was
performed by this offline analysis.
