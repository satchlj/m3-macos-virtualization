# Current handoff clues (attempts 48–49, 2026-09-11)

> Superseded by attempt 51: the `0x13c9` native return caused an illegal-return
> state (`0x1013c4`). Normalizing it to physical EL1h `0x13c5` cleared the fault
> without permission changes and established actual XNU instruction execution.
> See [the mode audit](xnu-gexit-mode-audit.md). The account below preserves
> attempts 48–49 and must not be read as proof of their legal mode transition.

SPTM now completes TXM and launches XNU. The image transitions use different
instructions and saved PSTATE values:

| Transition | SPTM source | Target | Saved PSTATE |
| --- | --- | --- | --- |
| SPTM to TXM | rewritten `eret` at `0xfffffe00070a4e44` | `0xfffffe0017070000` | `0x13c0` |
| SPTM to XNU | native `gexit` at `0xfffffe00070a5260` | `0xfffffe002bfb0000` | `0x13c9` |

The TXM target comes from global `0xfffffe0007098928`; the XNU target comes
from `0xfffffe0007098930`. Live page-table translation, image placement, linked
entry identity, and payload bytes distinguish them.

Attempt 48 (`33a9fa59-c841-4baf-b4c7-d8ebda7254fa`) recorded 45 verified TXM
world returns: one bootstrap return, 42 bounded repeats at selector-3's return
site, and two selector-2 returns. SPTM then wrote the XNU target and `0x13c9`,
cleared `ASPSR_GL1`, and executed native `gexit`. Its next diagnostic reports a
synchronous exception at the exact XNU entry with `ESR 0x8600000f`, a level-3
instruction-permission fault on the first fetch. This proves control transfer;
no XNU instruction is proved retired.

Attempt 49 (`10e559ef-3a8c-495f-b52a-b6a05accc168`) used the existing
`ASPSR_GL1` redirect trap immediately before `gexit`, verified mapped
kernelcache `__TEXT_BOOT_EXEC`, exact entry bytes and `SPSR_GL1=0x13c9`, then
stopped `handoff-xnu-entry`. The watchdog returned and the proxy remained alive.

The next frontier is the execute-permission mismatch at the XNU entry. Preserve
attempt 49 as the known-good launch gate, then compare the live stage-1 leaf and
SPRR index with PPERM/UPERM before changing permission. See the
[exact post-TXM path](post-txm-svc-path.md), [first authentic SVC](txm-first-svc-2026-09-11.md),
and [finite return catalog](txm-svc-return-catalog.md).
