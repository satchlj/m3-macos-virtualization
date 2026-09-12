# SPTM guarded-call service = a GXF world-transition state machine (2026-09-10, complete)

Full decode of the guarded-call service (verified against `sptm.macho`,
SHA `6ab3f26f…`). The classifier at `0xfffffe00070e8d4c` maps the x16 selector to an
EVENT, then `dispatch_state_machine` (`0xe842c`) runs `transition[state][event]` from
a 2-D table at `0x701a310` (row stride 480, col stride 32; entry = next_state, an
arm64e-authed action fn-ptr, commit byte, flags). Idle state = STATE_XNU (5).

## Selector -> event (the only x16-selectable events)

| selector field | event | code |
|---|---|---|
| low byte `0x1b` | ENTER_GUEST | 12 |
| low byte `0x1c` | EXIT_GUEST | 13 |
| low byte `0x1e` | CALL_SPTM_HIB | 14 |
| bits[55:48]==2 | CALL_TXM | 3 |
| bits[55:48]==3 | CALL_SK | 4 |
| else (bits[39:32]≠0, or default low byte) | CALL_SPTM | 2 |

## Transitions from STATE_XNU (idle), classified

| event | action | class | evidence |
|---|---|---|---|
| CALL_SPTM (2) | `0xa424c` | **SAFE family** | set monitor SP, `blr` resolved service, unwind via RETURN-event 5; **no eret, no inline PT/SPRR/GXF write** |
| CALL_TXM (3) | `0xa4000` | MUTATING + transfer | writes SCTLR/TCR/MDSCR/GXF regs, then `eret` -> TXM guarded domain |
| CALL_SK (4) | `0xa410c` | MUTATING/transfer | writes GXF regs, `bl 0xe90b0`, `eret` -> SK guarded domain |
| ENTER_GUEST (12) | `0xa424c` | **LAUNCH** | full guest GPR/SIMD restore + GXF program + `eret` to lower EL = normal-world XNU kernel |
| EXIT_GUEST (13) | NULL | PANIC (no-op) | can't exit a guest from idle |
| CALL_SPTM_HIB (14) | `0xa424c` | likely MUTATING | hibernation (power/persistence) |

## Safest first call: CALL_SPTM (event 2)

Its action never `eret`s to another domain and does no inline mutation — it runs a
C service and returns a result to the caller. Recipe: bits[55:48]=0, bits[39:32]≠0
(=> event 2), SPTM func index in bits[35:32]. So **x16 = idx << 32** (idx 1,2,3,…).

**Caveat (why we sweep, not guess):** the per-function handler+allowed-state table
(`~0x99xxx`) is in `__LATE_CONST` — zero on disk, filled at monitor init — so which
index is a valid read-only query, and its exact result, can't be read from the file.
An index not permitted in STATE_XNU takes LOG (`0xf8ce0`) then **PANIC** (`0xf8ca0`,
noreturn): non-mutating, non-launching, but it panics instead of returning. The probe
now HALTS at `0xf8ca0` before the panic runs (`stop_reason guarded-call-panic`), so a
sweep is safe: each index either returns a status (captured) or panic-halts cleanly.

## Kernel-launch selector (confirmed)

**ENTER_GUEST, `x16 = 0x1b`** -> action `0xa424c` -> full guest restore + `eret` to
the normal-world XNU kernel. This is the unique kernel-launch selector (CALL_SK/TXM
`eret` into the *guarded* SK/TXM domains, not the normal world). This is the pivot to
the "kernel launch" milestone (see the forward-complexity analysis) — do NOT issue it
until the guest image + launch context + reversibility are prepared.
