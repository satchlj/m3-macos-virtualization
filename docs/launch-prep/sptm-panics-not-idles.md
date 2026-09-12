# CORRECTION: 0xf8b88 is SPTM's panic halt, not a WFE idle (2026-09-10)

A disassembly trace overturns a load-bearing prior assumption.

## The finding

`0xfffffe00070f8b88` (`wfe; b .-4`) is the terminal spin **inside SPTM's noreturn
panic/fatal function `0xf8980`**, reachable ONLY via the panic forwarders `0xf8ca0`
(generic panic, ~900 call sites), `0xf8cc0`, `0xb18c0`. There is **no non-panic path
to 0xf8b88** (xref: the park is hit only by `cbz x20,0xf8b88` at 0xf8ab0 inside
0xf8980, plus its self-loop). `0xf8980` formats a message (vsnprintf-style via
0xc439c) and halts.

**So SPTM did not "complete init and idle" — it PANICKED and halted.** The
attempt-11/21 "full init to WFE idle" milestone was the terminal-WFE-mistaken-for-a-
benign-wait artifact (the exact risk flagged in memory `clean-syndrome-before-
interpreting`). Every real-guarded run reached this panic at ~7.815M events.

Consequences for the record:
- attempt-21 "full init to idle" = SPTM panicked mid-boot, then spun in the panic.
- first contact (attempt-23) patched the panic spin's `wfe` to genter; the genter
  worked, but it was issued from a **post-panic** state (not launch-ready).
- attempt-24/25 (CALL_SPTM / ENTER_GUEST from 0xf8b88) hit null actions because the
  state at the panic halt is not STATE_XNU (5). That's why ENTER_GUEST panicked.

## The real launch/no-launch fork (dispatcher 0xe842c)

State at `percpu+2656` (percpu = S3_6_C15_C11_1). Dispatcher reads it (0xe845c),
indexes transition table `0x701a310` at `state*480+event*32`, loads action ptr at
`+8`, and **`cbz x23,0xe86c4` (0xe84bc)**: NULL action -> panic. **State 5 is the
only state with a live ENTER_GUEST (event 12) action** (-> 0xa424c -> 0xa416c ->
eret to [0x98928]). Boot writes state=5 at 0xbfedc/0xc066c/0xc0990/0xc0bd8 and
state=12 at 0xc23e8 -- so SPTM CAN reach 5, but our run panicked before retaining it.

## The likely cause: XNU-context prep null-deref

The entry-PC global `0x98928` is written at `0xbf0b0` from a chain of DT
`chosen/memory-map` getprop lookups (getprop 0xbcc98, called at 0xbf048/6c/80/9c).
getprop returns NULL on a missing property; callers immediately `ldr x8,[x0]`. **A
missing/misnamed memory-map region -> NULL -> null-deref/abort -> panic -> 0xf8b88.**
No `sptm_n_cpus` spin gates the launch/dispatch path, so SMP is not the direct cause.

## Next: capture the panic

The one cheap, decisive step: capture, at the panic, the **caller LR (x30)** (names
which of ~900 panic sites fired), x0-x7 (panic/format args), `percpu+2656` (state),
and `[0x98928]` (entry-PC, 0 = context prep aborted). That names the exact unmet
precondition instead of guessing. Build a panic capture in the probe (stop at
0xf8ca0/panic path with register capture), run a plain real-guarded boot (no genter
injection), single-step near ~7.81M to catch the panic with clean registers.
