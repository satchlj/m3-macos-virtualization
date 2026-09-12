# Wake-path analysis — how SPTM leaves the WFE idle (2026-09-10)

Offline, read-only disassembly of the WFE idle reached in attempt-11 and the
paths that lead out of it. All addresses are `sptm/__TEXT_EXEC` (image virtual
base `0xfffffe0007004000`); disassembled from the verified payload via the
`trace_disassembly` mapping, no hardware.

## The idle itself

The primary CPU ends in a per-CPU park routine (`+0xf4ab0…+0xf4b8c`): it
validates a small struct at `x20` (reads a 6-byte field, `cmp #2 / b.lo`), zeroes
several byte fields, sets a state byte `[x20+16] = 1`, makes one call
`fn(x20+56, x19, 2600, -1)` (`+0xf4b64`), then enters:

```
+0xf4b88  wfe
+0xf4b8c  b   .-4        ; unconditional: pure idle, no flag re-check
```

Because the branch loops straight back to `wfe`, nothing *after* the `wfe`
advances the monitor. The re-entry at `+0xf4b90` (`mrs x8, TPIDR_EL2; b …`) is a
branch target used by a resumed path, not fall-through. So the real wake is an
exception/guarded-entry, not the idle code.

## EL exceptions are fatal here (VBAR → 0xDEAD)

`VBAR_EL12 = 0xfffffe00070ad000`. All twelve vector slots share one prologue and
a common body:

```
adrp x8,#4096; add x8,x8,#24; ldr x8,[x8]   ; x8 = *(0xae018) = per-CPU exception ctx
cbz x8, →DEAD                                ; null ctx → panic
ldr x9,[x8+16]; cbnz x9, →DEAD              ; reentrancy flag already set → panic
mov x9,#1; str x9,[x8+16]                    ; mark busy
mov x9,#<code>; str x9,[x8+24]              ; record class: 1=curEL_SP0_sync … 9=lowerEL_a64_sync
str xzr,[x8+72]
mrs x9,S3_6_C15_C8_0 (GXF_STATUS); cbnz →guarded
  ESR_EL1/ELR_EL1/FAR_EL1  → [x8+32/40/48]   ; ordinary syndrome
guarded: S3_6_C15_C10_5/6/7 → [x8+32/40/48]  ; guarded syndrome (ESR/ELR/FAR_GL1)
→DEAD:  mov x0,#0xDEAD (57005); wfe; b .-4    ; record-then-park
```

Every slot records the exception into the per-CPU context (`0xae018`) and then
parks at `mov x0,#0xDEAD; wfe`. So in this state a CPU exception is recorded and
fatal — these vectors are not the service path. (The `0xDEAD` marker is the
classic "unexpected" stub.) An interrupt during the idle would, if unmasked, land
here and panic; the monitor idles with interrupts masked, so the `wfe` waits for
an event rather than taking the IRQ vector.

## The real service path: GXF guarded-call dispatch

`GXF_ENTRY_EL1 = 0xfffffe00070a4524` (`GXF_PABENTRY_EL1 = …0bcaf4` for guarded
aborts; `TPIDR_GL2 = 0xfffffe0007106200`, the per-CPU context). A lower level
(the kernel) calls SPTM by executing `genter`, entering the guarded world at this
dispatcher:

```
+0xa0524  msr PAN, #0
+0xa0528  mrs x8, S3_6_C15_C10_5      ; guarded ESR, set by genter
+0xa052c  and x8, x8, #0x1f           ; low 5 bits = call/exception type
+0xa0530  cmp x8,#4; b.eq  →T4        ; five typed handlers
+0xa0544  cmp x8,#0; b.eq  →T0
+0xa054c  cmp x8,#1; b.eq  →T1
+0xa0554  cmp x8,#2; b.eq  →T2
+0xa055c  cmp x8,#3; b.eq  →T3
+0xa0564  mov x0,#0xDEAD; wfe; b .    ; any other type → panic
```

So the SPTM call ABI is: `genter` from the kernel, with the guarded ESR low bits
selecting one of five typed handlers (0–4); the handler then switches SP to a
guarded stack (`+0xa0580…`: read per-CPU base `S3_6_C15_C11_1`, `+0xa10`, load SP,
push frame) and runs the service. This is the mechanism that would wake SPTM to
do real work (service a call, launch the kernel below it).

## Implications

- **Driving real work needs a real guarded entry.** The service interface is
  `genter`, not the EL vectors. Our probe virtualizes GXF, so on hardware the
  real `genter` path is not exercised. Exercising it is R2 (real guarded
  execution), which brings real SPRR enforcement — the go-conditions from
  [sprr-permission-model.md](sprr-permission-model.md) apply directly.
- **The call type lives in the guarded ESR** (`S3_6_C15_C10_5` low 5 bits), which
  `genter #imm` sets. To invoke a specific service we choose the immediate; to
  know which type launches the kernel vs services a page operation, the five
  handlers (T0–T4) must be enumerated offline.
- **The per-CPU exception context at `0xae018`** gates the EL handlers (null →
  panic) and records class/syndrome; its runtime provenance (who sets `0xae018`,
  and to what) is worth confirming, since a real guarded call path may rely on it.
