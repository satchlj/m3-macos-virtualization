# Pinned TXM SVC return catalog

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

This catalog is for `local/payload/txm.macho`, SHA-256
`df750ed7e0cb8f9ceff6e0d78a58b0442668367cdd896d39334b60fa09e67cef`.
It was produced offline by scanning every four-byte-aligned instruction in the
Mach-O and checking the results with LLVM's AArch64 disassembler. The image has
exactly ten `svc` instructions and 821 `retab` instructions.

The runtime addresses below use the placement observed in attempts 45 and 46:
linked entry `0xfffffff017070000` at runtime `0xfffffe0017070000`.

## Selector stubs

Seven `svc #0` instructions are in identical five-instruction stubs:

```asm
pacibsp
mov   x16, #low16
movk  x16, #high16, lsl #32
svc   #0
retab
```

`mov` clears the other bits and `movk` inserts bits 47:32, so each selector is
fully determined by the two instructions.

| selector in `x16` | linked SVC | linked post-SVC `retab` | runtime post-SVC `retab` | static direct callers |
|---:|---:|---:|---:|---:|
| `0x0000000100000001` | `0xfffffff01706800c` | `0xfffffff017068010` | `0xfffffe0017068010` | entry point |
| `0x0000000100000002` | `0xfffffff0170532e8` | `0xfffffff0170532ec` | `0xfffffe00170532ec` | 2 |
| `0x0000000100000003` | `0xfffffff0170532d4` | `0xfffffff0170532d8` | `0xfffffe00170532d8` | 1 |
| `0x0000000100000004` | `0xfffffff0170532fc` | `0xfffffff017053300` | `0xfffffe0017053300` | 1 |
| `0x000000fd00000000` | `0xfffffff017053324` | `0xfffffff017053328` | `0xfffffe0017053328` | 1 |
| `0x000000fe00000000` | `0xfffffff017053310` | `0xfffffff017053314` | `0xfffffe0017053314` | 6 |
| `0x000000ff00000000` | `0xfffffff017053338` | `0xfffffff01705333c` | `0xfffffe001705333c` | 1 |

The `0x100000001` and `0x100000003` returns were observed in attempts 45 and
46, respectively. The other five entries are payload-derived candidates, not
observed runtime events.

## Other SVC instructions

The remaining three instructions are control-transfer machinery rather than
the selector-stub shape above:

| linked SVC | immediate | linked next PC | next instruction |
|---:|---:|---:|---|
| `0xfffffff017031024` | `0x25` | `0xfffffff017031028` | `ldp x8, x9, [x0, #0xc0]` |
| `0xfffffff0170310b4` | `0x25` | `0xfffffff0170310b8` | branch to `0xfffffff01702edec` |
| `0xfffffff017031208` | `0x26` | `0xfffffff01703120c` | `ldp x8, x9, [sp], #0x10` |

None has an immediate post-SVC `retab`, so none belongs in the world-return
allowlist.

## Fail-closed predicate

A generic rule accepting any payload-verified TXM `retab` is too broad. It
would accept 821 linked sites, including ordinary function epilogues that do
not establish a completed SVC. For this pinned payload, use the seven linked
post-SVC PCs above as the complete finite allowlist.

The existing return-state predicate is appropriately strict when combined
with that allowlist:

```python
0 <= spsr_gl1 < (1 << 32) and (spsr_gl1 & ~0xf0000000) == 0x13c0
```

It fixes every low PSTATE bit to the observed TXM return state and permits only
the four NZCV bits to vary. Keep the other existing gates: exact SPTM ERET
overlay PC, prior verified TXM entry, TXM executable segment, translated live
bytes equal to the pinned payload, and a bounded total continuation count. An
unknown target, changed byte, non-TXM mapping, or any non-NZCV SPSR difference
must stop rather than resume.

Treating every linked site as one-shot is an additional safe bound, but it is
not a property of the payload ABI: selectors `0x100000002` and `0xfe00000000`
already have two and six direct call sites. If native continuation must permit
repeat calls, bound the total number of accepted world returns and report the
per-site count instead of widening the target predicate.
