# XNU M3 AHCR diagnostic compatibility

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

The opt-in `--xnu-m3-nop-ahcr-compat` reproduces one bounded upstream m1n1
loader behavior. It replaces the pinned kernelcache's `mrs x10, AHCR_EL2` at
linked `0xfffffe000b8178d4` and `msr AHCR_EL2, x10` at linked
`0xfffffe000b8178dc` with NOPs. Both source words, the `__TEXT_EXEC` segment,
and the host ADT chip ID are verified before either instruction is changed.

The originating upstream change is AsahiLinux/m1n1 commit
`874ff59ea1297b8bdc438c6ad425efdcf4224dd3`, whose stated scope is macOS
14.8.3 on M3 devices containing EL2-only accesses with no known trap route.
The local audited m1n1 checkout is pinned at
`1c98fd09817cede0043d25c95fb540dbd683ef18`; this is the revision containing
the behavior, not its origin.

This is a diagnostic bypass. It does not model AHCR state, define the meaning
of bits `0x1e`, or emulate any AHCR hardware effect. The MRS NOP leaves `x10`
holding the preceding platform value, exactly as upstream does, and that value
is consumed only by the suppressed MSR before `x10` is overwritten. The flag
requires `--xnu-run` and is accepted only for the same chip-ID set used by the
upstream loader: `0x8122`, `0x6030`, `0x6031`, `0x6032`, and `0x6034`.

## Diagnostic hardware result

Attempt 57 (`826720d8-f7e3-4139-9a67-ce9f448159fc`) applied the exact pair
on the verified M3 chip and progressed to a different early XNU panic:

```text
panic: Undefined kernel instruction: pc=0xfffffe002b823a18 instr=d519f751 @sleh.c:1869
Kernel panicked very early before serial init, spinning forever...
```

The finalized archive contains 4905 events; console extraction verified its
identity and event count. The guest returned, the timer guest bank was restored
and read back, and the proxy remained responsive. This demonstrates progress
under suppressed AHCR accesses. It does not establish AHCR hardware equivalence
or full upstream M3 compatibility; only the observed pair uses upstream's NOP
treatment.
