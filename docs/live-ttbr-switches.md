# Bounded live translation-root switches

With preserved boot inputs, attempt `9069b2d5-335b-417c-8980-03b3f307963b`
reached 7,501,391 events and stopped at the deliberate live-control guard.
Guest ESR/ELR/FAR/SPSR were zero. The request is a `TTBR0_EL1` write to a
new empty root, while continuation code, stack and vectors use TTBR1.
Read-only inspection captured three table pages and verified unchanged
physical backing for all three continuation addresses.

`--allow-live-ttbr` permits same-profile plain 42-bit aligned root replacements
only. It walks the complete candidate root within a bounded table/leaf budget,
rejects table or leaf addresses outside guest RAM, cycles and unsupported
descriptors, and verifies executable code/vector and writable stack mappings
with unchanged physical backing. It does not require unrelated old mappings
to survive an intentional root replacement. TCR/MAIR changes remain guarded.

The guest is stopped during validation. Table writes are ordered with DSB,
the EL12 root is written, then ISB and guest stage-1 TLBI/barriers complete
before resuming. Readback must match. Every table page read is retained in the
attempt inputs, and the report records old/new controls and validation results.
The stage-2 owned-RAM boundary remains unchanged; this is not a general MMU
emulator or complete-machine-state proof.

Synthetic tests cover removing low mappings with high continuation, external
leaves, cyclic tables, root tags, budgets, changed physical backing and denied
execution. Real-callback replay checks write/barrier ordering and confirms
TCR changes remain guarded. The suite passes 209 tests. Hardware application
of the new switch handler is pending.

`inspect_pending_ttbr.py` performs the read-only inspection on the latest
completed unchanged guest RAM. Its captured pages can also be replayed offline
through `validate_root_switch`; no target is needed for that replay.
