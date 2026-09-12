# Exact SPRR permission representability

The upstream `hv-sprr` implementation at our pinned `1c98fd0` explicitly overgrants some permission combinations when building ordinary shadow leaves, and logs that hierarchical table attributes are ignored. This is an unresolved integration constraint for Tahoe monitor support, not a reason to remove the current translated-SPRR stop.

`scripts/sprr_permissions.py` provides an offline audit using the public upstream nibble interpretation. Given EL1/EL0 permission registers and a selected guarded or ordinary world, it identifies each index's requested RWX pair and whether an ordinary stage-1 leaf can express it exactly. It rejects unrepresentable pairs rather than broadening access. The assumptions are explicit: AF set, PAN and WXN clear, no hierarchical restrictions. No target state or page tables are changed.

This does not validate the upstream nibble meanings on M3, implement shadow-table synchronization, or enable SPRR/GXF in our probe. Integration still needs evidence for actual permissions and table attributes, correct fault delivery, coherence after guest table writes and world-specific exception banks. In particular, execute-only and asymmetric EL0/EL1 write permissions cannot simply be mapped with extra access and declared equivalent.

Tests exhaust all 64 RWX pairs, verify representative privilege and execution constraints, and distinguish the two upstream world mappings. The full research suite now has 170 passing tests. This is a preparation tool for step 2 of the monitor plan; live translated SPRR remains unsupported.

Source: [pinned public hv_sprr.c](https://github.com/AsahiLinux/m1n1/blob/1c98fd09817cede0043d25c95fb540dbd683ef18/src/hv_sprr.c), `sprr_el_rwx`, `sprr_gl_rwx`, `sprr_leaf_bits`, and `sprr_mirror_entry`.
