# Boot panic root cause: SPTM can't look up the 'slide' image region (2026-09-10)

Extracted from attempt-25's existing trace (first panic entry 0xf8ca0 at idx
7,811,800; no new run needed).

## The panic

- Panic caller: `0xfffffe00070bcd50` (`bl` to panic 0xf8ca0), in the region parser.
- Format string (x0 = `0x7006666`): **`"%s: error %d looking up image region '%s'"`**
- Region name (x1 = `0x7006514`): **`slide`**

So SPTM's `init_get_image_region("slide")` returns a nonzero error during boot, and
SPTM panics -> 0xf8980 -> spins at 0xf8b88. This is the halt we mis-read as "WFE idle."

## Meaning

SPTM parses `chosen/memory-map` for named regions (BootKC-*/TXM-*/SPTM-*/TrustCache/
**slide**/BootArgs). The `slide` lookup fails -> panic BEFORE it writes the XNU entry
PC global (0x98928) and reaches launch-ready state 5. So the launch was never
possible; the boot aborts at the slide lookup.

The probe builds the ADT from target M3's REAL ADT and overwrites `layout['regions']`
entries with guest addresses. If `slide` is not in `layout['regions']` (so it keeps
the real machine's value, which is wrong/inconsistent for our guest) or is malformed,
the lookup errors. FIX: provide a correct `slide` region in the guest memory-map.

## Next

Determine what `slide` should be for our guest layout (SPTM self-relocates by
aligning phys_base to 32 MB; slide = guest phys/virt offset), and set the `slide`
region in the ADT so `init_get_image_region("slide")` succeeds. Then SPTM's boot
proceeds past 0xbcd50, writes the entry-PC global, and can reach launch-ready.

## Confirmed: 'slide' is absent from the memory-map entirely

Inspected the saved ADTs (attempt-25 inputs). The `chosen/memory-map` props include
all of `BootKC-*`, `TXM-*`, `SPTM-*`, `CL4-*`, `TrustCache*`, `BootArgs`,
`DeviceTree*`, `AuxKC-*`, `RTBuddySeg`, etc. -- but **no `slide` and no `PHYS_SLIDE`**.
target M3's real ADT (u.get_adt()) lacks it because target M3 booted m1n1, not the real
SPTM chain (iBoot synthesizes `slide` only for the monitor boot path). So our probe
has nothing to overwrite, and the region is simply missing -> lookup error -> panic.

Guest ADT already has (probe-set) e.g. `BootKC-entry = 0xfffffe000bfb0000` (XNU entry
VA), `BootArgs = 0x10019218000`, `TrustCache = 0x10011eec000`. It just lacks `slide`.

## The fix

Add a `slide` region to the guest `chosen/memory-map`. `init_get_image_region` reads
it (address/size); SPTM computes the XNU entry PC = BootKC base + slide, so the slide
value must be consistent with how BootKC-entry/virt are set. Determine the exact
semantics (is `slide` an address=value/size=0 like BootKC-entry, and is the correct
value 0 for our linked-VA guest, or the phys/virt relocation offset?) then set it in
the probe's ADT construction (alongside the layout['regions'] overwrites). Re-run;
SPTM's boot should pass 0xbcd50 and proceed toward launch-ready.
