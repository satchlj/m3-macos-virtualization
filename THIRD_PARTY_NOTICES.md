# Third-party credits and notices

## Asahi Linux and m1n1

This project builds on the Asahi Linux contributors' Apple Silicon research,
m1n1 bootloader and hypervisor, host proxy tools, and public documentation.
We gratefully acknowledge that foundation. This project is independent and
is not an official Asahi Linux project or an endorsed distribution.

Copyright The Asahi Linux Contributors.
The full [upstream MIT license](LICENSES/Asahi-m1n1-MIT.txt) is included unchanged.

Sources:

- [m1n1 loader baseline](https://github.com/AsahiLinux/m1n1/tree/940439b9a407fbfc499bea933269219f3f62d4c7), pinned by `upstream.lock`.
- [m1n1 virtual-EL2 baseline](https://github.com/AsahiLinux/m1n1/tree/1c98fd09817cede0043d25c95fb540dbd683ef18), pinned by `upstream-vel2.lock`.
- `proxyclient/tools/chainload.py`: RAM chainload sequence adapted in `scripts/chainload_preserve_boot.py`.
- `proxyclient/tools/reboot.py`: reset-panic-counter/reboot sequence used in `scripts/clean_reboot_target.py`.
- `src/hv_sprr.c` and `src/memory.h`: permission tables and leaf index mapping adapted in `scripts/sprr_permissions.py`.
- `proxyclient/m1n1/hv/__init__.py`: upstream loader and hypervisor behavior referenced by the patches and probe; the AHCR compatibility behavior originates in commit `874ff59ea1297b8bdc438c6ad425efdcf4224dd3`.

The patch series contains upstream context and local modifications. It does not
replace m1n1's upstream notices. See upstream Git history for individual authors.

## QEMU SPTM loader

`scripts/sptm_layout.py` is a Python adaptation of the placement logic in
[jprx/qemu-sptm, hw/arm/xnuboot_sptm.c](https://github.com/jprx/qemu-sptm/blob/6c3ca665bab9a08399f4681e4ada43bfcfb7d493/hw/arm/xnuboot_sptm.c).
Credit belongs to that file's authors and the QEMU contributors; consult the
pinned upstream Git history for authorship. The source file contains no separate
copyright/license header. The pinned repository's [license policy](LICENSES/QEMU-LICENSE.txt)
licenses such files under GPL version 2 or any later version. We preserve that
license for the adaptation; see [GPL-2.0-or-later](LICENSES/GPL-2.0-or-later.txt).
Local changes in 2026 include Python conversion, offline layout reporting,
validation, and subsequent research corrections.

The documentation also cites QEMU's `darwin.c` and debug implementation as
technical references. Citation alone grants no MIT rights in QEMU code.

## Artwork and fonts in separately obtained m1n1

The source snapshot includes no graphics or fonts. Bootstrap fetches the
[Asahi artwork repository](https://github.com/AsahiLinux/artwork/tree/80d14f8b6f485b310e305a84b4b806361518ddd1)
as an upstream submodule. Its logos are copyright (c) 2021 soundflora* and Hector
Martin, licensed CC BY-SA 4.0. The upstream logo README asks users to reference
Asahi Linux, not represent another project or imply association or endorsement.

Upstream m1n1 also embeds boot logos and the OFL-1.1 Source Code Pro font.
A future binary release needs its own artwork/font and dependency review.
Removing a fetched artwork directory or appending a custom logo does not by
itself prove that embedded Asahi artwork was removed from a build.

## Other references and dependencies

Apple's published XNU source, Arm architecture documentation, and Asahi's
hardware documentation are credited where used in the technical notes. Their
licenses are not replaced by this repository's MIT grant. No clean-room claim
is made. See [the release review](docs/PUBLIC-RELEASE-REVIEW.md) for separately
installed Python dependencies, review evidence, and scope limitations.
