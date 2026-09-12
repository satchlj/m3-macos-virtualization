# Licensing and provenance

## Original contributions: MIT

Except for the third-party material and derivative work identified below, the
original scripts, tests, fixtures, setup files, patches, and documentation in
this repository are licensed under the [MIT License](LICENSE). This grant covers
our contributions to the extent we hold rights in them. It does not replace
upstream copyrights or grant rights in proprietary inputs, trademarks, or linked
external material. Existing copyright notices must be preserved.

## Included third-party material and derivatives

| Material | Applicable license | Required notice |
| --- | --- | --- |
| m1n1 patch context and adaptations in `patches/m1n1/` | MIT | [Asahi m1n1 MIT](LICENSES/Asahi-m1n1-MIT.txt) |
| Upstream portions of `scripts/chainload_preserve_boot.py`, `scripts/clean_reboot_target.py`, `scripts/sprr_permissions.py`, and m1n1-derived behavior in `scripts/sptm_probe/` (exported through `scripts/sptm_entry_probe.py`) | MIT | [Asahi m1n1 MIT](LICENSES/Asahi-m1n1-MIT.txt) and [credits](THIRD_PARTY_NOTICES.md) |
| `scripts/sptm_layout.py`, adapted from the pinned QEMU SPTM loader | GPL-2.0-or-later | [GPL text](LICENSES/GPL-2.0-or-later.txt), [upstream license policy](LICENSES/QEMU-LICENSE.txt), and [credits](THIRD_PARTY_NOTICES.md) |
| Reproduced license documents | Their own stated terms | Preserve verbatim |

Our independently copyrightable additions are offered under MIT wherever we
have the right to do so, including original additions to the layout module.
That does **not** make the QEMU-derived module as a whole available under MIT.
The module is distributed under GPL-2.0-or-later. A combined program using it
must comply with the applicable GPL terms; retaining MIT notices on independent
modules is compatible with that obligation. Do not describe the whole repository
or a bundled runtime as exclusively MIT licensed.

The layout module's Python adaptation, validation, and later research changes
were made in 2026. Its header identifies the upstream revision and the change.
This source repository includes its complete editable source. If distributing
binaries or a packaged combined program, supply the complete corresponding
source, build/install scripts, notices, and license texts as required by the
chosen GPL version; a link to this repository alone is not a universal substitute.

## Dependencies obtained separately

The repository contains no m1n1 checkout, Python distribution, Rust dependency,
or toolchain. Bootstrap obtains these under ignored `local/`. Their licenses
remain in force. MIT at the root does not relicense them.

m1n1's main code is MIT, not GPL-only. Its pinned README also identifies BSD/GPL
alternatives for libfdt and DWC3 portions, MIT components, Zlib, CC0, and the
OFL-1.1 Source Code Pro font. Choosing an available BSD alternative does not
remove its notice obligations. Preserve upstream `LICENSE`, `README.md`,
`3rdparty_licenses/`, individual source notices, and dependency licenses when
redistributing a patched source tree or build. See the [review](docs/PUBLIC-RELEASE-REVIEW.md)
for the dependency inventory and the separate LGPL payload tool.

## Apple inputs and external references

Apple kernel collections, SPTM/TXM images, firmware, device trees, and installer
payloads are not included or licensed by this repository. Locally supplied
inputs remain subject to their applicable terms. References to Apple open-source
XNU and Arm documentation do not relicense those works. Technical observations,
ABI constants, and short diagnostic excerpts do not establish a clean-room
implementation or a license to redistribute the underlying binaries.

## Names and artwork

Asahi Linux, Apple/macOS, QEMU, and Omarchy names are used for attribution and
technical identification, not as this project's brand or an endorsement.
No trademark rights are granted. No logo assets are included in this source
snapshot. The bootstrap's upstream artwork submodule and m1n1's embedded boot
logos are separately licensed; this source-only review does not approve a
branded binary release. See [credits](THIRD_PARTY_NOTICES.md).
