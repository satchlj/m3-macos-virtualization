# Public source release review — 2026-09-11

## Result and scope

The source snapshot is prepared for release with MIT as the default license,
preserved Asahi MIT notices, and an explicit GPL-2.0-or-later exception for the
QEMU-derived layout module. It must not be advertised as an entirely MIT project.
[LICENSES.md](../LICENSES.md) defines the scope; [credits](../THIRD_PARTY_NOTICES.md)
identify upstream sources. This review is a source/provenance assessment, not a
legal opinion or a clean-room certification.

Reviewed baseline: `98ced2c45ac43e0e673cbec8de1bb2405d5f53e5`, 184 tracked files.
The initial public branch contains a curated snapshot rather than development
history. That limits independent authorship reconstruction. The MIT grant is
for the project's original contributions, as authorized by its maintainer; it
cannot grant rights belonging to other authors. No imported contributor's
copyright is reassigned. Newly discovered copied material must retain its
actual license, even if a default MIT declaration was previously applied.

## Findings and changes

1. Added the root MIT license for original code, tests, fixtures, setup, patches,
   and documentation, with explicit third-party exceptions.
2. Included the exact MIT text from both pinned m1n1 revisions (identical).
   Added attribution headers for known chainload, reboot, and SPRR adaptations.
   Preserved existing patch bytes, license markers, and lock hashes.
3. Compared `scripts/sptm_layout.py` with the pinned QEMU loader cited by its
   existing docstring. Its placement sequence, prefix-size alignment, and virtual
   stride checks follow that loader. Classify the adaptation conservatively as
   GPL-2.0-or-later, not an independently MIT implementation. The upstream file
   has no specific license header; the pinned QEMU LICENSE supplies that default.
   Added the GPL text, QEMU policy, origin, and local modification notice.
4. The layout module is directly imported by `boot_data_relocation.py`,
   `chainload_preserve_boot.py`, `sptm_entry_probe.py`, and `test_sptm_layout.py`.
   Other programs may use it transitively. MIT grants on original modules do not
   remove GPL obligations when distributing a combined program using the module.
5. Kept Asahi credits and upstream URLs. Added explicit independent-project and
   non-endorsement language. No logo, font, image, or binary files occur in the
   reviewed tracked snapshot; every tracked file is text.
6. Checked both bootstrap paths: they fetch upstream artwork, and m1n1's normal
   build embeds boot logos. Do not publish those builds as an unbranded product.
   This release is source-only; removing/replacing embedded artwork and checking
   every included dependency is separate work for a future binary release.

## Separately installed Python dependencies

The two `setup/*requirements.lock` files name the following distributions. These
are downloaded during setup, not vendored into this source release. The
[machine-readable inventory](python-dependency-licenses.json) records exact
PyPI version metadata, with source-archive hashes and license-file evidence for
ambiguous entries. Metadata alone is not a full audit of bundled native code.

| Distribution | Version | License finding |
| --- | --- | --- |
| apple-compress | 0.2.3 | MIT in release archive; metadata lacks a useful license |
| asn1 | 2.8.0 | MIT in release archive; PyPI's BSD label is stale/conflicting |
| click | 8.1.8 | BSD-3-Clause, checked installed license |
| enum-compat | 0.0.3 | MIT |
| loguru | 0.7.3 | MIT |
| pycryptodome | 3.23.0 | BSD-2-Clause and public-domain portions |
| pyimg4 | 0.8.8 | MIT |
| pylzss | 0.3.4 | LGPLv3; release carries GPLv3 and LGPLv3 texts |
| construct | 2.10.70 | MIT |
| exceptiongroup | 1.3.1 | MIT |
| iniconfig | 2.1.0 | MIT |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pluggy | 1.6.0 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| pyserial | 3.5 | BSD-3-Clause in release archive |
| pytest | 8.4.2 | MIT |
| tomli | 2.4.1 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |

Installing or invoking a separately supplied tool does not make its license MIT.
If distributing a payload-tool environment, preserve `pylzss`'s LGPL/GPL notices,
provide the required library source and modifications, and meet the applicable
replacement/relinking requirements for the actual packaging method. Review the
native code and platform libraries bundled in the selected distributions before
shipping wheels or a frozen application. No environment is shipped here.

## m1n1 and build dependencies

Both pinned m1n1 READMEs identify:

| Component | Upstream terms |
| --- | --- |
| m1n1, mini-derived portions | MIT; retain upstream authorship notices |
| libfdt / related ADT portions | BSD-2-Clause OR GPL-2.0 |
| DWC3 portions | BSD-3-Clause OR GPL-2.0 |
| minlzma, musl floating-point portions | MIT |
| tinf | Zlib |
| ARM Trusted Firmware portions | BSD-3-Clause |
| dlmalloc, PDCLib portions | CC0/public domain as upstream specifies |
| Source Code Pro font | OFL-1.1, including reserved font name |
| Asahi logo artwork | CC BY-SA 4.0; attribution does not imply endorsement |

Rust dependencies, Homebrew tools, and system libraries are external build
inputs, not relicensed project files. A binary release needs an inventory of
its actual resolved Rust crates, features, toolchain runtime components, and
notices. The source-release review does not claim an exhaustive binary SBOM.

## Branding and external-source boundary

The public title is “M3 Tahoe SPTM virtualization research.” Asahi Linux is
credited as an upstream project. Apple/macOS and hardware names identify the
research target. QEMU names identify provenance. Omarchy is not adopted as a
project brand. No affiliation, sponsorship, or trademark permission is implied.
Existing `ASAHI_ROOT` environment-variable names are internal compatibility
identifiers, not a product identity.

The upstream [logo guidance](https://github.com/AsahiLinux/artwork/blob/80d14f8b6f485b310e305a84b4b806361518ddd1/logos/README.md)
permits referencing Asahi and asks that logos not represent other projects.
The snapshot contains no logos. Upstream builds remain a separate case.

The technical notes cite XNU, Arm, Asahi, and QEMU sources and contain short
observational/disassembly excerpts. They are not a claim that proprietary
SPTM/TXM or XNU binaries are MIT licensed. No proprietary input files are
included. A blanket assertion of clean-room provenance would be unsupported.

## Omarchy invitation

The [September 11 post](https://omarchy.org/news/2026/09/introducing-omarchy-m/)
invites developers working on Linux for Apple hardware to contact
`apple@omarchy.org` to exchange work. Its first-release focus is M1/M2, with newer
machines pursued in parallel. This repository's relevant contribution is M3
virtualization/research infrastructure. Its documented results do not establish
a bootable macOS guest, a Linux distribution, or GPU support.

No outreach has been sent. The invitation is not a license, endorsement, or
permission to use Omarchy or Asahi branding.

## Publication boundaries

Publish the reviewed source branch and license/notice files. Do not use a mirror
push of unrelated refs or upload the working directory wholesale: local caches,
private evidence, fetched dependencies, payloads, and editor checkpoint refs are
outside the intended release. No GitHub remote is configured in this checkout at
review time. No repository has been created or made public by this review.

The original cleanup validation checked AST-preserving refactoring, pinned patch and license identities, and local links without executing hardware. The refreshed snapshot also includes the Phase 5.3 descriptor/leaf gates and synthetic regressions: 526 configured host tests pass with 6 expected skips, and documentation reachability passes. Hardware evidence is represented only by concise findings; raw reports, event journals, device trees, payloads, serial paths, and archives remain excluded.

## Publication audit — September 11, 2026

Maintainer: **Satya Benson** · [Contact](https://satchlj.com/contact).

The publication audit covered `main` through
`15410714443bdeace25cdb4daab827160fea6cbe`: five commits, 337 unique
historical file blobs, and 237 historical paths. Every blob was decoded as
UTF-8 text; no binary payloads, private home-directory paths, credential URLs,
common token signatures, or suspicious private-input filenames were found by
the targeted scan. Commit metadata uses the public snapshot placeholder
identity. Public upstream attribution addresses and synthetic test addresses
were retained. Generic mentions of Tailscale contain no private endpoint.

Gitleaks 8.30.1 also scanned the release history. Its ten findings were manually
reviewed: all match the names of five pairs of Arm pointer-authentication
registers, once in the original probe and once in its extracted constants
module. These are register identifiers, not credential values. No actual
credential was identified. Pattern scanning and manual review cannot guarantee
that all sensitive information has been detected.

Publication is limited to the reviewed `main` history plus this audit and
maintainer-contact update. Local editor checkpoint refs, ignored working files,
private evidence, and fetched dependencies are excluded. The publication push
uses an explicit commit-to-`main` refspec, without tags or mirror mode.

Fresh-environment setup and GitHub CI remain deferred. Earlier host-test results
are not a substitute for a fresh setup or independent hardware reproduction.

Pre-publication validation on the configured local environment passed: 526
host tests discovered, six skipped; documentation checks reached all 100
Markdown files. No hardware was accessed during this audit.

## Phase 5.3 refresh — September 12, 2026

The public tree now carries the validated behavior through the private research
baseline `fd51f24`, translated into the existing split probe package rather than
copying private development history. The refresh adds the source-pinned GL1
redirect, three-site retype HVC accelerator, exact SS-off ERET continuation,
atomic and memcpy permission-window families, synthetic regressions, and the
matching pinned firmware patch and lock metadata. The public facade and package
layout remain unchanged.

Attempt 143 is included only as a concise engineering result: the PRE callback
and six exact ERET continuations passed, while GENTER rejected a pointer-
authenticated link register before any retype, descriptor, leaf, or AIC result.
No attempt configuration, report, event stream, device path, payload, firmware,
kernel image, archive path, UUID, or private-input digest was copied here.

The September 12 refresh repeated the tracked-tree, history, secret-pattern,
symlink, binary, license-marker, documentation-link, and configured host-test
reviews. Any exceptions and their disposition are recorded above or in the
commit history; no hardware was accessed.
