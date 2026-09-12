# M3 Tahoe SPTM virtualization research

Experimental tooling for running and observing Tahoe's SPTM/TXM/XNU path on an
Apple M3 (J613/T8122) through a patched
[Asahi Linux m1n1](https://github.com/AsahiLinux/m1n1) hypervisor.

This repository is a research snapshot, not a macOS boot solution. It contains
host tooling, tests, two pinned m1n1 patch series, and concise technical notes. It
does **not** contain Apple firmware, kernel collections, device trees, raw traces,
credentials, or a prebuilt boot image.

## Start here

| You want to… | Read |
| --- | --- |
| Understand the project and terminology | [Overview](docs/OVERVIEW.md) |
| See what works and what remains open | [Current status and evidence](docs/STATUS.md) |
| Explore without a physical target | [Host test guide](tests/README.md) |
| Find a script or understand code organization | [Script map](scripts/README.md) · [Maintenance review](docs/CODE-REVIEW.md) |
| Trace a research finding | [Complete documentation index](docs/README.md) |
| Reproduce the source environment | [Setup guide](setup/README.md) |
| Make a contribution | [Contributing](CONTRIBUTING.md) |

## Current result — September 11, 2026

Attempt 119 completed the bounded Phase 5.3 objective on an M3/J613: one
kernel-driven allocation and ownership-transfer chain was tied to a live
selector-3 L3 table installation and selector-2 leaf PTE insertion. The exact
16 KiB table changed only at the independently computed slot, both services
returned status zero, the guest returned cleanly, and the proxy remained alive.

**A macOS boot has not been demonstrated.** This is one bounded dynamic Stage-1
mutation chain, not general SPTM compatibility. Phase 5.4 AIC initialization is
the next frontier. [STATUS.md](docs/STATUS.md) distinguishes the verified scope
from open work and links the [leaf-binding evidence](docs/launch-prep/xnu-phase53-leaf-page-bind.md).

Hardware findings are documented here, but raw captures and proprietary inputs
are retained outside Git. A fresh clone can run synthetic host checks; it cannot
independently replay every hardware finding. Read the
[evidence model](docs/SAFETY.md) when assessing claims.

## Repository map

| Path | Contents |
| --- | --- |
| [scripts/](scripts/README.md) | Host analysis, evidence tools, and experimental runners |
| [tests/](tests/README.md) | Synthetic regression coverage and source-dependent checks |
| [docs/](docs/README.md) | Current orientation plus historical evidence and design notes |
| [setup/](setup/README.md) | Source checkout and Python environment setup |
| [patches/m1n1/](patches/m1n1/) | Two separate patch tracks, each pinned by its own lock file |
| [upstream.lock](upstream.lock) | Loader-validation baseline and patch hashes |
| [upstream-vel2.lock](upstream-vel2.lock) | Experimental runtime baseline and patch hashes |

The patches apply to **different upstream revisions**, not sequentially to one
tree. Setup creates separate local checkouts. Building or passing tests does not
establish hardware readiness.

## Inputs and provenance

Apple payloads are intentionally excluded. `setup/restore-payloads.py` accepts a
locally supplied, checksum-manifested evidence directory and recreates disposable
extracted payloads under ignored `local/payload/`. It neither downloads nor
redistributes proprietary inputs.

The lock files identify exact upstream repositories, commits, expected source
hashes, and patch hashes. See [licensing and provenance](LICENSES.md) before
redistribution. Original work is MIT licensed, with a GPL-2.0-or-later
exception for the QEMU-derived layout module and preserved upstream notices.
See [third-party credits](THIRD_PARTY_NOTICES.md) and the
[public-release review](docs/PUBLIC-RELEASE-REVIEW.md).

## Maintainer

Maintained by **Satya Benson**. For questions, collaboration, or research
feedback, use [my contact page](https://satchlj.com/contact).

## Credits and project identity

This is an independent research project built on Asahi Linux’s m1n1 and
Apple Silicon reverse-engineering work. We thank the Asahi Linux contributors
for the bootloader, hypervisor, proxy tools, and public hardware documentation
that make this work possible. The layout work also builds on jprx/qemu-sptm.

This project is not affiliated with or endorsed by Asahi Linux, Apple, QEMU,
or Omarchy. Their names identify upstream work, references, and compatible
hardware/software; their logos are not this project’s branding. The source
release contains no logo assets. Locally built upstream m1n1 images still
include upstream artwork and are not covered by this source-release review.
