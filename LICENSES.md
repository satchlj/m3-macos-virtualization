# Licensing and provenance

This repository does not vendor the m1n1 source tree. The lock files pin
[Asahi Linux m1n1](https://github.com/AsahiLinux/m1n1) revisions, and the files in
`patches/m1n1/` are intended to be applied to those exact revisions. Preserve the
upstream copyright, license, and notice files when building or redistributing a
patched tree. Several newly added patch files carry `SPDX-License-Identifier:
MIT`; that identifier does not override the license or notices of surrounding
upstream files.

Apple kernel, SPTM, TXM, firmware, device-tree, and installer payloads are not
included and are not licensed by this repository. Users must obtain and handle
their own inputs under applicable terms.

No project-wide license has yet been declared for unmarked original scripts,
tests, or documentation in this snapshot. Sharing the repository for technical
review is not a blanket permission to redistribute or incorporate those files.
Choose and add an explicit project-wide license before a public release.
