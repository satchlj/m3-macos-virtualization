# Project overview

[Repository home](../README.md) · [Current status](STATUS.md) · [Documentation index](README.md)

## What this repository is for

This project studies how macOS Tahoe's monitor and early kernel execution behave
on an Apple M3 using a modified m1n1 research hypervisor. It combines source
patches, host-side analysis tools, synthetic regression tests, and records of
bounded hardware experiments. It is not a Linux distribution, installer, or
working macOS virtual machine.

The latest recorded result is a kernel-driven allocation and page-table-frame
ownership transition. The corresponding runtime page-table descriptor mutation
and a complete operating-system boot remain unestablished. The authoritative
milestone list and its limits live in [STATUS.md](STATUS.md).

## How the pieces fit together

```text
Pinned upstream m1n1 revisions + separate patch series
                         |
              local research source trees
                         |
           host tools and experimental runtime
                         |
           recorded reports / event journals
                         |
       offline validation, summaries, and research notes

Synthetic fixtures -----------------> host regression tests
Private payloads and raw captures ---> local files, excluded from Git
```

The two upstream tracks have different purposes and cannot be interchanged:
`upstream.lock` pins the loader-validation track; `upstream-vel2.lock` pins the
experimental runtime track. Neither patch is a follow-on patch for the other
track. The [setup guide](../setup/README.md) describes the source layout.

## Reading the evidence

There are three different things to evaluate:

- **Source and tests:** available in this clone, with synthetic checks that a
  reader can run locally. Some tests also need the pinned upstream sources.
- **Written hardware findings:** included as bounded claims tied to attempt IDs
  and specific target/payload identities.
- **Raw hardware evidence and proprietary inputs:** retained outside Git. A
  fresh clone cannot independently replay every published finding.

A replay validates the host code's treatment of events; it does not emulate the
processor or prove the hardware claims. Read the [evidence labels](SAFETY.md)
before interpreting “verified,” “complete,” or an attempt's clean return.

## Terminology

| Term | Meaning in this repository |
| --- | --- |
| m1n1 | Asahi Linux's bootloader and Apple Silicon experimentation environment |
| XNU / BootKC | Apple's kernel / the boot kernel collection being studied |
| SPTM | Secure Page Table Monitor |
| TXM | Trusted Execution Monitor |
| EL1 / EL2 / vEL2 | Arm exception levels / the experimental virtual EL2 model |
| GXF / guarded world | Apple guarded-execution facilities discussed in the research notes |
| SPRR | Apple permission-register mechanisms used in the research model |
| ADT | Apple Device Tree, containing platform descriptions and boot metadata |
| VA / IPA / PA | Virtual / intermediate physical / physical address |
| Stage 1 / Stage 2 | Guest address translation / hypervisor address translation |
| Retype | A frame-ownership/type transition; not by itself a page-table update |
| Attempt / run bundle | One recorded experiment / its reports, manifest, and events |
| Gate | A prerequisite check; passing one is not a general readiness claim |
| J613 / T8122 | Board / SoC identifiers for the observed M3 environment |

## Choose a next step

- Understand the result: [current status](STATUS.md), then its linked evidence.
- Explore the code: [script map](../scripts/README.md) and [code review](CODE-REVIEW.md).
- Run checks without a target: [test guide](../tests/README.md).
- Trace a historical claim: [complete documentation index](README.md).
- Contribute: [contributor guide](../CONTRIBUTING.md).
