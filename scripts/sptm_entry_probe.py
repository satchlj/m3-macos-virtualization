#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
'Bounded SPTM instruction trace in isolated guest RAM; not a macOS boot loader.'

# Preserve the existing command path and public imports used by tools/tests.
from sptm_probe.constants import *
from sptm_probe.adapters import (
    PpermWindowLimit,
    TpidrGl2FastShadow, Gl1FastRedirect,
    Vel2StepFilter,
    audit_and_disable_tpidr_gl2_fast_shadow,
    phase53_hvc_gl1_counter_checks,
)
from sptm_probe.platform import *
from sptm_probe.runtime import run_probe, plan
from sptm_probe.cli import main

if __name__ == '__main__':
    main()
