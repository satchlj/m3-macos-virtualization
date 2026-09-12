# Automated probe pipeline

`run_probe_pipeline.py --config CONFIG.json --output NEW_DIRECTORY --execute`
runs one bounded probe, captures post-stop diagnostics and table pages when
the guest returned cleanly, then publishes a gzip-level-1 transfer archive and
SHA-256/size identity sidecar. The archive retains failed attempt evidence too;
its pipeline status and exit code distinguish failure. Without `--execute`,
only offline layout validation runs.

Configuration fields are explicit: `payload`, `checkout`, `device`, `steps`,
`step_batch`, `trace_window`, `allow_monitor_mmu`, `emulate_zero_loops`,
`relocate_boot_data`, `allow_live_ttbr`, `stop_on_vector_entry`
([vector-visit stop](guest-exception-stop.md)), `pause_on_guard` and integer
`pause_timeout` ([guarded continuation](guarded-pause.md)), `observe_sprr`
([observation-only SPRR](sprr-observation.md)) , `virtual_gxf` and
`stage_el2_config` ([virtual guarded world](virtual-guarded-world.md)). Boolean flags and bounded
budgets (at most 33,554,432 steps) are validated before execution. The output directory must be new. Paths should be
absolute on the USB host, with its development environment activated.

The optional `xnu_tpidr_gl2_fast_shadow` Boolean maps to
`--xnu-tpidr-gl2-fast-shadow`, requires `xnu_run`, and is fail-closed against
the pinned firmware proxy API. Its exact post-prefix activation gate, status
counters, teardown behavior, and limits are documented in the
[TPIDR_GL2 fast-shadow runbook](launch-prep/xnu-tpidr-gl2-fast-shadow.md).

Cooperating pipeline processes take a device-specific local advisory lock
through probe and diagnostics, then release it before compression. Standalone
legacy scripts do not honor this lock: keep one physical device owner.
The pipeline does not install or chainload a runtime. A verified running image
and appropriate fresh-boot gate remain prerequisites.

Output contains `config.json`, `pipeline.json`, console and diagnostic logs,
the usual immutable `runs/RUN_ID` bundle, and optional diagnostics/tables.
The sibling `NEW_DIRECTORY.tar.gz` is renamed into place only after closure;
`NEW_DIRECTORY.tar.gz.identity.json` records its digest and byte size.
Bulk artifacts remain ignored and are retained on analysis host after transfer.
On analysis host, register a downloaded archive with the
[verified pipeline importer](pipeline-import.md).
