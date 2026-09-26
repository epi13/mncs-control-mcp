# ADR 0002: Thin MCP boundary and upstream pressures

- **Status:** Accepted
- **Date:** 2026-09-26

## Context

`mncs-control-mcp` historically compensated for missing project infrastructure:
a private workflow runner (`run_workflow`/`control_run`), a laboratory status
plane, a publication retry state machine (`PUBLISHING`/`RETRY_PENDING`/
`SYNC_REQUIRED`), and a readiness verdict delegated to an imported Harness
readiness contract (`evaluate_layers`, `inspect_live_config`). The catch-up
campaign thinned all four back to typed MCP exposure over canonical
capabilities. Thinning surfaces gaps Control cannot close without touching
repos outside its ownership boundary.

## Decision

Control keeps only what it can verify itself:

- `experiment_publish` is single-shot and idempotent by record identity; the
  Commons operator owns delivery retry internally.
- `experiment_readiness` projects adapter status plus a write probe against
  Control's own experiment store, with a stated verdict rule
  (BLOCKED if a required layer is BLOCKED, DEGRADED if a required layer is
  not READY, else READY). It never judges worker, model, routing, Commons,
  or Fabric classification.
- There is no generic workflow runner; multi-step work composes typed tools.
- `file_patch` stays a thin validate-and-apply capability over workspace
  files (policy-checked headers, `git apply --check` then apply).
- `specialist_route_shadow` stays observation-only; policy remains
  authoritative and nothing is executed.

## Upstream pressures (recorded, not acted on)

1. **mncs-harness — readiness contract boundary.** Control previously imported
   `epi13_local_harness.experiment_readiness` to render its verdict. Harness
   should declare whether those helpers are a public reusable contract or
   internal implementation, so future consumers do not re-couple to them.
2. **mncs-commons — publish retry/idempotency semantics.** Thin clients now
   assume `publish_record` is safe to retry with a re-derived record and that
   the operator owns delivery retry. The operator boundary should document
   that contract explicitly.
3. **Removed tool migration.** `laboratory_status`, `control_run` /
   `run_workflow`, `control_reload`, `terminal_jobs`, `run_tests`,
   `job_status` / `job_result` are gone. Any active agents, scripts, or docs
   outside this repo still calling them must migrate to `fabric_status` /
   `control_capabilities` and the individual typed tools.
