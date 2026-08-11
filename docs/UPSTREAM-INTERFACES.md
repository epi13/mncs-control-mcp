# Current MNCS upstream boundaries

These adapters were reviewed against the sibling sources present in `$HOME/Documents/Projects` during the developer-workspace refactor.

## Harness

`epi13-local-harness` 0.6.0 exposes `LocalAgent.run`, model inventory/routing sessions, policy-aware tools, and Fabric integration. MNCS Control currently reports Harness configuration and Fabric enablement but does not create a second agent loop. Direct Harness agent execution remains intentionally unexposed until its command/file tools can be placed under the same Bubblewrap boundary without weakening Harness policy semantics.

## Fabric

`mncs-fabric` 0.2.0a13 exposes the stable `FabricClient`, registry loading, worker observations, `build_manifest`, `validate_job_plan`, deterministic `build_bundle_archive`, and `execute`. MNCS Control now constructs these public artifacts for `pytest`, `python`, and `cargo_test` tasks and delegates worker selection, capability admission, native bundle transfer, execution, receipts, and reconciliation to Fabric.

The adapter does not turn a caller string into Fabric remote shell. Python scripts must exist in the selected artifact tree; pytest/cargo entrypoints are fixed task families. Fabric bundle limits and symlink rules remain authoritative. The optional MCP `model` field is reported but not used to invent model-placement semantics; Harness owns model routing.

## Forge

`mncs-forge-mcp` exposes a typed operation inventory and `DEFAULT_OPERATION_REGISTRY`. For a project with a validated `mncs-forge.toml`, `run_mncs_evaluation` constructs a development-mode `Forge` and invokes `development.checks.run`. Forge owns candidate, evidence, lifecycle, scoring, and claim boundaries.

## Commons

Commons remains transport-neutral and evidence-preserving. This MCP does not turn Commons content, reproduction instructions, or suggested actions into commands. Any future publication adapter must use Commons' public boundary and preserve PASS/FAIL/UNKNOWN distinctions.
