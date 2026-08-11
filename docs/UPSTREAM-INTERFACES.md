# Upstream interface notes

The first implementation was designed against the sibling repositories present in the MNCS Projects directory.

## Harness

`epi13-local-harness` provides `load_config`, `FabricSession`, and `InventoryAwareFabricSession`. The control project uses Harness as an optional import for configuration/library status and leaves model execution to Harness. It does not instantiate a second agent loop.

## Fabric

`mncs-fabric` exposes `FabricClient`, `load_registry`, and `workers()`. `fabric_status` uses this public API and projects only bounded worker information. Fabric remains authoritative for node discovery, capabilities, routing, and remote execution.

The current public execution API requires a validated job plan, artifact manifest, and (for remote work) an execution bundle. The control boundary therefore returns `not_supported_yet` for generic `dispatch_fabric_job` rather than accepting a command string or fabricating an incomplete plan.

## Forge

`mncs-forge-mcp` exposes a typed operation registry and `Forge` facade. When an approved repository contains a Forge config and the requested case study is a configured workflow, `run_mncs_evaluation` invokes the existing development-check operation. Otherwise it reports the missing capability without duplicating evaluation logic.

## Commons

Commons is not directly mutated by this first control surface. Future evidence publication should use Commons' existing application/MCP boundaries and preserve its distinction between delivery, verification, and acceptance.
