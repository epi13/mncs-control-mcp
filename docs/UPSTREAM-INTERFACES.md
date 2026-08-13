# Current MNCS upstream boundaries

These adapters were reviewed against the sibling sources present in `$HOME/Documents/Projects` during the developer-workspace refactor.

## Harness

`epi13-local-harness` 0.6.1 exposes `LocalAgent.run`, model inventory/routing sessions, policy-aware tools, and Fabric integration. MNCS Control reports the configured provider/model roles, router mode, policy approval mode, Fabric enablement, and configured worker count. It does not create a second agent loop. Direct Harness agent execution remains intentionally unexposed until its command/file tools can be placed under the same Bubblewrap boundary without weakening Harness policy semantics.

## Fabric

`mncs-fabric` 0.2.0a15 is the persistent fleet and controller authority. It
owns durable lifecycle/membership state, the foreground controller runtime,
worker presence, the consumer AF_UNIX socket, and the separate local operator
socket. Ordinary consumers use `FabricClient.connect()`; `FabricAdminClient`
is reserved for local operator code and is not used by MNCS Control.

The current public consumer boundary supports controller and fleet reads through
`controller_status()`, `fleet()`, `fleet_status()`, and `workers()`. The
controller's public status projection advertises each persistent-service
capability independently. When the controller is configured with its
operator-owned authenticated worker endpoint registry, it also advertises
controller-managed service execution, worker observations, and capability
ingestion. `FabricClient.connect()` dispatches through that service path; it
does not load the registry or worker credentials into Control. Authenticated
worker-initiated rendezvous is another controller-owned backend and can project
the same public service features when configured. If the connected controller does not advertise execution,
Control reports `FABRIC_SERVICE_EXECUTION_UNSUPPORTED` rather than creating an
embedded execution client. `transitional` mode may use a separately marked
embedded-direct compatibility client for bounded execution while persistent
Fabric remains fleet authority. This path is temporary and does not grant
Control the admin socket.

The `embedded` mode remains for isolated tests and deployments. Only that
explicit compatibility mode prepares/loads the legacy worker registry and
trust references. Service mode never copies `workers.json`, trust state,
certificates, or private keys into Control state.

The service status response is controller-owned and includes `fabric_version`,
`service_contract`, and `public_contract_identity`. Consumers report that
identity separately from their locally imported Fabric client version.

The adapter does not turn a caller string into Fabric remote shell. Python scripts must exist in the selected artifact tree; pytest/cargo entrypoints are fixed task families. Fabric bundle limits and symlink rules remain authoritative. The optional MCP `model` field is reported but not used to invent model-placement semantics; Harness owns model routing.

## Forge

`mncs-forge-mcp` exposes a typed operation inventory and `DEFAULT_OPERATION_REGISTRY`. Control
uses the repository's canonical Forge MCP entry point for a real stdio initialize, tools/list,
and harmless `mncs_forge_project_inspect` health probe. `forge.status` reports explicit
configuration, reachability, protocol, version, and capability state. For a project with a
validated `mncs-forge.toml`, `run_mncs_evaluation` still constructs a development-mode `Forge`
and invokes `development.checks.run` through that same public typed registry; it does not copy
Forge implementation into Control or create a second evaluator. Forge owns candidate, evidence,
lifecycle, scoring, and claim boundaries.

## Commons

Commons remains transport-neutral and evidence-preserving. Control uses the
persistent local service's public consumer client and socket, not a Harness CLI
subprocess or direct store access. Its fixed adapter exposes only status, work,
query, get, conversation, evidence, and sync. The consumer client has no publish
or recovery method; those operations remain on Commons' separate operator
boundary. Commons content, reproduction instructions, and suggested actions are
returned as untrusted inert data and never become commands.

## Control-plane ownership

`control_capabilities`, `project_review`, `laboratory_status`, and `control_run`
are planning/orchestration views. They aggregate adapter results but do not
replace upstream routing, model selection, evaluation, evidence, or Commons
protocol semantics. `control_jobs` records upstream execution summaries without
claiming local process ownership.
