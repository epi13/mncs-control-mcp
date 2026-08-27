# Micro-model MCP control

MNCS Control should minimize the amount of tool-catalog and orchestration context that reaches general-purpose models. Repeated MCP control decisions are candidates for very small, task-specific learned models operating under deterministic policy, schema validation, and explicit escalation.

This document defines a multi-step MCP control pipeline in which learned components propose bounded routing and argument decisions while Control retains authority.

## Goal

Replace the common pattern:

```text
request
  -> large model sees entire MCP catalog
  -> large model chooses tool and arguments
  -> execute
```

with a staged pipeline:

```text
request
  -> deterministic preflight
  -> micro-model tool-family router
  -> bounded candidate tool set
  -> micro-model tool selector
  -> constrained argument generator
  -> schema validator
  -> deterministic Control policy gate
  -> execution
  -> deterministic/result verifier
  -> accept or escalate
```

The larger model becomes an escalation target for ambiguity rather than the default mechanism for every MCP decision.

## Multi-step learned control

Control may use multiple independently bounded micro-models rather than one model that owns the whole tool loop.

Recommended roles include:

1. **Intent / family router** — selects one or more MCP families or control lanes from a bounded catalog.
2. **Candidate reducer** — narrows a large function catalog to a small set of plausible tools.
3. **Tool selector** — chooses a specific tool or abstains.
4. **Argument extractor** — maps request/context into typed arguments under a compiled schema or grammar.
5. **Continuation classifier** — after tool results, decides whether the task is complete, another bounded tool step is appropriate, or escalation is required.
6. **Result-risk classifier** — detects novelty, missing evidence, contradiction, or high-risk outcomes that require a stronger model or operator review.

Each step has a narrow output contract and an independent abstention path.

## Token firewall

The primary efficiency objective is to avoid sending irrelevant MCP schemas and state to larger models.

A request should expose only the minimum context necessary at each stage. For example:

```text
full MCP registry
  -> family router sees compact family descriptors
  -> candidate reducer sees compact tool signatures
  -> selector sees only candidate signatures
  -> argument model sees only the selected schema
  -> larger model, if needed, sees only the unresolved subset
```

Control should record prompt/schema tokens avoided and larger-model invocations avoided so the value of the routing stack can be measured directly.

## Constrained tool calls

When a tool schema can be represented as a grammar, enum, typed contract, or MNCS-language schema, argument generation should be constrained so that invalid tool names, unknown keys, and structurally invalid calls cannot be emitted.

A learned tool decision is not executable until it passes:

- exact tool identity resolution;
- schema/grammar validation;
- argument bounds and enum validation;
- Control permission policy;
- workspace/target policy where applicable;
- any required human approval.

Tool-call syntax correctness should be guaranteed structurally where possible rather than inferred from model reliability.

## Abstention and escalation

Every learned MCP stage must support abstention. Typical escalation triggers include:

- confidence below calibrated threshold;
- multiple near-equal tool candidates;
- unseen or changed schema identity;
- required argument missing from available context;
- request spans multiple authority domains;
- destructive or approval-gated operation;
- unexpected tool result;
- contradiction between tool output and current state;
- repeated loop without measurable progress.

Escalation may target a larger local specialist, a general model, or an operator depending on policy.

## Authority boundary

Micro-models may propose semantic choices. They do not own:

- permissions;
- destructive-action authorization;
- credential access;
- worker or transport trust;
- policy bypass;
- evidence acceptance;
- conformance or custody decisions.

Control remains responsible for authorization and tool-loop governance. Fabric remains an execution substrate and factual capability source; it does not become the semantic router.

## Catalog compilation

Control should maintain a compact, versioned representation of MCP catalogs suitable for micro-model use. A compiled catalog should preserve at least:

- tool family identity;
- exact tool identity;
- short semantic purpose;
- side-effect class;
- required approvals;
- argument names and types;
- enum/range constraints;
- schema identity/version;
- connector/provider identity;
- availability state.

The compiled representation should be derived from authoritative schemas and invalidated when those schemas change.

## Multi-step state

The MCP control stack should keep explicit machine-readable state rather than forcing each model call to reconstruct the interaction from prose history. A control-step record should be able to bind:

- request identity;
- current step number;
- selected family/candidates/tool;
- schema identity;
- generated arguments;
- validation outcome;
- authorization outcome;
- execution receipt/result identity;
- continuation decision;
- abstention/escalation reason;
- model/provider identity and calibration version.

This permits replay, evaluation, rollback analysis, and MNEL/Forge training without preserving unnecessary conversational text.

## Learning loop

Successful verified tool traces can become training material for task-specific Control providers:

```text
verified MCP traces
  -> task-family clustering
  -> compact supervised examples
  -> MNEL training/calibration
  -> shadow routing
  -> Forge adversarial evaluation
  -> bounded Control deployment
```

Failed traces, abstentions, schema changes, and operator corrections are equally important training evidence.

## Metrics

Control should track at least:

- exact tool-selection accuracy;
- false-accept rate;
- abstention rate;
- schema-valid-call rate;
- argument accuracy;
- tool-loop steps per completed task;
- unnecessary tool calls avoided;
- larger-model calls avoided;
- prompt/schema tokens avoided;
- p50/p95 routing latency;
- escalation correctness;
- regressions after catalog/schema changes.

Optimization should prefer lower false acceptance and clean escalation over maximum autonomous completion.

## Implementation direction

An incremental implementation can proceed without replacing the existing MCP path:

1. compile existing tool schemas into a compact Control catalog;
2. add deterministic candidate reduction baselines;
3. define provider interfaces for family routing, tool selection, argument extraction, continuation, and risk classification;
4. run learned providers in shadow mode against existing decisions;
5. record step-level evidence and token savings;
6. enable direct micro-model routing only for calibrated operating envelopes;
7. keep existing large-model routing as the explicit fallback.

This architecture is intentionally additive. Existing MCP behavior remains the safety fallback while bounded learned control earns narrower authority through evidence.

## Executable first slice

Control exposes `specialist_route_shadow` as a bounded, destructive-capable sandbox
operation because its declared provider command is external code. The provider receives
one compact feature vector and a versioned catalog, while the returned observation
records exact-family agreement, candidate-set recall, false accepts, abstention and
escalation correctness, schema validity, catalog bytes/tokens avoided, larger-model
calls avoided, and p50/p95 latency fields. The existing policy decision is retained as
the fallback and remains authoritative; the specialist cannot authorize or execute a
tool. Missing configuration, stale/malformed responses, schema drift, timeout, or
budget violations fail closed to `UNKNOWN`.
