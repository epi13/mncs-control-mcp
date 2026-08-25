# ADR 0001: Multi-step micro-model MCP control

- **Status:** Accepted
- **Date:** 2026-08-25

## Context

General-purpose models are often given large MCP catalogs containing many irrelevant tools, schemas, parameter descriptions, and examples. This increases token use and leaves a general model responsible for repeated low-entropy decisions such as tool-family routing, exact tool selection, argument extraction, and loop continuation.

MNCS already separates learned proposals from deterministic authority. Very small task-specific models can therefore reduce MCP orchestration cost without becoming trusted control-plane components.

## Decision

MNCS Control will support an additive multi-step MCP control architecture in which bounded learned providers may perform narrow semantic decisions before a larger model is invoked.

The intended sequence is:

```text
request
  -> deterministic preflight
  -> family routing
  -> candidate reduction
  -> exact tool selection
  -> constrained argument generation
  -> schema validation
  -> deterministic policy/approval gate
  -> execution
  -> result verification
  -> continuation, completion, or escalation
```

Each learned stage must expose abstention and must operate against a versioned schema/catalog identity. Control retains all authorization, approval, credential, trust, and execution-governance decisions.

The existing general-model MCP path remains the fallback and reference behavior while micro-model stages are introduced in shadow mode and earn bounded deployment through evidence.

## Consequences

- Control should compile authoritative MCP schemas into compact family/tool representations.
- Larger models should receive only the unresolved candidate subset rather than the full catalog whenever possible.
- Tool argument generation should use schema- or grammar-constrained decoding where feasible.
- Step-level records should preserve request, candidate, schema, provider, validation, execution, continuation, abstention, and escalation identities.
- Verified traces and operator corrections should be consumable by MNEL for training/calibration and by Forge for adversarial evaluation.
- Metrics should include false accepts, abstentions, schema validity, tool calls avoided, larger-model calls avoided, and tokens avoided.
- Fabric remains an execution and factual capability substrate; semantic MCP routing remains a Control/Harness policy concern.

See `docs/MICRO_MODEL_MCP_CONTROL.md` for the detailed design.