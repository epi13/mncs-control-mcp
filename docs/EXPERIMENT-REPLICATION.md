# Concept Experiment Replication

`experiment_replicate` closes the loop around one frozen MNCS Language Concept
Experiment realization:

```text
MNCS Language experiment (frozen by `experiment run`)
        |
        | verify exact identities through the language CLI itself
        v
Replication request  (experiment_replicate spec)
        |
        v
Control ReplicationManager  (durable on-disk coordinator, resume-safe)
        |
        v
MNCS Fabric  -- one exactly requested worker, no fallback
        execute the already-frozen backend artifact (never recompiled)
        |
        v
Fabric execution evidence  (admission, execution record, receipt,
                            FamilyExecutionReference with attempt lineage)
        |
        v
Language sealed replicated result  (`experiment inspect` re-verified locally)
        |
        v
Forge comparison / concept evaluation  (observation-only evidence)
        |
        v
Commons Family Record: `Replication`
```

## Operation surface

| Tool | Purpose |
| --- | --- |
| `experiment_replicate(spec)` | Start a durable replication; returns immediately after acceptance. |
| `replication_status(id)` | Inspect identities, Fabric evidence, Forge references, and Commons publication. Safe to call after reconnecting. |
| `replication_list()` | List attempts with coordination outcomes. |

Spec fields:

```json
{
  "baseline_result_path": ".../result.json",
  "backend_artifact_path": ".../backend-artifact.json",
  "corpus_path": ".../corpus.json",
  "worker_id": "fabric-worker-01",
  "concept_experiment_id": "mncs:concept:tri-state-result-lattice",
  "timeout_seconds": 300
}
```

The language binary is resolved from `[integration] language_binary`, defaulting
to the size-optimized `cargo build --profile fabric -p mncs-cli` output in the
configured `language` repository (fits Fabric's 8 MiB per-file bundle limit).

## Lifecycle and durability

States are persisted under `~/.local/state/mncs-control-mcp/replications/`:
`ACCEPTED → VERIFYING → PREPARING → EXECUTING → COLLECTING → COMPARING →
PUBLISHING → COMPLETED | FAILED`. A coordinator thread advances the state
machine; if the MCP client disconnects or the Control service restarts, the
startup resume scan respawns coordinators for non-terminal replications.
Starting an identical spec twice deduplicates to the first non-FAILED attempt.
One bounded re-dispatch is allowed for transient controller timeouts; it is
safe because Fabric derives a deterministic `execution_request_identity`, so a
repeat after a genuine execution returns `DUPLICATE_IDEMPOTENT` instead of
re-running.

## Identity binding

The coordinator records, directly or via typed producer references:

- `baseline_result_identity`, `definition_identity`, stage fingerprints
  (`semantic`/`hir`/`ssa`), realization-request and plan identities;
- `backend_identity`, `backend_artifact_identity`, corpus digest;
- Fabric requested/admitted worker, admission identity, disposition, execution
  record identity, receipt identity, and the `FamilyExecutionReference`
  stable id with attempt number;
- `replicated_result_identity` (re-verified locally through the language CLI);
- Forge baseline/replica record ids, comparison reference, and the
  `ConceptEvaluation` id;
- the Commons `Replication` record id and ingestion receipt digest.

## Fail-closed behavior

Before dispatch, the pipeline rejects (exit state `FAILED`, no outputs):

- baseline result whose identity chain does not re-verify (`LANGUAGE_IDENTITY_INVALID`);
- supplied artifact not exactly equal to the artifact embedded in the baseline
  result (`ARTIFACT_IDENTITY_MISMATCH`) — mutation after freezing is caught here;
- missing inputs (`REPLICATION_INPUT_MISSING`);
- unknown/unavailable worker (`FABRIC_WORKER_UNKNOWN`,
  `FABRIC_WORKER_UNAVAILABLE`) — **no fallback worker is ever selected**;
- capability mismatch (`FABRIC_WORKER_INCOMPATIBLE`).

After execution, the pipeline refuses `PASS` when:

- the worker envelope lacks evidence (`REPLICA_OUTPUT_MISSING`,
  `REPLICA_EVIDENCE_INCOMPLETE`) — outcome stays `UNKNOWN`;
- the returned result binds a different definition
  (`DEFINITION_IDENTITY_DIVERGENCE`) or fails local identity re-verification
  (`REPLICATED_IDENTITY_INVALID`);
- Forge comparison evidence is unavailable (`FORGE_COMPARISON_FAILED`,
  `FORGE_UNAVAILABLE`) — outcome stays `UNKNOWN`;
- Commons publication fails (`COMMONS_PUBLISH_FAILED`) — recorded honestly
  rather than claimed as published.

## Ownership boundaries

| Concern | Owner |
| --- | --- |
| Program semantics, experiment results, interpretation of executions | MNCS Language |
| Frozen-artifact transport, worker admission/placement, execution attempts, runtime facts, liveness/capability observations | MNCS Fabric |
| Worker/model/tool routing policy (not exercised here: no model inference occurs in a replication) | MNCS Harness |
| Orchestration lifecycle and durable state only | MNCS Control |
| Persisted language-owned records, comparisons, bounded evaluations | MNCS Forge |
| Durable family lineage, ingestion receipts (publication ≠ acceptance) | MNCS Commons |

A Fabric `EXECUTED` disposition means Fabric moved and executed identified
computation; it never means the program is correct. Forge evaluations remain
bounded development evidence, never MNCS conformance. The published Commons
record describes what happened; acceptance remains a separate lifecycle
decision.

## What this demonstrates — and what it does not

Demonstrated (2026-08, live environment):

- CRE-1 (tri-state lattice) frozen WASM and research-bytecode realizations
  replicated verbatim onto the explicitly requested remote Linux worker with
  full evidence chains and identical content-addressed result identities;
- deliberate artifact mutation rejected before dispatch;
- nonexistent-worker request rejected without fallback.

Not demonstrated:

- cross-host *behavioral divergence* detection (both backends are
  deterministic interpreters, so agreement is expected; native LLVM/C11
  backends would exercise toolchain sensitivity);
- attestation, protected custody, or independence of the executing host —
  none of these are claimed anywhere in the chain;
- Cranelift CRE execution (legitimately withheld upstream);
- universal compiler correctness or MNCS conformance.
