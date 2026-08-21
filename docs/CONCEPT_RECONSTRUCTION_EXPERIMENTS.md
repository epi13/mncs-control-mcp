# Concept Reconstruction Experiments in Control

Status: architecture proposal / non-normative

## Role

Control should own the durable lifecycle of a Concept Reconstruction Experiment (CRE), not the scientific meaning of the result and not the final evaluation verdict.

A CRE asks independent experimenters to reconstruct one fundamental computing concept required by the MNCS family using the semantics currently available in MNCS Language. The goal is not to transpile the current Forge, RAVEL, Fabric or other implementation. The current implementation is a source of invariants and comparison targets.

## Control-owned experiment identity

Durable experiments should grow an explicit producer-neutral Concept Experiment manifest containing at least:

- experiment ID and concept ID;
- governing RFC/contract references;
- target MNCS-family capability;
- language profile/compiler identity;
- hypothesis, falsifiers and protected properties;
- frozen and hidden inputs;
- resource/tool budgets;
- exact actors: worker, model, provider and Harness role;
- candidate/compiler/execution/evaluation reference sets;
- terminal coordination status;
- rerun/predecessor lineage.

This manifest is a coordination record. It does not mean the hypothesis was scientifically established.

## Bootstrap role set

Before RAVEL and MNEL are operational, Control MAY schedule ordinary Harness/Fabric models under explicit roles:

- `experimenter` or `builder` — constructs a candidate;
- `experiment-investigator` — critiques experiment design, evidence, falsifiers and competing explanations;
- `adaptive-experiment-critic` — proposes the next high-information intervention;
- `reviewer` or `skeptic` — challenges claims or attempts reproduction.

These role labels MUST NOT change producer identity. A model acting as `experiment-investigator` is not MNEL. A model acting as `adaptive-experiment-critic` is not RAVEL. Control should retain exact model/worker/provider/Harness provenance so future systems can compare themselves against these baseline controls.

## Lifecycle

A useful CRE lifecycle is:

```text
DRAFT
 -> FROZEN
 -> RUNNING
 -> OBSERVED
 -> EVALUATED
 -> ATTRIBUTION_PENDING | ATTRIBUTED | UNKNOWN
 -> RETAINED / SUPERSEDED / RERUN
```

Control may coordinate these states, but producer-native records remain authoritative for their own facts. Fabric owns execution observations, Language owns compiler/semantic records, Forge owns bounded evaluation results, MNCDS owns governed development history and MNCS owns assurance/conformance semantics.

## Failure as a durable output

Control should never discard a terminal study merely because the candidate failed. The experiment identity should retain failure references and allow the exact frozen experiment to be rerun after a language/compiler/verifier/tooling change.

Suggested classifications are recorded as observations rather than Control verdicts:

- implementation error;
- language expressivity gap;
- semantic-model gap;
- compiler/lowering gap;
- verifier gap;
- tooling/orchestration gap;
- target/portability gap;
- specification ambiguity;
- unresolved/insufficient evidence.

## Publication boundary

At terminal or important intermediate states, Control should be able to publish or expose an inert coordination record to Commons containing references to the exact producer-native artifacts. Publication must not copy large artifacts by default and must not reinterpret their statuses.

Recommended path:

```text
Control durable state
  -> Harness actor/tool provenance
  -> Fabric execution identities
  -> Language/Forge records
  -> Concept Experiment manifest
  -> controller-local Commons
```

An ingestion receipt from Commons is storage/delivery only.

## Authority rules

Control MUST NOT:

- turn Fabric execution success into experiment validity;
- turn a model critique into scientific attribution;
- turn Forge evaluation into MNCS conformance;
- claim RAVEL/MNEL identity for temporary model roles;
- silently change frozen inputs, evaluators, budgets or language profiles on a rerun.

If a rerun changes one of those dimensions, the change must be explicit in the descendant experiment record.

## First exercise

The first CRE should be deliberately small, such as reconstructing the MNCS `PASS`/`UNKNOWN`/`FAIL` lattice in the current MNCS Language profile. Multiple independent candidates can be compiled, run through Fabric, evaluated by Forge and retained as one addressable experiment family.
