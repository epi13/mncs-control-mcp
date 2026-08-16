# Durable MNCS experiments

Long-running multi-model experiments must not be owned by `terminal_start` or any other sandbox process whose lifetime is bounded by an MCP command. The protected terminal is a development execution surface, not a durable experiment scheduler.

MNCS Control now exposes a durable experiment coordinator through `experiment_start`, `experiment_status`, `experiment_result`, `experiment_list`, and `experiment_stop`.

## Ownership

The authority split is explicit:

- **MNCS Control** owns only experiment lifecycle, durable turn state, handoff ordering, restart/recovery, and the client-facing experiment identity.
- **MNCS Harness** owns exact model/worker resolution and the model-facing invocation contract.
- **MNCS Fabric** owns every detached execution, worker placement evidence, execution record, and receipt.
- **MNCS Commons** grants no execution authority. Experiment output may later be deliberately promoted through the normal Commons knowledge lifecycle, but successful experiment execution is not Commons acceptance.

The coordinator runs in the Control MCP service process, not inside the bwrap terminal sandbox. State is written beneath the existing private Control state directory at `~/.local/state/mncs-control-mcp/experiments/`. On Control server startup, non-terminal experiments are discovered and resumed.

A resumed turn never blindly submits again. If durable state already contains a Fabric `work_id`, Control reconnects to that work. If the process stopped after creating a `PREPARING` turn but before persisting the returned work identity, the deterministic idempotency key `<experiment-id>:turn:<n>` causes Fabric detached submission to reconcile the duplicate request to the same work identity.

## Starting an experiment

`experiment_start` accepts a bounded object such as:

```json
{
  "goal": "Determine whether heterogeneous model critique improves an MNCS protocol under equal constraints.",
  "actors": [
    {"name": "planner", "worker": "collamore02-windows", "model": "gemma4:e4b"},
    {"name": "critic", "worker": "fabric-worker-01", "model": "granite3.3:2b"}
  ],
  "stages": [
    "Propose one falsifiable design and its failure condition.",
    "Attack the prior handoff and preserve any unresolved disagreement.",
    "Turn the surviving claim into a controlled experiment with measurable evidence."
  ],
  "duration_seconds": 3600,
  "max_turns": 48,
  "max_turn_wait_seconds": 900,
  "stop_on_turn_failure": true
}
```

`experiment_start` first requires the Harness-owned `multi-agent` readiness profile to be `READY`. It then returns immediately after Control has persisted the experiment and started its coordinator. The initiating ChatGPT/MCP client may disconnect.

`experiment_status` reports the durable state and current detached Fabric turn. `experiment_result` returns retained turn outputs and the Fabric evidence references captured for each completed turn. `experiment_list` is bounded to the most recent 100 experiment records.

`experiment_stop` stops the **coordinator** from starting further work. If a turn is already detached, Control explicitly records that the Fabric work may continue independently; it does not pretend to have cancelled an upstream execution when Fabric has not exposed cancellation authority.

## Failure and recovery semantics

Coordinator/runtime exceptions are retained as `last_coordinator_error` and retried with bounded backoff until the experiment deadline. Transient Fabric status failures are retained on the current turn and retried. A turn that exceeds `max_turn_wait_seconds` is recorded as failed, with an explicit warning that the detached Fabric work may still finish later.

Model outputs are untrusted experimental material. The coordinator prompt reinforces that Fabric execution success is provenance, not proof of correctness. Failures, uncertainty, disagreement, and missing handoffs remain evidence rather than being converted into successful results.

## Why the Fabric scheduled queue is not used as the coordinator

Fabric's current scheduled-work queue is an availability/admission plane. A schedule tick can select an eligible worker and mark a queued item dispatched, but the current controller path does not carry a chained semantic workflow or automatically feed one model's output into the next model's prompt. Treating that queue as a multi-turn experiment engine would overstate its present contract.

The durable Control coordinator therefore delegates each turn to Fabric's already-supported detached execution API while leaving Fabric semantic-agnostic.
