#!/usr/bin/env python3
"""End-to-end MNCS Concept Experiment replication demonstration.

Drives the real vertical slice against the live local infrastructure:

    MNCS Language (frozen CRE-1 realization)
      -> Control ReplicationManager (durable orchestration)
        -> Fabric exact-target execution on one explicitly requested worker
          -> replicated sealed experiment result
            -> Forge record + comparison + concept evaluation
              -> Commons Replication Family Record

Also demonstrates two deliberately broken replications and where the
pipeline catches them.

Usage:
    python scripts/run_replication_demo.py [--config control.toml] [--keep]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

CONTROL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONTROL_ROOT / "src"))

from mncs_control_mcp.adapters import IntegrationBundle  # noqa: E402
from mncs_control_mcp.config import load_config  # noqa: E402
from mncs_control_mcp.replication import ReplicationManager  # noqa: E402
from mncs_control_mcp.sandbox import Sandbox  # noqa: E402
from mncs_control_mcp.workspace import WorkspacePolicy  # noqa: E402

LANGUAGE_EXAMPLES = Path(__file__).resolve().parents[2] / "mncs-language" / "examples"
CRE1_SOURCE = LANGUAGE_EXAMPLES / "source" / "cre1-evidence-combine.mncs"
CRE1_CORPUS = LANGUAGE_EXAMPLES / "execution" / "cre1-evidence-corpus.json"


def prepare_baselines(binary: Path, demo_root: Path) -> dict[str, Path]:
    """Freeze one Concept Experiment realization per backend via `experiment run`."""
    baselines = {}
    for backend, name in (
        ("mncs-portable-wasm-mvp", "wasm"),
        ("mncs-research-bytecode", "bytecode"),
    ):
        out = demo_root / f"baseline-{name}"
        completed = subprocess.run(
            [
                str(binary),
                "experiment",
                "run",
                str(CRE1_SOURCE),
                "--backend",
                backend,
                "--corpus",
                str(CRE1_CORPUS),
                "--output-dir",
                str(out),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if not out.joinpath("result.json").is_file():
            raise SystemExit(f"baseline run failed for {backend}: {completed.stderr[-2000:]}")
        # The frozen corpus is an explicit replication input; keep it beside the
        # other realization artifacts for exact binding.
        (out / "corpus.json").write_bytes(CRE1_CORPUS.read_bytes())
        baselines[name] = out
    return baselines


def run_replication(
    manager: ReplicationManager,
    spec: dict,
    *,
    label: str,
) -> dict:
    started = manager.start(spec)
    replication_id = started["replication_id"]
    deadline = time.time() + 600
    state = manager._load(replication_id)
    while state["state"] not in {"COMPLETED", "FAILED"} and time.time() < deadline:
        time.sleep(2.0)
        state = manager._load(replication_id)
    print(f"\n=== {label}: replication {replication_id} -> {state['state']} ===")
    print(json.dumps(manager.status(replication_id), indent=2, sort_keys=True)[:4000])
    return state


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(CONTROL_ROOT / "control.toml"))
    parser.add_argument("--worker", default="fabric-worker-01")
    parser.add_argument("--demo-root", default="/tmp/opencode/mncs-replication-demo")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)
    binary = config.resolved_language_binary
    if not binary.is_file():
        raise SystemExit(
            f"language binary missing at {binary}; build with "
            "`cargo build --profile fabric -p mncs-cli` in mncs-language"
        )
    import shutil

    demo_root = Path(args.demo_root)
    if demo_root.exists() and not args.keep:
        shutil.rmtree(demo_root)
    demo_root.mkdir(parents=True, exist_ok=True)
    replications_root = Path.home() / ".local/state/mncs-control-mcp/replications"
    if replications_root.exists() and not args.keep:
        shutil.rmtree(replications_root)

    print("== Freezing CRE-1 baseline realizations through the language CLI ==")
    baselines = prepare_baselines(binary, demo_root)
    for name, directory in baselines.items():
        result = json.loads(directory.joinpath("result.json").read_text())
        print(
            f"  {name}: result={result['identity'][:58]}... status={result['status']} "
            f"artifact={result['artifact']['identity'][:52]}..."
        )

    policy = WorkspacePolicy(config)
    sandbox = Sandbox(config, policy)
    integrations = IntegrationBundle(config, None, policy, sandbox)
    manager = ReplicationManager(
        config,
        fabric=integrations.fabric,
        forge=integrations.forge,
        commons=integrations.commons,
        resume=False,
    )

    results: dict[str, dict] = {}

    # --- Real cross-worker replications of the same frozen experiment --------
    for name in ("wasm", "bytecode"):
        base = baselines[name]
        spec = {
            "baseline_result_path": str(base / "result.json"),
            "backend_artifact_path": str(base / "backend-artifact.json"),
            "corpus_path": str(base / "corpus.json"),
            "worker_id": args.worker,
            "concept_experiment_id": "mncs:concept:tri-state-result-lattice",
            "timeout_seconds": 420,
        }
        results[f"replica-{name}"] = run_replication(
            manager, spec, label=f"frozen CRE-1 realization ({name})"
        )

    # --- Broken replication 1: mutated frozen artifact -----------------------
    broken_base = demo_root / "broken-artifact"
    broken_base.mkdir(parents=True, exist_ok=True)
    for filename in ("result.json", "backend-artifact.json"):
        (broken_base / filename).write_bytes(
            (baselines["wasm"] / filename).read_bytes()
        )
    artifact = json.loads((broken_base / "backend-artifact.json").read_text())
    raw = bytearray(bytes.fromhex(artifact["bytes_hex"]))
    raw[len(raw) // 2] ^= 0x01  # flip one bit of the frozen module body
    artifact["bytes_hex"] = bytes(raw).hex()
    (broken_base / "backend-artifact.json").write_text(json.dumps(artifact))
    results["broken-mutated-artifact"] = run_replication(
        manager,
        {
            "baseline_result_path": str(broken_base / "result.json"),
            "backend_artifact_path": str(broken_base / "backend-artifact.json"),
            "corpus_path": str(CRE1_CORPUS),
            "worker_id": args.worker,
        },
        label="BROKEN: mutated frozen artifact",
    )

    # --- Broken replication 2: unavailable worker (no fallback allowed) -----
    results["broken-unavailable-worker"] = run_replication(
        manager,
        {
            "baseline_result_path": str(baselines["wasm"] / "result.json"),
            "backend_artifact_path": str(baselines["wasm"] / "backend-artifact.json"),
            "corpus_path": str(CRE1_CORPUS),
            "worker_id": "nonexistent-worker",
        },
        label="BROKEN: nonexistent worker (must not fall back)",
    )

    print("\n================ REPLICATION DEMONSTRATION SUMMARY ================")
    for key, state in results.items():
        identities = state.get("identities") or {}
        fabric = state.get("fabric") or {}
        forge = state.get("forge") or {}
        commons = state.get("commons") or {}
        summary = state.get("status_summary") or {}
        print(f"\n[{key}] {state['state']} outcome={state.get('outcome')}")
        if state.get("error"):
            print(f"  error: {state['error']['code']}")
        print(f"  language baseline : {identities.get('baseline_result_identity')}")
        print(f"  definition        : {identities.get('definition_identity')}")
        print(f"  backend           : {identities.get('backend_identity')}")
        print(f"  frozen artifact   : {identities.get('backend_artifact_identity')}")
        print(f"  worker requested  : {fabric.get('requested_worker')}")
        print(f"  worker admitted   : {fabric.get('admitted_worker')}")
        print(f"  disposition       : {fabric.get('disposition')}")
        fref = fabric.get("family_execution_reference") or {}
        if isinstance(fref, dict):
            print(f"  fabric execution  : {fref.get('stable_id')}")
        print(f"  replica result    : {identities.get('replicated_result_identity')}")
        print(
            f"  behavior agrees   : {summary.get('bounded_behavior_agrees')} "
            f"(language status {summary.get('language_status')})"
        )
        print(f"  forge comparison  : {forge.get('comparison_reference')}")
        print(f"  forge evaluation  : {forge.get('concept_evaluation_id')}")
        publication = commons.get("publication") or {}
        print(f"  commons record    : {commons.get('replication_record_id')}")
        print(
            f"  commons receipt   : {publication.get('deliveryStatus')} "
            f"{str(publication.get('contentDigest'))[:30]} acceptance={publication.get('acceptanceStatus')}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
