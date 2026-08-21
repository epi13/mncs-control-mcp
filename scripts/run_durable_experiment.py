"""Start a Control durable experiment from the current source tree.

Used when the connected MCP stdio process cannot reload. The coordinator is
still MNCS Control's ExperimentManager and writes the same durable state.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "mncs-harness" / "src"))
sys.path.insert(0, str(ROOT.parent / "mncs-fabric" / "src"))
sys.path.insert(0, str(ROOT.parent / "MNCS-Commons" / "src"))

from mncs_control_mcp.config import load_config  # noqa: E402
from mncs_control_mcp.experiments import ExperimentManager  # noqa: E402

TERMINAL = {"COMPLETED", "FAILED", "STOPPED"}


def main() -> int:
    spec_path = Path(sys.argv[1]).expanduser().resolve()
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    config = load_config(ROOT / "control.toml")
    manager = ExperimentManager(config, resume=False)
    accepted = manager.start(spec)
    experiment_id = accepted["experiment_id"]
    print(json.dumps(accepted, indent=2, sort_keys=True), flush=True)
    while True:
        status = manager.status(experiment_id)
        print(
            json.dumps(
                {
                    "experiment_id": experiment_id,
                    "state": status.get("recorded_state") or status.get("state"),
                    "successful_turns": status.get("successful_turns"),
                    "failed_turns": status.get("failed_turns"),
                    "current_turn": status.get("current_turn"),
                    "last_coordinator_error": status.get("last_coordinator_error"),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        if str(status.get("recorded_state") or status.get("state")) in TERMINAL:
            print(json.dumps(manager.result(experiment_id), indent=2, sort_keys=True)[:20000], flush=True)
            return 0 if str(status.get("recorded_state")) == "COMPLETED" else 1
        time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
