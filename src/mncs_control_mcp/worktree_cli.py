"""Provider-owned worktree selection for Environment campaign sessions.

The MCP surface and this bounded JSON CLI share ``GitService`` semantics.
Environment is the composition boundary; Git/worktree decisions remain in
Control.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.git_adapter import GitService
from mncs_control_mcp.workspace import WorkspacePolicy


def prepare(workspace_root: Path, requests: list[dict[str, Any]]) -> dict[str, Any]:
    root = workspace_root.expanduser().resolve()
    config = ControlConfig(workspace_root=root, require_real_sandbox=False)
    policy = WorkspacePolicy(config)
    # Worktree administration is implemented by GitService's provider-owned
    # host operation and does not use the content sandbox.
    git = GitService(config, policy, sandbox=None)  # type: ignore[arg-type]
    selected = []
    for request in requests:
        if not isinstance(request, dict):
            raise ValueError("each worktree request must be an object")
        selected.append(
            git.worktree_prepare(
                str(request["repository"]),
                name=str(request["name"]),
                branch=str(request["branch"]),
                source_ref=str(request.get("source_ref", "origin/main")),
            )
        )
    return {"workspace_root": str(root), "selected_checkouts": selected}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mncs-control-worktrees")
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--workspace-root", required=True, type=Path)
    prepare_parser.add_argument("--requests-json", required=True)
    args = parser.parse_args(argv)
    try:
        requests = json.loads(args.requests_json)
        if not isinstance(requests, list):
            raise ValueError("requests-json must contain an array")
        result = prepare(args.workspace_root, requests)
    except Exception as error:
        print(json.dumps({"error": type(error).__name__, "message": str(error)}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
