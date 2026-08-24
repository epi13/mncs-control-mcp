from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

_EXPERIMENT_TOOLS = {
    "experiment_readiness",
    "experiment_start",
    "experiment_status",
    "experiment_result",
    "experiment_list",
    "experiment_stop",
    "experiment_attach_reference",
    "experiment_publish",
    "experiment_rerun",
    "experiment_graph",
    "experiment_replicate",
    "replication_status",
    "replication_list",
}

_JOURNAL_CONTEXT_TOOLS = {
    "journal_context_status",
    "journal_context_collect",
    "journal_context_get",
}


def tool_surface_manifest(names: Iterable[str]) -> dict[str, Any]:
    """Return a stable non-secret identity for the advertised MCP tool-name surface."""

    ordered = sorted({str(name) for name in names if name})
    digest = hashlib.sha256(("\n".join(ordered) + "\n").encode("utf-8")).hexdigest()
    return {
        "schema": "mncs-control.tool-surface.v0.1",
        "tool_count": len(ordered),
        "tool_names_sha256": f"sha256:{digest}",
        "experiment_tools_present": _EXPERIMENT_TOOLS <= set(ordered),
        "journal_context_tools_present": _JOURNAL_CONTEXT_TOOLS <= set(ordered),
    }
