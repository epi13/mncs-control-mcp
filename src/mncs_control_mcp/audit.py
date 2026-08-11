from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .security import redact_text


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self._lock = threading.Lock()

    def record(self, tool: str, **metadata: Any) -> None:
        event = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "tool": tool,
            **self._sanitize(metadata),
        }
        encoded = json.dumps(event, ensure_ascii=False, sort_keys=True, default=str)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(encoded + "\n")

    def _sanitize(self, value: Any) -> Any:
        if isinstance(value, str):
            return redact_text(value[:8192])
        if isinstance(value, dict):
            return {str(k)[:128]: self._sanitize(v) for k, v in list(value.items())[:128]}
        if isinstance(value, (list, tuple)):
            return [self._sanitize(item) for item in value[:128]]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return redact_text(str(value)[:1024])

    def summary(self, limit: int = 50) -> dict[str, object]:
        """Return aggregate recent metadata without exposing raw audit records."""
        if limit < 1 or limit > 200:
            limit = 50
        counts: dict[str, int] = {}
        failures = 0
        recent: list[dict[str, object]] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
        except OSError:
            lines = []
        for line in lines:
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            tool = str(record.get("tool", "unknown"))
            counts[tool] = counts.get(tool, 0) + 1
            if record.get("success") is False:
                failures += 1
            recent.append({key: record.get(key) for key in ("timestamp", "tool", "success", "error", "job_id", "project", "scope", "duration_seconds") if key in record})
        return {"path": str(self.path), "events_considered": len(recent), "failures": failures, "tool_counts": counts, "recent": recent}
