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

    def journal_availability(self) -> dict[str, str]:
        """Report whether the private audit source can be inspected."""
        if not self.path.exists():
            return {"status": "EMPTY", "detail": "no audit records have been created"}
        if not self.path.is_file():
            return {"status": "UNAVAILABLE", "detail": "audit path is not a regular file"}
        try:
            with self.path.open("rb") as handle:
                handle.read(1)
        except OSError as exc:
            return {"status": "UNAVAILABLE", "detail": redact_text(str(exc))[:300]}
        return {"status": "AVAILABLE", "detail": "private redacted audit source is readable"}

    def journal_projection(
        self,
        start: str,
        end: str,
        *,
        projects: list[str] | None = None,
        limit: int = 500,
    ) -> dict[str, object]:
        """Return a project-scoped, redacted chronology without raw commands."""
        try:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        except ValueError:
            return {"status": "MALFORMED", "events": [], "detail": "invalid interval"}
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=UTC)
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=UTC)
        if limit < 1 or limit > 5000:
            limit = 500
        allowed = set(projects or [])
        availability = self.journal_availability()
        if availability["status"] != "AVAILABLE":
            return {**availability, "events": []}
        events: list[dict[str, object]] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            return {"status": "UNAVAILABLE", "events": [], "detail": redact_text(str(exc))[:300]}
        for line in lines[-5000:]:
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            timestamp = record.get("timestamp")
            if not isinstance(timestamp, str):
                continue
            try:
                observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                continue
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=UTC)
            if not start_dt <= observed <= end_dt:
                continue
            project = record.get("project") if isinstance(record.get("project"), str) else None
            if allowed and project is not None and project not in allowed:
                continue
            # Keep only chronology fields. In particular, command, environment,
            # and arbitrary adapter payloads are never projected.
            events.append(
                {
                    "timestamp": timestamp,
                    "tool": str(record.get("tool") or "unknown")[:128],
                    "success": record.get("success") if isinstance(record.get("success"), bool) else None,
                    "error": str(record.get("error"))[:128] if record.get("error") else None,
                    "project": project,
                    "scope": str(record.get("scope"))[:32] if record.get("scope") else None,
                    "duration_seconds": record.get("duration_seconds") if isinstance(record.get("duration_seconds"), (int, float)) else None,
                    "job_id": str(record.get("job_id"))[:64] if record.get("job_id") else None,
                }
            )
            if len(events) >= limit:
                break
        return {"status": "AVAILABLE" if events else "EMPTY", "events": events, "detail": "raw audit fields omitted from journal projection"}
