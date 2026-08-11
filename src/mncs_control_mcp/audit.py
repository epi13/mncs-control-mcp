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
