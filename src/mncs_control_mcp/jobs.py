from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass
class Job:
    job_id: str
    status: str = "queued"
    assigned_node: str | None = None
    model: str | None = None
    created_at: str = field(default_factory=_now)
    started_at: str | None = None
    completed_at: str | None = None
    progress: object | None = None
    result: object | None = None

    def public(self, *, include_result: bool = False) -> dict[str, object]:
        result: dict[str, object] = {
            "job_id": self.job_id,
            "status": self.status,
            "assigned_node": self.assigned_node,
            "model": self.model,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "progress": self.progress,
        }
        if include_result:
            result["result"] = self.result
        return result


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()

    def create(self, *, node: str | None = None, model: str | None = None) -> Job:
        job = Job("mncs-job-" + secrets.token_hex(12), assigned_node=node, model=model)
        with self._lock:
            self._jobs[job.job_id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)
