"""Worker-thread progress heartbeat evidence records."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WorkerThreadProgressHeartbeatEvidence:
    """Immutable evidence for failed per-thread worker progress heartbeat publication."""

    job_id: str
    attempt: int
    stage: str
    progress_counter: int
    reason: str
    published: bool = False

    def as_metadata(self) -> dict[str, object]:
        return {
            "worker_thread_progress_heartbeat_failed": not self.published,
            "worker_thread_progress_job_id": self.job_id,
            "worker_thread_progress_attempt": self.attempt,
            "worker_thread_progress_stage": self.stage,
            "worker_thread_progress_counter": self.progress_counter,
            "worker_thread_progress_failure_reason": self.reason,
        }


__all__ = ("WorkerThreadProgressHeartbeatEvidence",)
