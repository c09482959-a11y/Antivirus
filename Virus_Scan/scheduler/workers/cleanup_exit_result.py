"""Immutable process-queue worker cleanup result contracts."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple


@dataclass(frozen=True)
class WorkerExitWaitResult:
    """Immutable evidence for final worker wait and cleanup actions."""

    worker_idx: int
    pid: int
    output: str
    status: int
    timed_out: bool
    cleanup_actions: tuple[str, ...] = ()
    failure_markers: tuple[str, ...] = ()
    reason: str = "worker_final_wait"

    def __post_init__(self) -> None:
        object.__setattr__(self, "cleanup_actions", immutable_tuple(self.cleanup_actions))
        object.__setattr__(self, "failure_markers", immutable_tuple(self.failure_markers))

    @property
    def infrastructure_failed(self) -> bool:
        return self.status == 4 or self.status < 0

    def as_evidence(self) -> dict[str, object]:
        return {
            "worker_idx": self.worker_idx,
            "worker_pid": self.pid,
            "worker_output": self.output,
            "worker_exit_status": self.status,
            "worker_wait_timed_out": self.timed_out,
            "worker_cleanup_actions": list(self.cleanup_actions),
            "worker_failure_markers": list(self.failure_markers),
            "worker_cleanup_reason": self.reason,
        }


__all__ = ("WorkerExitWaitResult",)
