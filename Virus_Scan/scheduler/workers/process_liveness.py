"""Worker-owned PID liveness evidence."""
from __future__ import annotations

import os
from dataclasses import dataclass


from Virus_Scan.scheduler.internal.immutable_outputs import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_int


@dataclass(frozen=True)
class WorkerLivenessResult:
    """Immutable result for worker PID liveness probes."""

    pid: int
    alive: bool
    reason: str

    def as_evidence(self) -> dict[str, object]:
        return {
            "worker_pid": self.pid,
            "pid_alive": self.alive,
            "liveness_reason": self.reason,
        }



def check_process_queue_worker_liveness(pid: object, *, record_suppressed: object) -> WorkerLivenessResult:
    """Return immutable worker-owned PID liveness evidence."""
    pid_i, reason = worker_int(pid, reason='process_queue_pid_rejected', minimum=0)
    if reason:
        record_suppressed(
            "process_queue_pid_liveness_probe_failed",
            RuntimeError(reason),
            extra={
                "pid_unavailable": True,
                "pid_unavailable_reason": reason,
                "pid_evidence": unsupported_scheduler_value_evidence(pid, field_name="worker_pid"),
            },
        )
        return WorkerLivenessResult(0, alive=False, reason="pid_parse_failed")
    if pid_i <= 0:
        return WorkerLivenessResult(pid_i, alive=False, reason="invalid_pid")
    if pid_i == os.getpid():
        return WorkerLivenessResult(pid_i, alive=True, reason="current_process")
    try:
        os.kill(pid_i, 0)
        return WorkerLivenessResult(pid_i, alive=True, reason="os_probe_alive")
    except ProcessLookupError:
        return WorkerLivenessResult(pid_i, alive=False, reason="process_missing")
    except PermissionError:
        return WorkerLivenessResult(pid_i, alive=True, reason="permission_denied_assumed_alive")
    except OSError as exc:
        record_suppressed(
            "process_queue_pid_liveness_probe_failed",
            exc,
            extra={"pid": pid_i},
        )
        return WorkerLivenessResult(pid_i, alive=False, reason="os_probe_failed")


__all__ = ("WorkerLivenessResult", "check_process_queue_worker_liveness")
