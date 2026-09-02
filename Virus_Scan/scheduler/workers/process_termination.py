"""Worker-owned process termination evidence."""
from __future__ import annotations

import os
import signal
import shutil
import subprocess
from dataclasses import dataclass


from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.runtime.queue_filesystem import scheduler_windows_creationflags as _umige_windows_creationflags
from Virus_Scan.scheduler.workers.process_control_no_hook import (
    call_process_method,
    owned_job_ids_active,
    safe_process_control_exception_name,
    safe_process_control_int,
    safe_process_control_text,
    safe_process_pid,
)


def _windows_taskkill_path() -> str | None:
    return shutil.which("taskkill")


@dataclass(frozen=True)
class WorkerTerminationResult:
    """Immutable result for worker-authority termination attempts."""

    pid: int
    requested: bool
    terminated: bool
    reason: str
    error: str = ""

    def as_evidence(self) -> dict[str, object]:
        return {
            "worker_pid": self.pid,
            "termination_requested": self.requested,
            "worker_terminated": self.terminated,
            "termination_reason": self.reason,
            "termination_error": self.error,
        }


@dataclass(frozen=True)
class WorkerProcessHandleTerminationResult:
    """Immutable result for worker-owned Popen handle termination attempts."""

    worker_idx: int
    pid: int
    action: str
    requested: bool
    completed: bool
    reason: str
    error: str = ""

    def as_evidence(self) -> dict[str, object]:
        return {
            "worker_idx": self.worker_idx,
            "worker_pid": self.pid,
            "worker_action": self.action,
            "termination_requested": self.requested,
            "termination_completed": self.completed,
            "termination_reason": self.reason,
            "termination_error": self.error,
        }


def terminate_queue_worker_pid(pid: object, *, reason: object="queue_progress_stalled") -> WorkerTerminationResult:
    """Terminate a worker process by explicit worker authority and return evidence."""
    pid_i, pid_reason = safe_process_control_int(
        pid,
        replacement_value=0,
        minimum=0,
        reason="queue_worker_pid_rejected",
    )
    termination_reason, _reason_failure = safe_process_control_text(
        reason,
        replacement_text="queue_progress_stalled",
        reason="queue_worker_termination_reason_rejected",
    )
    validation_error = ""
    result_pid = pid_i
    if pid_reason:
        result_pid = 0
        validation_error = pid_reason
    elif pid_i <= 0:
        validation_error = "invalid_pid"
    elif pid_i == os.getpid():
        validation_error = "refused_self_termination"
    if validation_error:
        return WorkerTerminationResult(result_pid, requested=False, terminated=False, reason=termination_reason, error=validation_error)
    try:
        if os.name == "nt":
            try:
                taskkill_path = _windows_taskkill_path()
                if taskkill_path is None:
                    raise FileNotFoundError("taskkill")
                subprocess.run(  # noqa: S603
                    [taskkill_path, "/PID", str(pid_i), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    creationflags=_umige_windows_creationflags(helper=True),
                    check=False,
                )
                return WorkerTerminationResult(pid_i, requested=True, terminated=True, reason=termination_reason)
            except RECOVERABLE_RUNTIME_ERRORS:
                os.kill(pid_i, signal.SIGTERM if hasattr(signal, "SIGTERM") else 1)
                return WorkerTerminationResult(pid_i, requested=True, terminated=True, reason=termination_reason)
        os.kill(pid_i, signal.SIGTERM if hasattr(signal, "SIGTERM") else 15)
        return WorkerTerminationResult(pid_i, requested=True, terminated=True, reason=termination_reason)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        return WorkerTerminationResult(pid_i, requested=True, terminated=False, reason=termination_reason, error=safe_process_control_exception_name(exc))


def terminate_process_queue_worker_handle(*, worker_idx: object, proc: object, action: str, reason: str) -> WorkerProcessHandleTerminationResult:
    """Apply worker-owned termination/kill action to a Popen-like worker handle."""
    idx, _idx_reason = safe_process_control_int(
        worker_idx,
        replacement_value=-1,
        minimum=-1,
        reason="process_queue_worker_index_rejected",
    )
    pid, pid_reason = safe_process_pid(proc)
    action_name, action_reason = safe_process_control_text(
        action,
        replacement_text="terminate",
        reason="process_queue_worker_action_rejected",
    )
    termination_reason, _reason_failure = safe_process_control_text(
        reason,
        replacement_text="worker_cleanup",
        reason="process_queue_worker_termination_reason_rejected",
    )
    if pid_reason:
        return WorkerProcessHandleTerminationResult(idx, pid, action_name, requested=False, completed=False, reason=termination_reason, error=pid_reason)
    if action_reason or action_name not in {"terminate", "kill"}:
        return WorkerProcessHandleTerminationResult(idx, pid, action_name, requested=False, completed=False, reason=termination_reason, error="invalid_action")
    poll_result, poll_reason = call_process_method(proc, "poll")
    if poll_reason:
        return WorkerProcessHandleTerminationResult(idx, pid, action_name, requested=False, completed=False, reason=termination_reason, error=poll_reason)
    if poll_result is not None:
        return WorkerProcessHandleTerminationResult(idx, pid, action_name, requested=False, completed=False, reason=termination_reason, error="already_exited")
    _method_result, method_reason = call_process_method(proc, action_name)
    if method_reason:
        return WorkerProcessHandleTerminationResult(idx, pid, action_name, requested=True, completed=False, reason=termination_reason, error=method_reason)
    return WorkerProcessHandleTerminationResult(idx, pid, action_name, requested=True, completed=True, reason=termination_reason)


def terminate_idle_inmemory_worker_for_toxicity(*, proc: object, toxic_pid: object, owned_job_ids: object, reason: str = "worker_memory_toxic") -> WorkerTerminationResult:
    """Terminate an idle toxic in-memory worker through worker ownership."""
    pid_i, pid_reason = safe_process_control_int(
        toxic_pid,
        replacement_value=0,
        minimum=0,
        reason="toxic_worker_pid_rejected",
    )
    termination_reason, _reason_failure = safe_process_control_text(
        reason,
        replacement_text="worker_memory_toxic",
        reason="toxic_worker_termination_reason_rejected",
    )
    if pid_reason:
        return WorkerTerminationResult(0, requested=False, terminated=False, reason=termination_reason, error=pid_reason)
    proc_pid, proc_pid_reason = safe_process_pid(proc)
    if proc_pid_reason:
        return WorkerTerminationResult(pid_i, requested=False, terminated=False, reason=termination_reason, error=proc_pid_reason)
    if proc_pid != pid_i:
        return WorkerTerminationResult(pid_i, requested=False, terminated=False, reason=termination_reason, error="pid_mismatch")
    has_owned_jobs, owned_jobs_reason = owned_job_ids_active(owned_job_ids)
    if owned_jobs_reason:
        return WorkerTerminationResult(pid_i, requested=False, terminated=False, reason=termination_reason, error=owned_jobs_reason)
    if has_owned_jobs:
        return WorkerTerminationResult(pid_i, requested=False, terminated=False, reason=termination_reason, error="worker_owns_active_jobs")
    alive, alive_reason = call_process_method(proc, "is_alive")
    if alive_reason:
        return WorkerTerminationResult(pid_i, requested=False, terminated=False, reason=termination_reason, error=alive_reason)
    if type(alive) is not bool:
        return WorkerTerminationResult(pid_i, requested=False, terminated=False, reason=termination_reason, error="worker_liveness_result_rejected")
    if alive is False:
        return WorkerTerminationResult(pid_i, requested=False, terminated=False, reason=termination_reason, error="already_exited")
    _terminate_result, terminate_reason = call_process_method(proc, "terminate")
    if terminate_reason:
        return WorkerTerminationResult(pid_i, requested=True, terminated=False, reason=termination_reason, error=terminate_reason)
    return WorkerTerminationResult(pid_i, requested=True, terminated=True, reason=termination_reason)


__all__ = (
    "WorkerProcessHandleTerminationResult",
    "WorkerTerminationResult",
    "terminate_idle_inmemory_worker_for_toxicity",
    "terminate_process_queue_worker_handle",
    "terminate_queue_worker_pid",
)
