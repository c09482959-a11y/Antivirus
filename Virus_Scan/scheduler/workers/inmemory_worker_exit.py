"""Worker-owned in-memory worker-exit evidence handling."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.workers.inmemory_worker_exit_decisions import (
    active_worker_items_decision,
    info_pid_decision,
    terminal_job_ids_decision,
    worker_exit_pid_decision_from_message,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, MutableSet

_EMPTY_INT_TUPLE: tuple[int, ...] = ()


def _worker_exit_int(value: object, *, reason: str) -> int:
    parsed, parse_reason = scheduler_int(value, default=0, minimum=0, reason=reason)
    return 0 if parse_reason != "" else parsed


def _worker_exit_int_tuple(value: object, *, reason: str) -> tuple[int, ...]:
    items = no_hook_sequence_items(value)
    if items is None:
        return _EMPTY_INT_TUPLE
    out: list[int] = []
    for item in items:
        parsed = _worker_exit_int(item, reason=reason)
        if parsed > 0:
            out.append(parsed)
    return tuple(out)



@dataclass(frozen=True, slots=True)
class InMemoryWorkerExitEvidence:
    """Immutable evidence emitted when an in-memory worker exits."""

    worker_pid: int
    active_jobs: tuple[int, ...]
    retried_jobs: tuple[int, ...]
    ignored_jobs: tuple[int, ...]
    reason: str = "worker_exit"

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_pid", _worker_exit_int(self.worker_pid, reason="worker_exit_pid_rejected"))
        object.__setattr__(self, "active_jobs", _worker_exit_int_tuple(self.active_jobs, reason="worker_exit_active_job_rejected"))
        object.__setattr__(self, "retried_jobs", _worker_exit_int_tuple(self.retried_jobs, reason="worker_exit_retried_job_rejected"))
        object.__setattr__(self, "ignored_jobs", _worker_exit_int_tuple(self.ignored_jobs, reason="worker_exit_ignored_job_rejected"))

    @property
    def had_active_work(self) -> bool:
        return len(self.active_jobs) > 0

    def as_record(self) -> dict[str, object]:
        return {
            "worker_pid": self.worker_pid,
            "active_jobs": list(self.active_jobs),
            "retried_jobs": list(self.retried_jobs),
            "ignored_jobs": list(self.ignored_jobs),
            "reason": self.reason,
        }


def worker_exit_pid_from_message(message: object) -> int:
    """Parse the worker pid from a worker-exit message without caller hooks."""
    return worker_exit_pid_decision_from_message(message).pid


def reconcile_inmemory_worker_exit(
    *,
    message: object,
    active: Mapping[int, Mapping[str, object]],
    terminal: MutableSet[int],
    retry_or_fail: Callable[..., bool],
) -> InMemoryWorkerExitEvidence:
    """Convert one worker-exit message into retry/evidence decisions."""
    pid_decision = worker_exit_pid_decision_from_message(message)
    pid = pid_decision.pid
    if not pid_decision.accepted:
        return InMemoryWorkerExitEvidence(0, (), (), (), reason=pid_decision.reason)
    terminal_ids = terminal_job_ids_decision(terminal).job_ids
    active_jobs: list[int] = []
    retried_jobs: list[int] = []
    ignored_jobs: list[int] = []
    active_worker_decision = active_worker_items_decision(active)
    if not active_worker_decision.accepted:
        raise ValueError(active_worker_decision.reason)
    for job_id_raw, info in active_worker_decision.items:
        job_id = _worker_exit_int(job_id_raw, reason="worker_exit_job_id_rejected")
        if job_id <= 0 or job_id in terminal_ids or info_pid_decision(info).pid != pid:
            continue
        active_jobs.append(job_id)
        if retry_or_fail(job_id, "worker_exit", pid=pid):
            retried_jobs.append(job_id)
        else:
            ignored_jobs.append(job_id)
    return InMemoryWorkerExitEvidence(pid, tuple(active_jobs), tuple(retried_jobs), tuple(ignored_jobs))


__all__ = (
    "InMemoryWorkerExitEvidence",
    "reconcile_inmemory_worker_exit",
    "worker_exit_pid_from_message",
)
