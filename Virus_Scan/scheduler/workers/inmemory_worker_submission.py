"""Worker-owned in-memory task submission into the local worker pool."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, MutableMapping

from Virus_Scan.scheduler.workers.inmemory_worker_assignment import make_inmemory_worker_task_meta
from Virus_Scan.scheduler.workers.inmemory_worker_job import InMemoryWorkerJobExecutionRequest
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import safe_lifecycle_int
from Virus_Scan.scheduler.workers.inmemory_worker_submission_failure import (
    handle_worker_task_submission_failure,
    owned_task_meta_value,
)


def _owned_task_meta_value(task_meta: object, field_name: str) -> object:
    """Read worker-owned task metadata through the canonical submission helper."""
    if type(task_meta) is not dict or type(field_name) is not str:
        return None
    return owned_task_meta_value(task_meta, field_name)


@dataclass(frozen=True, slots=True)
class InMemoryWorkerTaskSubmissionResult:
    """Immutable evidence for one submitted in-memory worker task."""

    submitted: bool
    job_id: int | str | None
    attempt: int
    active_jobs: int
    suppressed_failures: int = 0


def submit_inmemory_worker_task(
    *,
    task: object,
    tpool: object,
    active: MutableMapping[object, object],
    execute_job: Callable[..., object],
    worker_execution_deps: object,
    worker_config: object,
    cancel_table: object,
    heartbeat_table: object,
    heartbeat_flags: MutableMapping[object, object],
    completed_jobs: int,
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
) -> InMemoryWorkerTaskSubmissionResult:
    """Build a worker request, submit it, and return immutable evidence."""
    task_meta = make_inmemory_worker_task_meta(task)
    try:
        worker_request = InMemoryWorkerJobExecutionRequest.build(
            job_id=task.job_id,
            path=task.path,
            attempt=task.attempt,
            worker_config=worker_config,
            cancel_table=cancel_table,
            heartbeat_table=heartbeat_table,
            heartbeat_flags=heartbeat_flags,
            completed_jobs=completed_jobs,
            task_meta=task_meta,
        )
        future = tpool.submit(execute_job, worker_request, worker_execution_deps)
        active[future] = task_meta
    except recoverable_exceptions as submit_exc:
        task_path = _owned_task_meta_value(task_meta, "path")
        return InMemoryWorkerTaskSubmissionResult(
            submitted=False,
            job_id=_owned_task_meta_value(task_meta, "job_id"),
            attempt=safe_lifecycle_int(_owned_task_meta_value(task_meta, "attempt")),
            active_jobs=len(active or {}),
            suppressed_failures=handle_worker_task_submission_failure(
                task_meta=task_meta,
                task_path=task_path,
                submit_exc=submit_exc,
                worker_execution_deps=worker_execution_deps,
                recoverable_exceptions=recoverable_exceptions,
                record_suppressed=record_suppressed,
            ),
        )
    return InMemoryWorkerTaskSubmissionResult(
        submitted=True,
        job_id=_owned_task_meta_value(task_meta, "job_id"),
        attempt=safe_lifecycle_int(_owned_task_meta_value(task_meta, "attempt")),
        active_jobs=len(active or {}),
    )


__all__ = ("InMemoryWorkerTaskSubmissionResult", "submit_inmemory_worker_task")
