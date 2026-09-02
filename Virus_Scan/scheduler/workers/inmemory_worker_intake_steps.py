"""Bounded worker task-intake steps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int
from Virus_Scan.scheduler.workers.inmemory_worker_assignment import (
    InMemoryAssignedTask,
    InMemoryWorkerAssignmentPublicationResult,
    parse_inmemory_worker_task,
    publish_inmemory_worker_assignment,
)

_TASK_INTAKE_TIMEOUT_SECONDS = 0.05


@dataclass(frozen=True, slots=True)
class WorkerQueueIntake:
    """Result of reading one item from a worker task queue."""

    item: object
    queue_empty: bool
    suppressed_failures: int


def normalized_worker_intake_timeout(timeout_sec: object) -> float:
    """Normalize worker queue timeout without exposing fallback keyword routes."""

    timeout_value, timeout_reason = scheduler_float(
        timeout_sec,
        minimum=0.0,
        reason="inmemory_worker_intake_timeout_rejected",
    )
    if timeout_reason:
        return _TASK_INTAKE_TIMEOUT_SECONDS
    return timeout_value


def read_worker_queue_item(
    *,
    task_q: object,
    queue_empty_type: type[BaseException],
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
    timeout_value: float,
) -> WorkerQueueIntake:
    """Read one worker queue item and record recoverable intake failures."""

    try:
        return WorkerQueueIntake(
            item=task_q.get(timeout=timeout_value),
            queue_empty=False,
            suppressed_failures=0,
        )
    except queue_empty_type:
        return WorkerQueueIntake(item=None, queue_empty=True, suppressed_failures=0)
    except recoverable_exceptions as intake_exc:
        try:
            record_suppressed("inmemory_worker_task_intake_failure", intake_exc)
        except recoverable_exceptions as record_exc:
            _ = record_exc
        return WorkerQueueIntake(item=None, queue_empty=False, suppressed_failures=1)


def parse_worker_queue_assignment(
    *,
    item: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
    invalid_item_reporter: Callable[[object, BaseException], object],
) -> InMemoryAssignedTask | None:
    """Parse one immutable worker assignment from a queue item."""

    return parse_inmemory_worker_task(
        item,
        recoverable_exceptions=recoverable_exceptions,
        invalid_item_reporter=invalid_item_reporter,
    )


def publish_worker_assignment_result(
    *,
    result_put: Callable[[object], object],
    task: InMemoryAssignedTask,
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
) -> tuple[InMemoryWorkerAssignmentPublicationResult, int]:
    """Publish worker assignment evidence and capture bounded suppression count."""

    try:
        publication_result = publish_inmemory_worker_assignment(
            result_put=result_put,
            task=task,
            record_scheduler_suppressed=record_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
    except recoverable_exceptions as publish_exc:
        try:
            record_suppressed("inmemory_worker_assignment_publication_failure", publish_exc)
        except recoverable_exceptions as record_exc:
            _ = record_exc
        publication_result = InMemoryWorkerAssignmentPublicationResult(
            job_id=task.job_id,
            attempt=scheduler_int(
                task.attempt,
                minimum=0,
                reason="inmemory_worker_intake_attempt_rejected",
            )[0],
            published=False,
            suppressed_failures=1,
            failure_stage="inmemory_worker_assignment_publication_failure",
        )
        return publication_result, 1
    return publication_result, 0


def worker_assignment_publication_state(
    publication_result: InMemoryWorkerAssignmentPublicationResult,
) -> tuple[bool, int]:
    """Return normalized publication status and suppressed-failure delta."""

    suppressed_failures, _suppressed_reason = scheduler_int(
        publication_result.suppressed_failures,
        minimum=0,
        reason="inmemory_worker_publication_suppressed_failures_rejected",
    )
    assignment_published, _published_reason = scheduler_bool(
        publication_result.published,
        reason="inmemory_worker_assignment_published_rejected",
    )
    return assignment_published, suppressed_failures


__all__ = (
    "WorkerQueueIntake",
    "normalized_worker_intake_timeout",
    "parse_worker_queue_assignment",
    "publish_worker_assignment_result",
    "read_worker_queue_item",
    "worker_assignment_publication_state",
)
