"""Worker-owned in-memory task assignment publication helpers."""
from __future__ import annotations

from dataclasses import dataclass
import os
import time
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int

_SCHEDULER_ZERO_INT = 0


@dataclass(frozen=True)
class InMemoryAssignedTask:
    """Immutable assignment parsed from one parent-to-worker queue item."""

    job_id: object
    path: object
    attempt: int


@dataclass(frozen=True, slots=True)
class InMemoryWorkerAssignmentPublicationResult:
    """Immutable evidence for worker assignment publication to the parent loop."""

    job_id: object
    attempt: int
    published: bool
    suppressed_failures: int = 0
    failure_stage: str = ""


def _report_invalid_inmemory_assignment(
    item: object,
    exc: BaseException,
    *,
    invalid_item_reporter: Callable[[object, BaseException], object] | None,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    if invalid_item_reporter is None:
        return
    try:
        invalid_item_reporter(item, exc)
    except recoverable_exceptions as report_exc:
        _ = report_exc


_INMEMORY_WORKER_TASK_ATTEMPT_FIELDS = 3


@dataclass(frozen=True, slots=True)
class InMemoryWorkerTaskDecision:
    task: InMemoryAssignedTask | None
    reason: str
    accepted: bool

    def as_task(self) -> InMemoryAssignedTask | None:
        return self.task


def parse_inmemory_worker_task_decision(
    item: object,
    *,
    recoverable_exceptions: tuple[type[BaseException], ...],
    invalid_item_reporter: Callable[[object, BaseException], object] | None = None,
) -> InMemoryWorkerTaskDecision:
    if type(item) not in {list, tuple}:
        reason = "invalid worker assignment shape"
        _report_invalid_inmemory_assignment(item, ValueError(reason), invalid_item_reporter=invalid_item_reporter, recoverable_exceptions=recoverable_exceptions)
        return InMemoryWorkerTaskDecision(None, reason, accepted=False)
    if len(item) < 2:
        reason = "invalid worker assignment length"
        _report_invalid_inmemory_assignment(item, ValueError(reason), invalid_item_reporter=invalid_item_reporter, recoverable_exceptions=recoverable_exceptions)
        return InMemoryWorkerTaskDecision(None, reason, accepted=False)
    raw_attempt = item[2] if len(item) >= _INMEMORY_WORKER_TASK_ATTEMPT_FIELDS else 0
    attempt, _attempt_reason = scheduler_int(
        raw_attempt,
        default=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_worker_assignment_attempt_rejected",
    )
    return InMemoryWorkerTaskDecision(InMemoryAssignedTask(job_id=item[0], path=item[1], attempt=attempt), "", accepted=True)


def parse_inmemory_worker_task(
    item: object,
    *,
    recoverable_exceptions: tuple[type[BaseException], ...],
    invalid_item_reporter: Callable[[object, BaseException], object] | None = None,
) -> InMemoryAssignedTask | None:
    """Parse one worker queue item and explicitly report malformed assignments."""
    return parse_inmemory_worker_task_decision(
        item,
        recoverable_exceptions=recoverable_exceptions,
        invalid_item_reporter=invalid_item_reporter,
    ).as_task()


def make_inmemory_worker_task_meta(task: InMemoryAssignedTask) -> dict[str, object]:
    """Return the canonical mutable per-future metadata owned by the worker loop."""
    return {
        "job_id": task.job_id,
        "path": task.path,
        "attempt": scheduler_int(
            task.attempt,
            default=_SCHEDULER_ZERO_INT,
            minimum=0,
            reason="inmemory_worker_task_meta_attempt_rejected",
        )[0],
        "started": time.time(),
        "last_hb": 0.0,
        "stage": "assigned",
        "progress_counter": 0,
        "bytes_processed": 0,
        "last_progress_ns": 0,
        "stage_started_ns": 0,
        "cost": {"weight": 1, "stage": "light", "heavy": False},
    }


def publish_inmemory_worker_assignment(
    *,
    result_put: Callable[[tuple[object, ...]], object],
    task: InMemoryAssignedTask,
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> InMemoryWorkerAssignmentPublicationResult:
    """Publish worker assignment evidence without letting the loop own shape details."""
    try:
        result_put(("assigned", task.job_id, task.path, os.getpid(), time.time(), task.attempt))
    except recoverable_exceptions as assign_exc:
        suppressed_failures = 1
        try:
            record_scheduler_suppressed("inmemory_worker_assignment_publication_failure", assign_exc)
        except recoverable_exceptions as report_exc:
            _ = report_exc
            suppressed_failures += 1
        return InMemoryWorkerAssignmentPublicationResult(
            job_id=task.job_id,
            attempt=scheduler_int(
                task.attempt,
                default=_SCHEDULER_ZERO_INT,
                minimum=0,
                reason="inmemory_worker_assignment_publication_attempt_rejected",
            )[0],
            published=False,
            suppressed_failures=suppressed_failures,
            failure_stage="inmemory_worker_assignment_publication_failure",
        )
    return InMemoryWorkerAssignmentPublicationResult(
        job_id=task.job_id,
        attempt=scheduler_int(
            task.attempt,
            default=_SCHEDULER_ZERO_INT,
            minimum=0,
            reason="inmemory_worker_assignment_publication_attempt_rejected",
        )[0],
        published=True,
    )


__all__ = (
    "InMemoryAssignedTask",
    "InMemoryWorkerAssignmentPublicationResult",
    "InMemoryWorkerTaskDecision",
    "make_inmemory_worker_task_meta",
    "parse_inmemory_worker_task",
    "parse_inmemory_worker_task_decision",
    "publish_inmemory_worker_assignment",
)
