"""Worker-owned in-memory task intake and assignment evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import safe_lifecycle_exception_message, safe_worker_message_preview

from Virus_Scan.scheduler.workers.inmemory_worker_assignment import InMemoryAssignedTask
from Virus_Scan.scheduler.workers.inmemory_worker_intake_steps import (
    normalized_worker_intake_timeout,
    parse_worker_queue_assignment,
    publish_worker_assignment_result,
    read_worker_queue_item,
    worker_assignment_publication_state,
)


@dataclass(frozen=True, slots=True)
class InMemoryWorkerTaskIntakeResult:
    """Immutable evidence for one in-memory worker task-intake cycle."""

    task: InMemoryAssignedTask | None
    stop_requested: bool
    queue_empty: bool
    invalid_assignment: bool
    assignment_published: bool
    suppressed_failures: int = 0


@dataclass(frozen=True, slots=True)
class InMemoryWorkerTaskIntakeDependencies:
    """Immutable dependency bundle for one worker task-intake cycle."""

    result_put: Callable[[object], object]
    queue_empty_type: type[BaseException]
    recoverable_exceptions: tuple[type[BaseException], ...]
    record_suppressed: Callable[[str, BaseException], object]


def receive_inmemory_worker_task(
    *,
    task_q: object,
    intake: InMemoryWorkerTaskIntakeDependencies,
    timeout_sec: float = 0.05,
) -> InMemoryWorkerTaskIntakeResult:
    """Receive, validate, and publish one immutable worker task-intake result."""

    timeout_value = normalized_worker_intake_timeout(timeout_sec)
    queue_intake = read_worker_queue_item(
        task_q=task_q,
        queue_empty_type=intake.queue_empty_type,
        recoverable_exceptions=intake.recoverable_exceptions,
        record_suppressed=intake.record_suppressed,
        timeout_value=timeout_value,
    )
    if queue_intake.queue_empty:
        return InMemoryWorkerTaskIntakeResult(
            task=None,
            stop_requested=False,
            queue_empty=True,
            invalid_assignment=False,
            assignment_published=False,
        )
    if queue_intake.suppressed_failures:
        return InMemoryWorkerTaskIntakeResult(
            task=None,
            stop_requested=False,
            queue_empty=False,
            invalid_assignment=False,
            assignment_published=False,
            suppressed_failures=queue_intake.suppressed_failures,
        )
    if queue_intake.item is None:
        return InMemoryWorkerTaskIntakeResult(
            task=None,
            stop_requested=True,
            queue_empty=False,
            invalid_assignment=False,
            assignment_published=False,
        )

    task = parse_worker_queue_assignment(
        item=queue_intake.item,
        recoverable_exceptions=intake.recoverable_exceptions,
        invalid_item_reporter=lambda bad_item, exc: intake.record_suppressed(
            "inmemory_worker_invalid_assignment",
            RuntimeError(
                str.__add__(
                    str.__add__("invalid worker assignment ", safe_worker_message_preview(bad_item)),
                    str.__add__(": ", safe_lifecycle_exception_message(exc)),
                )
            ),
        ),
    )
    if task is None:
        return InMemoryWorkerTaskIntakeResult(
            task=None,
            stop_requested=False,
            queue_empty=False,
            invalid_assignment=True,
            assignment_published=False,
        )

    publication_result, publication_failures = publish_worker_assignment_result(
        result_put=intake.result_put,
        task=task,
        recoverable_exceptions=intake.recoverable_exceptions,
        record_suppressed=intake.record_suppressed,
    )
    assignment_published, result_failures = worker_assignment_publication_state(publication_result)
    return InMemoryWorkerTaskIntakeResult(
        task=task,
        stop_requested=False,
        queue_empty=False,
        invalid_assignment=False,
        assignment_published=assignment_published,
        suppressed_failures=publication_failures + result_failures,
    )


__all__ = (
    "InMemoryWorkerTaskIntakeDependencies",
    "InMemoryWorkerTaskIntakeResult",
    "receive_inmemory_worker_task",
)
