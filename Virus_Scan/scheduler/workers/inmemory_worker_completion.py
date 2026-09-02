"""Worker-owned in-memory active-future completion draining."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, MutableMapping, Sequence

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_int
from Virus_Scan.scheduler.workers.inmemory_result_publication import publish_completed_inmemory_worker_result
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_decisions import done_worker_futures_decision

_SCHEDULER_ZERO_INT = 0


@dataclass(frozen=True, slots=True)
class InMemoryWorkerCompletionDrainResult:
    """Immutable evidence for one in-memory worker completion-drain cycle."""

    processed_jobs: int
    stop_requested: bool
    completed_futures: int
    suppressed_failures: int = 0


def collect_done_inmemory_worker_futures(active: MutableMapping[object, object]) -> tuple[object, ...]:
    """Return completed in-memory worker futures without mutating active state."""

    return done_worker_futures_decision(active).items


@dataclass(frozen=True, slots=True)
class InMemoryWorkerCompletionDrainRequest:
    """Internal request for one worker completion-drain cycle."""

    done_futures: Sequence[object]
    active: MutableMapping[object, object]
    result_q: object
    max_jobs_per_worker: int
    processed_jobs: int
    worker_error_result: Callable[[object, BaseException], object]
    recoverable_exceptions: tuple[type[BaseException], ...]
    record_suppressed: Callable[[str, BaseException], object]


def drain_completed_inmemory_worker_futures(
    request: InMemoryWorkerCompletionDrainRequest,
) -> InMemoryWorkerCompletionDrainResult:
    """Publish completed worker futures and return immutable drain evidence."""
    next_processed, processed_reason = scheduler_int(
        request.processed_jobs,
        default=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_worker_completion_processed_jobs_rejected",
    )
    if processed_reason != "":
        next_processed = _SCHEDULER_ZERO_INT
    stop_requested = False
    suppressed_failures = 0
    completed_count = 0
    for future in no_hook_sequence_items(request.done_futures):
        try:
            publication = publish_completed_inmemory_worker_result(
                future=future,
                active=request.active,
                result_q=request.result_q,
                max_jobs_per_worker=request.max_jobs_per_worker,
                processed_jobs=next_processed,
                worker_error_result=request.worker_error_result,
                recoverable_exceptions=request.recoverable_exceptions,
                record_suppressed=request.record_suppressed,
            )
            next_processed = publication.processed_jobs
            completed_count += 1
            if publication.stop_requested:
                stop_requested = True
        except request.recoverable_exceptions as suppressed_exc:
            suppressed_failures += 1
            try:
                request.record_suppressed("suppressed_exception", suppressed_exc)
            except request.recoverable_exceptions as record_exc:
                _ = record_exc
    return InMemoryWorkerCompletionDrainResult(
        processed_jobs=next_processed,
        stop_requested=scheduler_bool(
            stop_requested,
            default=False,
            reason="inmemory_worker_completion_stop_rejected",
        )[0],
        completed_futures=completed_count,
        suppressed_failures=suppressed_failures,
    )




__all__ = (
    'InMemoryWorkerCompletionDrainRequest',
    'InMemoryWorkerCompletionDrainResult',
    'collect_done_inmemory_worker_futures',
    'drain_completed_inmemory_worker_futures',
)
