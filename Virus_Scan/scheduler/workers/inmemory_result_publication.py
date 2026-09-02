from dataclasses import dataclass
from typing import Callable, MutableMapping

from Virus_Scan.scheduler.workers.inmemory_result_publication_support import (
    completed_worker_counts,
    completed_worker_future_result,
    completed_worker_metadata,
    publish_worker_result_record,
    worker_result_requires_schema_normalization,
)
from Virus_Scan.scheduler.workers.result_contracts import normalize_scheduler_worker_result


@dataclass(frozen=True, slots=True)
class InMemoryWorkerResultPublication:
    """Immutable evidence for publication of one completed in-memory worker result."""

    processed_jobs: int
    stop_requested: bool
    job_id: object
    path: object
    attempt: int
    schema_normalized: bool
    queue_publish_failed: bool = False
    worker_error_result_failed: bool = False
    queue_publish_report_failed: bool = False


def publish_completed_inmemory_worker_result(
    *,
    future: object,
    active: MutableMapping[object, object],
    result_q: object,
    max_jobs_per_worker: int,
    processed_jobs: int,
    worker_error_result: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple,
    record_suppressed: Callable[[str, BaseException], object],
) -> object:
    """Worker-owned completion publication for one finished in-memory worker future."""
    job_id, _path, attempt, safe_path, path_unavailable_reason = completed_worker_metadata(
        active=active,
        future=future,
    )
    f, res, worker_error_result_failed = completed_worker_future_result(
        future=future,
        safe_path=safe_path,
        path_unavailable_reason=path_unavailable_reason,
        worker_error_result=worker_error_result,
        recoverable_exceptions=recoverable_exceptions,
    )
    schema_normalized = worker_result_requires_schema_normalization(res)
    res = normalize_scheduler_worker_result(
        f,
        res,
        worker_error_result=worker_error_result,
        recoverable_exceptions=recoverable_exceptions,
    )
    res, queue_publish_failed, queue_publish_report_failed = publish_worker_result_record(
        result_q=result_q,
        job_id=job_id,
        f=f,
        res=res,
        attempt=attempt,
        recoverable_exceptions=recoverable_exceptions,
        record_suppressed=record_suppressed,
    )
    next_processed, should_stop = completed_worker_counts(
        processed_jobs=processed_jobs,
        max_jobs_per_worker=max_jobs_per_worker,
    )
    return InMemoryWorkerResultPublication(
        processed_jobs=next_processed,
        stop_requested=should_stop,
        job_id=job_id,
        path=safe_path if path_unavailable_reason else f,
        attempt=attempt,
        schema_normalized=bool(schema_normalized),
        queue_publish_failed=queue_publish_failed,
        worker_error_result_failed=worker_error_result_failed,
        queue_publish_report_failed=queue_publish_report_failed,
    )


__all__ = ("InMemoryWorkerResultPublication", "publish_completed_inmemory_worker_result")
