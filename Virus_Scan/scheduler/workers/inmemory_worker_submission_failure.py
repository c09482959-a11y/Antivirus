"""Failure-publication helpers for in-memory worker task submission."""
from __future__ import annotations

import os
import time
from typing import Callable

from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import safe_lifecycle_int
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_evidence import (
    InMemoryWorkerLifecyclePublicationEvidence,
    annotate_worker_lifecycle_publication_failure,
    build_worker_error_result_evidence,
    worker_lifecycle_exception_reason,
)


def owned_task_meta_value(task_meta: object, field_name: str) -> object:
    """Read worker-owned task metadata without caller-owned mapping hooks."""
    if type(task_meta) is not dict or type(field_name) is not str:
        return None
    return dict.get(task_meta, field_name)


def record_submission_failure(
    *,
    submit_exc: BaseException,
    record_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[int, BaseException | None]:
    """Record a submission failure and return suppression accounting."""
    try:
        record_suppressed("inmemory_worker_task_submission_failure", submit_exc)
        return 1, None
    except recoverable_exceptions as record_exc:
        return 2, record_exc


def build_submission_failure_result(
    *,
    task_meta: object,
    task_path: object,
    submit_exc: BaseException,
    report_exc: BaseException | None,
    worker_execution_deps: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[object, InMemoryWorkerLifecyclePublicationEvidence]:
    """Build and annotate the worker error result for submission failure."""
    evidence = InMemoryWorkerLifecyclePublicationEvidence(
        operation="task_submission",
        job_id=safe_lifecycle_int(owned_task_meta_value(task_meta, "job_id")),
        path=task_path,
        generation=safe_lifecycle_int(owned_task_meta_value(task_meta, "attempt")),
        reason=worker_lifecycle_exception_reason(submit_exc),
        report_failed=report_exc is not None,
        report_error=worker_lifecycle_exception_reason(report_exc) if report_exc is not None else "",
    )
    try:
        failure_result = worker_execution_deps.worker_error_result(
            task_path,
            submit_exc,
        )
    except recoverable_exceptions as error_result_exc:
        failure_result = build_worker_error_result_evidence(
            task_path,
            submit_exc,
            error_result_exc=error_result_exc,
        )
    return annotate_worker_lifecycle_publication_failure(failure_result, evidence), evidence


def publish_submission_failure_result(
    *,
    task_meta: object,
    evidence: InMemoryWorkerLifecyclePublicationEvidence,
    failure_result: object,
    worker_execution_deps: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
) -> int:
    """Publish submission failure result to the parent result queue."""
    try:
        worker_execution_deps.result_put((
            "result",
            owned_task_meta_value(task_meta, "job_id"),
            evidence.path,
            failure_result,
            os.getpid(),
            time.time(),
            safe_lifecycle_int(owned_task_meta_value(task_meta, "attempt")),
        ))
        return 0
    except recoverable_exceptions as publish_exc:
        try:
            record_suppressed(
                "inmemory_worker_task_submission_result_publication_failure",
                publish_exc,
            )
            return 1
        except recoverable_exceptions:
            return 2


def handle_worker_task_submission_failure(
    *,
    task_meta: object,
    task_path: object,
    submit_exc: BaseException,
    worker_execution_deps: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
) -> int:
    """Record, annotate, and publish one worker task submission failure."""
    suppressed_failures, report_exc = record_submission_failure(
        submit_exc=submit_exc,
        record_suppressed=record_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    failure_result, evidence = build_submission_failure_result(
        task_meta=task_meta,
        task_path=task_path,
        submit_exc=submit_exc,
        report_exc=report_exc,
        worker_execution_deps=worker_execution_deps,
        recoverable_exceptions=recoverable_exceptions,
    )
    suppressed_failures += publish_submission_failure_result(
        task_meta=task_meta,
        evidence=evidence,
        failure_result=failure_result,
        worker_execution_deps=worker_execution_deps,
        recoverable_exceptions=recoverable_exceptions,
        record_suppressed=record_suppressed,
    )
    return suppressed_failures


__all__ = (
    "handle_worker_task_submission_failure",
    "owned_task_meta_value",
)
