"""Bounded cancellation steps for memory-toxic worker jobs."""
from __future__ import annotations

from typing import MutableMapping

from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_evidence import (
    attach_memory_toxicity_evidence,
    memory_toxicity_evidence,
)
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_policy import record_memory_toxicity_suppression
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_records import (
    memory_toxicity_job_record_for,
    memory_toxicity_owned_pid_decision,
)


def attach_memory_toxic_active_job_failure(
    *,
    active_info: object,
    job_records: object,
    worker_metrics: object,
    pid: object,
    job_id: object,
    rss_mb: float,
    reason: str,
    source: str,
    detail_error: object,
) -> None:
    attach_memory_toxicity_evidence(
        evidence=memory_toxicity_evidence(
            pid=pid,
            job_id=job_id,
            reason=reason,
            action="cancel_active_job",
            rss_mb=rss_mb,
            error=detail_error,
            source=source,
        ),
        active_info=active_info if isinstance(active_info, MutableMapping) else None,
        job_record=memory_toxicity_job_record_for(job_records, job_id),
        worker_metrics=worker_metrics if isinstance(worker_metrics, MutableMapping) else None,
    )


def record_active_job_pid_unavailable(
    *,
    info: object,
    job_records: object,
    worker_metrics: object,
    pid: object,
    job_id: object,
    rss_mb: float,
    pid_reason: str,
    recoverable_exceptions: object,
    record_suppressed: object,
) -> None:
    detail_error = record_memory_toxicity_suppression(
        error=ValueError(pid_reason),
        recoverable_exceptions=recoverable_exceptions,
        record_suppressed=record_suppressed,
    )
    attach_memory_toxic_active_job_failure(
        active_info=info,
        job_records=job_records,
        worker_metrics=worker_metrics,
        pid=pid,
        job_id=job_id,
        rss_mb=rss_mb,
        reason="worker_memory_toxic_active_job_pid_unavailable",
        source="active_job_pid",
        detail_error=detail_error,
    )


def should_cancel_memory_toxic_job(
    *,
    info: object,
    job_id: object,
    pid: object,
    terminal_values: set[object],
) -> bool:
    decision = memory_toxicity_owned_pid_decision(info)
    return (
        decision.status == "accepted"
        and isinstance(info, MutableMapping)
        and decision.value == pid
        and job_id not in terminal_values
    )


def cancel_memory_toxic_job(
    *,
    info: MutableMapping[object, object],
    job_records: object,
    worker_metrics: object,
    pid: object,
    job_id: object,
    rss_mb: float,
    cancel_job: object,
    recoverable_exceptions: object,
    record_suppressed: object,
) -> bool:
    try:
        cancel_requested = bool(cancel_job(job_id, "worker_memory_toxic", pid=pid))
    except recoverable_exceptions as cancel_exc:
        detail_error = record_memory_toxicity_suppression(
            error=cancel_exc,
            recoverable_exceptions=recoverable_exceptions,
            record_suppressed=record_suppressed,
        )
        attach_memory_toxic_active_job_failure(
            active_info=info,
            job_records=job_records,
            worker_metrics=worker_metrics,
            pid=pid,
            job_id=job_id,
            rss_mb=rss_mb,
            reason="worker_memory_toxic_cancel_failed",
            source="cancel_job",
            detail_error=detail_error,
        )
        return False
    if cancel_requested:
        return True
    attach_memory_toxic_active_job_failure(
        active_info=info,
        job_records=job_records,
        worker_metrics=worker_metrics,
        pid=pid,
        job_id=job_id,
        rss_mb=rss_mb,
        reason="worker_memory_toxic_cancel_rejected",
        source="cancel_job",
        detail_error=RuntimeError("memory toxicity cancel request was rejected"),
    )
    return False


def memory_toxic_job_pid_decision(info: object) -> object:
    return memory_toxicity_owned_pid_decision(info)


__all__ = (
    "attach_memory_toxic_active_job_failure",
    "cancel_memory_toxic_job",
    "memory_toxic_job_pid_decision",
    "record_active_job_pid_unavailable",
    "should_cancel_memory_toxic_job",
)
