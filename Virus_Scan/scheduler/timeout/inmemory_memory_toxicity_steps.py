"""Bounded worker memory toxicity iteration steps."""
from __future__ import annotations

from typing import MutableMapping

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_items_tuple
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_actions import (
    cancel_memory_toxic_active_jobs,
    terminate_idle_memory_toxic_workers,
)
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_evidence import (
    attach_memory_toxicity_evidence,
    memory_toxicity_evidence,
)
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_policy import record_memory_toxicity_suppression
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_records import (
    memory_toxicity_affected_info,
    memory_toxicity_job_record_for,
    memory_toxicity_owned_jobs,
)


def worker_memory_metric_items(worker_metrics: object) -> tuple[tuple[object, object], ...]:
    """Return no-hook worker metric items for memory-toxicity enforcement."""
    return scheduler_mapping_items_tuple(worker_metrics) or ()


def record_malformed_worker_rss_metric(
    *,
    active: object,
    job_records: object,
    worker_metrics: object,
    pid: object,
    rss_error: BaseException,
    recoverable_exceptions: object,
    record_suppressed: object,
) -> None:
    """Record malformed worker RSS metric evidence without invoking hooks."""
    detail_error = record_memory_toxicity_suppression(
        error=rss_error,
        recoverable_exceptions=recoverable_exceptions,
        record_suppressed=record_suppressed,
    )
    owned = memory_toxicity_owned_jobs(active=active, pid=pid)
    affected_job = owned[0] if owned else None
    attach_memory_toxicity_evidence(
        evidence=memory_toxicity_evidence(
            pid=pid,
            job_id=affected_job,
            reason="worker_memory_toxic_rss_metric_malformed",
            action="read_worker_rss_metric",
            rss_mb=0.0,
            error=detail_error,
            source="worker_metrics.rss_mb",
        ),
        active_info=memory_toxicity_affected_info(active=active, job_id=affected_job),
        job_record=memory_toxicity_job_record_for(job_records, affected_job),
        worker_metrics=worker_metrics if isinstance(worker_metrics, MutableMapping) else None,
    )


def cancel_and_terminate_memory_toxic_worker(
    *,
    procs: object,
    active: object,
    terminal: object,
    worker_metrics: object,
    pid: object,
    rss_mb: float,
    cancel_job: object,
    idle_worker_terminator: object,
    recoverable_exceptions: object,
    record_suppressed: object,
    job_records: object,
) -> int:
    """Cancel active over-budget jobs and terminate an idle toxic worker."""
    owned = memory_toxicity_owned_jobs(active=active, pid=pid)
    cancelled = cancel_memory_toxic_active_jobs(
        active=active,
        terminal=terminal,
        pid=pid,
        rss_mb=rss_mb,
        cancel_job=cancel_job,
        recoverable_exceptions=recoverable_exceptions,
        record_suppressed=record_suppressed,
        job_records=job_records,
        worker_metrics=worker_metrics,
    )
    terminate_idle_memory_toxic_workers(
        procs=procs,
        active=active,
        pid=pid,
        owned_job_ids=owned,
        rss_mb=rss_mb,
        idle_worker_terminator=idle_worker_terminator,
        recoverable_exceptions=recoverable_exceptions,
        record_suppressed=record_suppressed,
        job_records=job_records,
        worker_metrics=worker_metrics,
    )
    return cancelled


__all__ = (
    "cancel_and_terminate_memory_toxic_worker",
    "record_malformed_worker_rss_metric",
    "worker_memory_metric_items",
)
