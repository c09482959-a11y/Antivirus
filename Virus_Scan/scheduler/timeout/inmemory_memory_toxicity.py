"""In-memory worker memory toxicity escalation ownership."""
from __future__ import annotations

from typing import MutableMapping

from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_policy import (
    append_global_memory_toxicity_evidence,
    coerce_memory_toxicity_float,
    malformed_memory_toxicity_limit_evidence,
    record_memory_toxicity_suppression,
)
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_steps import (
    cancel_and_terminate_memory_toxic_worker,
    record_malformed_worker_rss_metric,
    worker_memory_metric_items,
)


def enforce_worker_memory_toxicity(*, procs: object, active: object, terminal: object, worker_metrics: object, rss_limit_mb: object, cancel_job: object, idle_worker_terminator: object, recoverable_exceptions: object, record_suppressed: object, job_records: object=None) -> object:
    """Request cancellation for over-budget workers and terminate idle toxic workers."""

    cancelled = 0
    try:
        rss_limit_value = coerce_memory_toxicity_float(value=rss_limit_mb, field="rss_limit_mb")
    except (TypeError, ValueError, OverflowError) as limit_exc:
        detail_error = record_memory_toxicity_suppression(
            error=limit_exc,
            recoverable_exceptions=recoverable_exceptions,
            record_suppressed=record_suppressed,
        )
        append_global_memory_toxicity_evidence(
            worker_metrics=worker_metrics,
            evidence=malformed_memory_toxicity_limit_evidence(error=detail_error),
        )
        return cancelled
    if rss_limit_value <= 0.0:
        return cancelled
    for pid, metrics in worker_memory_metric_items(worker_metrics):
        if not isinstance(metrics, MutableMapping):
            continue
        try:
            rss_mb = coerce_memory_toxicity_float(value=metrics.get("rss_mb"), field="rss_mb")
        except (TypeError, ValueError, OverflowError) as rss_exc:
            record_malformed_worker_rss_metric(
                active=active,
                job_records=job_records,
                worker_metrics=worker_metrics,
                pid=pid,
                rss_error=rss_exc,
                recoverable_exceptions=recoverable_exceptions,
                record_suppressed=record_suppressed,
            )
            continue
        if rss_mb <= rss_limit_value:
            continue
        cancelled += cancel_and_terminate_memory_toxic_worker(
            procs=procs,
            active=active,
            terminal=terminal,
            worker_metrics=worker_metrics,
            pid=pid,
            rss_mb=rss_mb,
            cancel_job=cancel_job,
            idle_worker_terminator=idle_worker_terminator,
            recoverable_exceptions=recoverable_exceptions,
            record_suppressed=record_suppressed,
            job_records=job_records,
        )
    return cancelled


__all__ = ("enforce_worker_memory_toxicity",)
