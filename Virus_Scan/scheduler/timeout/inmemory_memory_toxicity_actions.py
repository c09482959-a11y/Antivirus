"""Memory-toxicity cancellation and idle-worker termination actions."""
from __future__ import annotations

from typing import Mapping, MutableMapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items

from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_evidence import (
    attach_memory_toxicity_evidence,
    memory_toxicity_evidence,
)
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_policy import record_memory_toxicity_suppression
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_records import (
    memory_toxicity_affected_info,
    memory_toxicity_job_record_for,
)
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_cancel_steps import (
    cancel_memory_toxic_job,
    memory_toxic_job_pid_decision,
    record_active_job_pid_unavailable,
    should_cancel_memory_toxic_job,
)


def cancel_memory_toxic_active_jobs(
    *,
    active: Mapping[object, object],
    terminal: set[object],
    pid: object,
    rss_mb: float,
    cancel_job: object,
    recoverable_exceptions: object,
    record_suppressed: object,
    job_records: object=None,
    worker_metrics: object=None,
) -> int:
    """Request queue-owned cancellation for active jobs owned by a toxic worker."""

    cancelled = 0
    active_items = no_hook_mapping_items(active) or ()
    terminal_values = terminal if type(terminal) is set else set()
    for job_id, info in active_items:
        pid_decision = memory_toxic_job_pid_decision(info)
        if pid_decision.status != "accepted":
            record_active_job_pid_unavailable(
                info=info,
                job_records=job_records,
                worker_metrics=worker_metrics,
                pid=pid,
                job_id=job_id,
                rss_mb=rss_mb,
                pid_reason=pid_decision.reason,
                recoverable_exceptions=recoverable_exceptions,
                record_suppressed=record_suppressed,
            )
            continue
        if not should_cancel_memory_toxic_job(
            info=info,
            job_id=job_id,
            pid=pid,
            terminal_values=terminal_values,
        ):
            continue
        if cancel_memory_toxic_job(
            info=info,
            job_records=job_records,
            worker_metrics=worker_metrics,
            pid=pid,
            job_id=job_id,
            rss_mb=rss_mb,
            cancel_job=cancel_job,
            recoverable_exceptions=recoverable_exceptions,
            record_suppressed=record_suppressed,
        ):
            cancelled += 1
    return cancelled


def terminate_idle_memory_toxic_workers(
    *,
    procs: object,
    active: Mapping[object, object],
    pid: object,
    owned_job_ids: tuple[object, ...],
    rss_mb: float,
    idle_worker_terminator: object,
    recoverable_exceptions: object,
    record_suppressed: object,
    job_records: object=None,
    worker_metrics: object=None,
) -> None:
    """Terminate idle toxic workers and record evidence for recoverable failures."""

    for proc in tuple(procs):
        try:
            result = idle_worker_terminator(
                proc=proc,
                toxic_pid=pid,
                owned_job_ids=owned_job_ids,
                reason="worker_memory_toxic",
            )
        except recoverable_exceptions as terminate_exc:
            detail_error = record_memory_toxicity_suppression(
                error=terminate_exc,
                recoverable_exceptions=recoverable_exceptions,
                record_suppressed=record_suppressed,
            )
            _attach_termination_failure(
                active=active,
                job_records=job_records,
                worker_metrics=worker_metrics,
                pid=pid,
                owned_job_ids=owned_job_ids,
                rss_mb=rss_mb,
                reason="worker_memory_toxic_termination_exception",
                detail_error=detail_error,
            )
            continue
        if result.requested and not result.terminated and result.error not in {"already_exited", "worker_owns_active_jobs", "pid_mismatch"}:
            detail_error = record_memory_toxicity_suppression(
                error=RuntimeError(result.error),
                recoverable_exceptions=recoverable_exceptions,
                record_suppressed=record_suppressed,
            )
            _attach_termination_failure(
                active=active,
                job_records=job_records,
                worker_metrics=worker_metrics,
                pid=pid,
                owned_job_ids=owned_job_ids,
                rss_mb=rss_mb,
                reason="worker_memory_toxic_termination_failed",
                detail_error=detail_error,
            )


def _attach_termination_failure(
    *,
    active: Mapping[object, object],
    job_records: object,
    worker_metrics: object,
    pid: object,
    owned_job_ids: tuple[object, ...],
    rss_mb: float,
    reason: str,
    detail_error: BaseException,
) -> None:
    affected_job = owned_job_ids[0] if owned_job_ids else None
    attach_memory_toxicity_evidence(
        evidence=memory_toxicity_evidence(
            pid=pid,
            job_id=affected_job,
            reason=reason,
            action="terminate_idle_worker",
            rss_mb=rss_mb,
            error=detail_error,
            source="idle_worker_terminator",
        ),
        active_info=memory_toxicity_affected_info(active=active, job_id=affected_job),
        job_record=memory_toxicity_job_record_for(job_records, affected_job),
        worker_metrics=worker_metrics if isinstance(worker_metrics, MutableMapping) else None,
    )


__all__ = ("cancel_memory_toxic_active_jobs", "terminate_idle_memory_toxic_workers")
