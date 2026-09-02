"""Shared-heartbeat ingestion for in-memory timeout sweeps."""
from __future__ import annotations

from types import SimpleNamespace

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_exception_text
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import timeout_reporting_failure
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_contracts import SharedHeartbeatIngestionRequest


def ingest_timeout_sweep_shared_heartbeats(request: SharedHeartbeatIngestionRequest) -> object:
    """Ingest bounded active-worker heartbeats and convert failures to evidence."""

    try:
        return request.heartbeat_ingester(
            active_job_ids=request.active_job_ids,
            job_records=request.job_records,
            active=request.active,
            terminal=request.terminal,
            worker_heartbeats=request.worker_heartbeats,
            worker_metrics=request.worker_metrics,
            heartbeat_table=request.heartbeat_table,
            heartbeat_flags=request.heartbeat_flags,
            read_heartbeat=request.read_heartbeat,
            cancel_job=request.cancel_job,
            lifecycle_recorder=request.lifecycle_recorder,
            monotonic_ns=request.monotonic_ns,
            wall_time=request.wall_time,
        )
    except request.recoverable_exceptions as heartbeat_ingest_exc:
        detail_error: BaseException = heartbeat_ingest_exc
        try:
            request.record_scheduler_suppressed("suppressed_exception", heartbeat_ingest_exc)
        except request.recoverable_exceptions as record_exc:
            detail_error = RuntimeError(
                scheduler_exception_text(heartbeat_ingest_exc)
                + "; suppression_record_failed="
                + scheduler_exception_text(record_exc)
            )
        request.timeout_reporting_failures.append(
            timeout_reporting_failure(
                job_id="shared_heartbeat",
                reason="shared_heartbeat_ingest_failed",
                error=detail_error,
            )
        )
        return SimpleNamespace(observed=0, cancel_requested=0)


__all__ = ("ingest_timeout_sweep_shared_heartbeats",)
