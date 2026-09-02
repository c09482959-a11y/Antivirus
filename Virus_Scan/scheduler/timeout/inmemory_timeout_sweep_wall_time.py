"""Wall-time failure materialization for in-memory timeout sweeps."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_exception_text
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import timeout_reporting_failure
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_contracts import TimeoutSweepWallTimeFailureRequest
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_result import InMemoryTimeoutSweepResult, build_inmemory_timeout_sweep_result


def build_timeout_sweep_wall_time_failure_result(
    request: TimeoutSweepWallTimeFailureRequest,
) -> InMemoryTimeoutSweepResult:
    """Return an explicit timeout sweep failure result when wall-time cannot be read."""

    detail_error: BaseException = request.error
    try:
        request.record_scheduler_suppressed("suppressed_exception", request.error)
    except request.recoverable_exceptions as record_exc:
        detail_error = RuntimeError(
            scheduler_exception_text(request.error)
            + "; suppression_record_failed="
            + scheduler_exception_text(record_exc)
        )
    request.timeout_reporting_failures.append(
        timeout_reporting_failure(
            job_id="timeout_sweep",
            reason="wall_time_read_failed",
            error=detail_error,
        )
    )
    return build_inmemory_timeout_sweep_result(
        evaluated=0,
        queued_waits=0,
        assigned_waits=0,
        hard_timeouts=0,
        orphaned_workers=0,
        progress_stalls=0,
        cancelled_after_stall=0,
        shared_heartbeat_result=request.shared_heartbeat_result,
        timeout_retry_evidence=request.timeout_retry_evidence,
        timeout_reporting_failures=request.timeout_reporting_failures,
    )


__all__ = ("build_timeout_sweep_wall_time_failure_result",)
