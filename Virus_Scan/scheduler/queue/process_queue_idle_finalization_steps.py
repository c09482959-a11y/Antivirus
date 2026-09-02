"""Bounded process-queue idle finalization decision steps."""
from __future__ import annotations

from collections.abc import Callable
from Virus_Scan.scheduler.queue.terminal_missing_finalization import finalize_missing_file_accounting

IdleBoolCoercer = Callable[[object], bool]


def missing_accounting_idle_decision(
    *,
    request: object,
    dependencies: object,
    idle_done_since: float | None,
    coerce_missing_had_error: IdleBoolCoercer,
    coerce_missing_terminated: IdleBoolCoercer,
) -> tuple[float | None, bool, bool]:
    """Handle idle state when file accounting is still incomplete."""
    if idle_done_since is None:
        return request.now, False, False
    terminated, missing_had_error = finalize_missing_file_accounting(
        feed_complete=request.feed_complete,
        no_live_queue_work=request.no_live_queue_work,
        accounted_files=request.accounted_files,
        total_files=request.total_files,
        idle_elapsed=request.now - idle_done_since,
        idle_grace_sec=request.idle_grace_sec,
        all_files=request.all_files,
        queue_dir=request.queue_dir,
        outputs_dir=request.outputs_dir,
        procs=request.procs,
        load_queue_file_results=dependencies.load_queue_file_results,
        worker_error_result=dependencies.worker_error_result,
        terminate_worker=dependencies.terminate_worker,
        report=dependencies.report,
        log_error=dependencies.log_error,
        sleep=dependencies.sleep,
    )
    return (
        idle_done_since,
        coerce_missing_had_error(missing_had_error),
        coerce_missing_terminated(terminated),
    )


def completed_accounting_idle_decision(
    *,
    request: object,
    dependencies: object,
    idle_done_since: float | None,
    idle_notice_sec: float,
    coerce_terminated: IdleBoolCoercer,
) -> tuple[float | None, float, bool]:
    """Handle idle state when all files have terminal accounting."""
    if idle_done_since is None:
        return request.now, idle_notice_sec, False
    finalization_request = dependencies.idle_queue_finalization_request_factory(
        no_live_queue_work=request.no_live_queue_work,
        accounted_files=request.accounted_files,
        total_files=request.total_files,
        idle_elapsed=request.now - idle_done_since,
        idle_notice_sec=idle_notice_sec,
        idle_grace_sec=request.idle_grace_sec,
        live_workers=request.live_workers,
        procs=request.procs,
        terminate_worker=dependencies.terminate_worker,
        report=dependencies.report,
        log_info=dependencies.log_info,
        sleep=dependencies.sleep,
    )
    terminated, next_idle_notice_sec = (
        dependencies.idle_queue_finalization_request_owner(finalization_request)
    )
    return (
        idle_done_since,
        next_idle_notice_sec,
        coerce_terminated(terminated),
    )


__all__ = (
    "completed_accounting_idle_decision",
    "missing_accounting_idle_decision",
)
