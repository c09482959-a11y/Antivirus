"""Bounded final wait facade steps for process-queue workers."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.workers.cleanup_exit_result import (
    WorkerExitWaitResult,
)
from Virus_Scan.scheduler.workers.cleanup_no_hook import (
    cleanup_output_text,
    cleanup_timeout,
)
from Virus_Scan.scheduler.workers.cleanup_wait_status import (
    _WorkerExitIssueReporter,
    record_worker_exit_issue,
    wait_status,
)
from Virus_Scan.scheduler.workers.cleanup_wait_timeout import (
    WorkerCleanupTimeoutContext,
    _WorkerCleanupOS,
    timeout_worker_exit_result,
)
from Virus_Scan.scheduler.workers.process_control_no_hook import (
    safe_process_control_int,
    safe_process_pid,
)


@dataclass(frozen=True, slots=True)
class WorkerExitWaitStepContext:
    """Immutable inputs for a bounded final worker wait."""

    worker_idx: object
    output: object
    timeout_sec: object
    report_issue: _WorkerExitIssueReporter
    os_ops: _WorkerCleanupOS | None
    default_os_ops: _WorkerCleanupOS
    terminate_signal: int
    kill_signal: int


def wait_for_process_queue_worker_exit_steps(
    proc: object,
    context: WorkerExitWaitStepContext,
) -> WorkerExitWaitResult:
    idx, _idx_reason = safe_process_control_int(
        context.worker_idx,
        replacement_value=-1,
        minimum=-1,
        reason="worker_cleanup_index_rejected",
    )
    pid, _pid_reason = safe_process_pid(proc)
    os_owner = (
        context.default_os_ops
        if context.os_ops is None
        else context.os_ops
    )
    output_s = cleanup_output_text(context.output)
    timeout_value = cleanup_timeout(context.timeout_sec)
    cleanup_actions: list[str] = []
    failure_markers: list[str] = []
    try:
        status_i = wait_status(proc, timeout_value)
        return WorkerExitWaitResult(
            worker_idx=idx,
            pid=pid,
            output=output_s,
            status=status_i,
            timed_out=False,
            cleanup_actions=tuple(cleanup_actions),
            failure_markers=tuple(failure_markers),
        )
    except subprocess.TimeoutExpired as exc:
        return timeout_worker_exit_result(
            proc,
            WorkerCleanupTimeoutContext(
                idx=idx,
                pid=pid,
                output_s=output_s,
                timeout_value=timeout_value,
                report_issue=context.report_issue,
                os_owner=os_owner,
                default_os_ops=context.default_os_ops,
                terminate_signal=context.terminate_signal,
                kill_signal=context.kill_signal,
                cleanup_actions=cleanup_actions,
                failure_markers=failure_markers,
                timeout_exc=exc,
            ),
        )
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        failure_markers.append("queue_worker_final_wait_failed")
        record_worker_exit_issue(
            context.report_issue,
            failure_markers,
            "queue_worker_final_wait_failed",
            exc,
            idx,
            output_s,
        )
        timed_out, _timed_reason = scheduler_bool(
            value=False,
            default=False,
            reason="worker_cleanup_timeout_flag_rejected",
        )
        return WorkerExitWaitResult(
            worker_idx=idx,
            pid=pid,
            output=output_s,
            status=-1,
            timed_out=timed_out,
            cleanup_actions=tuple(cleanup_actions),
            failure_markers=tuple(failure_markers),
            reason="worker_final_wait_failed",
        )


__all__ = (
    "WorkerExitWaitStepContext",
    "wait_for_process_queue_worker_exit_steps",
)
