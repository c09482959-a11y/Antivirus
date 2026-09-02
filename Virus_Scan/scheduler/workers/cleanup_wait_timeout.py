"""Timeout cleanup action steps for final process-queue worker waits."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Protocol

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.workers.cleanup_exit_result import (
    WorkerExitWaitResult,
)
from Virus_Scan.scheduler.workers.cleanup_no_hook import call_cleanup_method
from Virus_Scan.scheduler.workers.cleanup_wait_status import (
    _WorkerExitIssueReporter,
    record_worker_exit_issue,
    wait_status,
)

_CLEANUP_ACTIONS = ("terminate", "kill")


class _WorkerCleanupOS(Protocol):
    """OS operations required by bounded worker cleanup."""

    @property
    def name(self) -> str:
        ...

    def getpgid(self, pid: int) -> int:
        ...

    def killpg(self, pgid: int, sig: int) -> None:
        ...


@dataclass(frozen=True, slots=True)
class WorkerCleanupTimeoutContext:
    """Immutable context for final worker timeout cleanup."""

    idx: int
    pid: int
    output_s: str
    timeout_value: float
    report_issue: _WorkerExitIssueReporter
    os_owner: _WorkerCleanupOS
    default_os_ops: _WorkerCleanupOS
    terminate_signal: int
    kill_signal: int
    cleanup_actions: list[str]
    failure_markers: list[str]
    timeout_exc: subprocess.TimeoutExpired


def timeout_worker_exit_result(
    proc: object,
    context: WorkerCleanupTimeoutContext,
) -> WorkerExitWaitResult:
    context.failure_markers.append("queue_worker_final_wait_timeout")
    record_worker_exit_issue(
        context.report_issue,
        context.failure_markers,
        "queue_worker_final_wait_timeout",
        context.timeout_exc,
        context.idx,
        context.output_s,
    )
    for action in _CLEANUP_ACTIONS:
        _attempt_cleanup_action(
            proc,
            action=action,
            context=context,
        )
        result = _wait_after_cleanup(
            proc,
            action=action,
            context=context,
        )
        if result is not None:
            return result
    return WorkerExitWaitResult(
        worker_idx=context.idx,
        pid=context.pid,
        output=context.output_s,
        status=-1,
        timed_out=True,
        cleanup_actions=tuple(context.cleanup_actions),
        failure_markers=tuple(context.failure_markers),
        reason="worker_final_wait_timeout",
    )


def _attempt_cleanup_action(
    proc: object,
    *,
    action: str,
    context: WorkerCleanupTimeoutContext,
) -> None:
    try:
        poll_result, poll_reason = call_cleanup_method(proc, "poll")
        if poll_reason:
            raise RuntimeError(poll_reason) from context.timeout_exc
        if poll_result is None:
            context.cleanup_actions.append(action)
            _execute_cleanup_action(
                proc,
                action,
                context=context,
            )
    except (OSError, RuntimeError, TypeError, ValueError) as kill_exc:
        marker = "queue_worker_final_" + action + "_failed"
        context.failure_markers.append(marker)
        record_worker_exit_issue(
            context.report_issue,
            context.failure_markers,
            marker,
            kill_exc,
            context.idx,
            context.output_s,
        )


def _execute_cleanup_action(
    proc: object,
    action: str,
    *,
    context: WorkerCleanupTimeoutContext,
) -> None:
    uses_default_owner = context.os_owner is context.default_os_ops
    is_posix_owner = context.os_owner.name != "nt"
    has_pid = context.pid > 0
    if all((uses_default_owner, is_posix_owner, has_pid)):
        try:
            process_signal = (
                context.terminate_signal
                if action == "terminate"
                else context.kill_signal
            )
            context.os_owner.killpg(
                context.os_owner.getpgid(context.pid),
                process_signal,
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            call_cleanup_method(proc, action)
    else:
        call_cleanup_method(proc, action)


def _wait_after_cleanup(
    proc: object,
    *,
    action: str,
    context: WorkerCleanupTimeoutContext,
) -> WorkerExitWaitResult | None:
    try:
        status_i = wait_status(proc, context.timeout_value)
        return WorkerExitWaitResult(
            worker_idx=context.idx,
            pid=context.pid,
            output=context.output_s,
            status=status_i,
            timed_out=True,
            cleanup_actions=tuple(context.cleanup_actions),
            failure_markers=tuple(context.failure_markers),
        )
    except subprocess.TimeoutExpired:
        return None
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as wait_exc:
        marker = "queue_worker_final_" + action + "_wait_failed"
        context.failure_markers.append(marker)
        record_worker_exit_issue(
            context.report_issue,
            context.failure_markers,
            marker,
            wait_exc,
            context.idx,
            context.output_s,
        )
        return WorkerExitWaitResult(
            worker_idx=context.idx,
            pid=context.pid,
            output=context.output_s,
            status=-1,
            timed_out=True,
            cleanup_actions=tuple(context.cleanup_actions),
            failure_markers=tuple(context.failure_markers),
            reason="worker_final_wait_failed",
        )


__all__ = ("WorkerCleanupTimeoutContext", "timeout_worker_exit_result")
