"""Bounded no-hook steps for queue worker termination cleanup."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_plain_instance_dict,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.queue.terminal_accounting_evidence import (
    report_terminal_accounting_failure,
    terminal_marker,
)
from Virus_Scan.scheduler.queue.terminal_accounting_support import owned_sequence


def termination_context_text(context: object, report: Callable[..., object] | None) -> str:
    if type(context) is str and context:
        return str.__str__(context)
    report_terminal_accounting_failure(
        report,
        "queue_termination_context_rejected",
        ValueError("queue_termination_context_rejected"),
    )
    return "queue_idle_finalization"


def termination_action_sequence(
    actions: object,
    *,
    report: Callable[..., object] | None,
) -> tuple[str, ...]:
    return tuple(
        action
        for action in owned_sequence(actions, field_name="worker_actions", report=report)
        if type(action) is str and action in {"terminate", "kill"}
    )


def reject_worker_tuple(
    *,
    report: Callable[..., object] | None,
    context_text: str,
    action: str,
    process_index: int,
) -> None:
    report_terminal_accounting_failure(
        report,
        terminal_marker(context_text, action, "worker_tuple_rejected"),
        ValueError("worker process tuple rejected"),
        extra={"process_index": process_index},
    )


def worker_index_for_item(
    *,
    item: tuple[object, ...],
    process_index: int,
    report: Callable[..., object] | None,
    context_text: str,
    action: str,
) -> int:
    candidate_worker_idx, worker_reason = no_hook_exact_nonnegative_int(
        item[0],
        reason="queue_worker_index_rejected",
        non_finite_reason="queue_worker_index_non_finite",
    )
    if not worker_reason:
        return candidate_worker_idx
    report_terminal_accounting_failure(
        report,
        terminal_marker(context_text, action, "worker_index_rejected"),
        ValueError(worker_reason),
        extra={"process_index": process_index},
    )
    return process_index


def termination_error_text(result_state: dict[str, object]) -> tuple[str, str]:
    raw_error = dict.get(result_state, "error")
    if type(raw_error) is str and raw_error:
        return str.__str__(raw_error), ""
    return "worker termination was not requested", "queue_termination_error_rejected"


def report_unrequested_termination(
    *,
    report: Callable[..., object] | None,
    context_text: str,
    action: str,
    worker_idx: int,
    result_state: dict[str, object],
) -> None:
    error_text, error_reason = termination_error_text(result_state)
    pid, _ = no_hook_exact_nonnegative_int(
        dict.get(result_state, "pid", 0),
        reason="queue_termination_pid_rejected",
        non_finite_reason="queue_termination_pid_non_finite",
    )
    report_terminal_accounting_failure(
        report,
        terminal_marker(context_text, action, "not_requested"),
        RuntimeError(error_text),
        extra={
            "worker_idx": worker_idx,
            "worker_pid": pid,
            "error_reason": error_reason,
        },
    )


def inspect_termination_result(
    *,
    result: object,
    report: Callable[..., object] | None,
    context_text: str,
    action: str,
    worker_idx: int,
) -> None:
    result_state = no_hook_plain_instance_dict(result)
    if result_state is None:
        return
    requested, requested_reason = scheduler_bool(
        dict.get(result_state, "requested", True),
        default=True,
        reason="queue_termination_requested_rejected",
    )
    completed, completed_reason = scheduler_bool(
        dict.get(result_state, "completed", True),
        default=True,
        reason="queue_termination_completed_rejected",
    )
    if requested_reason or completed_reason or (not requested and not completed):
        report_unrequested_termination(
            report=report,
            context_text=context_text,
            action=action,
            worker_idx=worker_idx,
            result_state=result_state,
        )


def terminate_worker_item(
    *,
    item: tuple[object, ...],
    process_index: int,
    action: str,
    terminate_worker: Callable[..., object],
    report: Callable[..., object] | None,
    context_text: str,
) -> None:
    worker_idx = worker_index_for_item(
        item=item,
        process_index=process_index,
        report=report,
        context_text=context_text,
        action=action,
    )
    try:
        result = terminate_worker(item[1], action=action, worker_idx=worker_idx)
        inspect_termination_result(
            result=result,
            report=report,
            context_text=context_text,
            action=action,
            worker_idx=worker_idx,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        report_terminal_accounting_failure(
            report,
            terminal_marker(context_text, action, "failed"),
            exc,
            extra={"worker_idx": worker_idx},
        )


__all__ = (
    "reject_worker_tuple",
    "terminate_worker_item",
    "termination_action_sequence",
    "termination_context_text",
)
