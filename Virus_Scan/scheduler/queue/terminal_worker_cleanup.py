"""Deterministic queue worker process cleanup."""
from __future__ import annotations

from typing import Callable, Iterable

from Virus_Scan.scheduler.queue.terminal_accounting_support import owned_sequence
from Virus_Scan.scheduler.queue.terminal_worker_cleanup_steps import (
    reject_worker_tuple,
    terminate_worker_item,
    termination_action_sequence,
    termination_context_text,
)


def terminate_processes(
    procs: Iterable[tuple[object, object, object, object]],
    *,
    actions: tuple[str, ...] = ("terminate", "kill"),
    terminate_worker: Callable[..., object],
    report: Callable[..., object] | None = None,
    sleep: Callable[[float], object] | None = None,
    context: str = "queue_idle_finalization",
) -> None:
    proc_list = owned_sequence(procs, field_name="worker_processes", report=report)
    action_list = termination_action_sequence(actions, report=report)
    context_text = termination_context_text(context, report)
    for action_index, action in enumerate(action_list):
        for process_index, item in enumerate(proc_list):
            if type(item) is not tuple or len(item) < 4:
                reject_worker_tuple(
                    report=report,
                    context_text=context_text,
                    action=action,
                    process_index=process_index,
                )
                continue
            terminate_worker_item(
                item=item,
                process_index=process_index,
                action=action,
                terminate_worker=terminate_worker,
                report=report,
                context_text=context_text,
            )
        if action_index < len(action_list) - 1 and sleep is not None:
            sleep(1.0)


__all__ = ("terminate_processes",)
