"""Routing-owned intrastage task admission through one session executor owner."""
from __future__ import annotations

from collections.abc import Callable

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.routing.intrastage_executor_session import (
    effective_intrastage_backend,
    effective_intrastage_enabled,
    effective_stage_parallel_workers,
    execute_intrastage_tasks,
)


def _intrastage_text(value: object, *, default: object = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="intrastage_text_missing",
        unsupported_reason="intrastage_text_rejected",
    )
    return default if reason else text


def _intrastage_worker_count(value: object, *, default: object) -> int:
    workers, reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason="intrastage_worker_count_rejected",
        non_finite_reason="intrastage_worker_count_rejected",
    )
    return default if reason or workers < 1 else workers


def _exact_raw_tasks(
    tasks: object,
) -> list[tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]]]:
    exact: list[tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]]] = []
    for item in no_hook_sequence_items(tasks):
        if type(item) is not tuple or len(item) != 4:
            raise TypeError("intrastage_task_contract_invalid")
        name, fn, args, kwargs = item
        if not callable(fn):
            raise TypeError("intrastage_task_callable_invalid")
        if type(args) is not tuple:
            raise TypeError("intrastage_task_args_invalid")
        if type(kwargs) is not dict or any(type(key) is not str for key in dict.keys(kwargs)):
            raise TypeError("intrastage_task_kwargs_invalid")
        exact.append((name, fn, args, dict(kwargs)))
    return exact


def run_raw_task_queue(
    tasks: object,
    max_workers: object = None,
    backend: object = None,
) -> object:
    """Run raw evidence tasks through the active session-owned executor."""
    task_items = _exact_raw_tasks(tasks)
    if not task_items:
        return []
    default_workers = effective_stage_parallel_workers()
    requested_workers = default_workers if max_workers is None else max_workers
    workers = max(
        1,
        min(
            _intrastage_worker_count(requested_workers, default=default_workers),
            len(task_items),
        ),
    )
    if not effective_intrastage_enabled():
        workers = 1
    safe_backend = _intrastage_text(
        backend,
        default=effective_intrastage_backend(),
    ).lower()
    if safe_backend not in {"thread", "process"}:
        safe_backend = effective_intrastage_backend()
    return execute_intrastage_tasks(
        task_items,
        backend=safe_backend,
        requested_workers=workers,
    )


__all__ = ("run_raw_task_queue",)
