"""Pure next-check deadline projection for the canonical in-memory timeout owner."""
from __future__ import annotations

import math
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float

_MISSING = object()


def _nonnegative(value: object, default: float = 0.0) -> float:
    parsed, reason = scheduler_float(
        value,
        default=default,
        minimum=0.0,
        reason="inmemory_timeout_deadline_value_rejected",
        non_finite_reason="inmemory_timeout_deadline_value_non_finite",
    )
    return default if reason != "" or not math.isfinite(parsed) else parsed


def _field(record: object, name: str, default: object = None) -> object:
    items = no_hook_mapping_items(record)
    value = scheduler_mapping_item_value(items, name, _MISSING)
    return default if value is _MISSING else value


def _strictly_after(value: float) -> float:
    return math.nextafter(value, math.inf)


def _running_budget(record: Mapping[str, object], policy_value: object, budget_field: str) -> float:
    budget_info = _field(record, "timeout_budget", {})
    budget_items = no_hook_mapping_items(budget_info)
    record_value = scheduler_mapping_item_value(budget_items, budget_field, 0.0)
    return max(_nonnegative(policy_value), _nonnegative(record_value))


def next_timeout_check_deadline(
    *,
    record: object,
    now: float,
    queued_start_timeout_sec: float,
    assigned_start_timeout_sec: float,
    heartbeat_stale_sec: float,
    progress_stale_sec: float,
    base_pf_timeout: float,
    cancel_grace_sec: float,
    start_wait_budget: Callable[[Mapping[str, object], float], float],
) -> float | None:
    """Return the next semantic timeout boundary for one current live record."""
    if type(record) is not dict:
        return None
    state = _field(record, "state", "")
    if type(state) is not str:
        return None
    if state == "queued":
        armed_at = _nonnegative(_field(record, "queued_timeout_armed_at", 0.0))
        if armed_at <= 0.0:
            return now
        try:
            budget = _nonnegative(start_wait_budget(record, queued_start_timeout_sec), queued_start_timeout_sec)
        except (OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError):
            return now
        return _strictly_after(armed_at + budget)
    if state == "assigned":
        assigned_at = _nonnegative(_field(record, "assigned_at", 0.0))
        if assigned_at <= 0.0:
            return now
        try:
            budget = _nonnegative(start_wait_budget(record, assigned_start_timeout_sec), assigned_start_timeout_sec)
        except (OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError):
            return now
        return _strictly_after(assigned_at + budget)
    if state != "running":
        return None
    running_at = _nonnegative(_field(record, "running_at", 0.0))
    last_heartbeat = _nonnegative(_field(record, "last_heartbeat", running_at), running_at)
    last_progress = _nonnegative(_field(record, "last_progress_time", running_at), running_at)
    hard_budget = _running_budget(record, base_pf_timeout, "timeout_budget")
    heartbeat_budget = _running_budget(record, heartbeat_stale_sec, "heartbeat_stale_budget")
    progress_budget = _running_budget(record, progress_stale_sec, "stall_budget")
    candidates: list[float] = []
    if running_at > 0.0:
        candidates.append(_strictly_after(running_at + hard_budget))
    if last_heartbeat > 0.0:
        candidates.append(_strictly_after(last_heartbeat + heartbeat_budget))
    if last_progress > 0.0:
        progress_deadline = _strictly_after(last_progress + progress_budget)
        cancel_at = _nonnegative(_field(record, "cancel_requested_at", 0.0))
        if cancel_at > 0.0 and now > (last_progress + progress_budget):
            candidates.append(_strictly_after(cancel_at + _nonnegative(cancel_grace_sec)))
        else:
            candidates.append(progress_deadline)
    if not candidates:
        return now
    deadline = min(candidates)
    return deadline if deadline > now else now


__all__ = ("next_timeout_check_deadline",)
