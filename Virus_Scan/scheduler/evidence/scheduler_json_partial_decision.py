"""Checkpoint due-policy and pending-delta selection for scheduler JSON output."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.scheduler.evidence.partial_output_support import (
    partial_due_by_count,
    partial_timestamp_value,
)
from Virus_Scan.scheduler.evidence.scheduler_json_partial_inputs import (
    SchedulerCheckpointInputs,
    resolve_checkpoint_clock,
    resolve_checkpoint_inputs,
)


@dataclass(frozen=True, slots=True)
class SchedulerCheckpointDecision:
    """Replayable decision for one partial checkpoint publication attempt."""

    target: str
    payload: object | None
    last_written: float
    current: float
    should_write: bool


def _observe_terminal(
    checkpoint_cache: PartialCheckpointCache | None,
    results: object,
    make_json_safe: object,
    *,
    force: bool,
) -> None:
    if type(checkpoint_cache) is not PartialCheckpointCache:
        return
    if force:
        checkpoint_cache.reconcile_results(results, make_json_safe)
        return
    checkpoint_cache.observe_latest_terminal(results, make_json_safe)


def _pending_payload(
    checkpoint_cache: PartialCheckpointCache | None,
    results: object,
) -> object:
    if type(checkpoint_cache) is PartialCheckpointCache:
        return checkpoint_cache.pending_delta()
    return results


def _count_due(inputs: SchedulerCheckpointInputs) -> bool:
    return (
        inputs.force
        or inputs.result_count == 1
        or partial_due_by_count(inputs.result_count, inputs.every)
    )


def _not_due(inputs: SchedulerCheckpointInputs) -> SchedulerCheckpointDecision:
    return SchedulerCheckpointDecision(
        inputs.target,
        None,
        inputs.last_written,
        inputs.last_written,
        False,
    )


def _timed_decision(
    inputs: SchedulerCheckpointInputs,
    timing: tuple[float, float],
    checkpoint_cache: PartialCheckpointCache | None,
    results: object,
) -> SchedulerCheckpointDecision:
    current, min_interval = timing
    due = inputs.force or current - inputs.last_written >= min_interval
    payload = _pending_payload(checkpoint_cache, results) if due else None
    return SchedulerCheckpointDecision(
        inputs.target,
        payload,
        inputs.last_written,
        current,
        due,
    )


def scheduler_checkpoint_decision(
    *,
    partial_output_path: object,
    results: object,
    total_files: object,
    partial_output_every: object,
    last_partial_write: object,
    now: object,
    environ_get: object,
    make_json_safe: object,
    log_error: object,
    checkpoint_cache: PartialCheckpointCache | None,
    force: object,
) -> SchedulerCheckpointDecision | None:
    """Observe one terminal result and build a payload only when due."""
    inputs = resolve_checkpoint_inputs(
        partial_output_path=partial_output_path, results=results,
        total_files=total_files, partial_output_every=partial_output_every,
        last_partial_write=last_partial_write, force=force, log_error=log_error,
    )
    if inputs is None:
        return None
    _observe_terminal(
        checkpoint_cache, results, make_json_safe, force=inputs.force,
    )
    if (
        inputs.result_count >= inputs.total_files
        and not inputs.force
        or not _count_due(inputs)
    ):
        return _not_due(inputs)
    timing = resolve_checkpoint_clock(now, environ_get, log_error)
    return _not_due(inputs) if timing is None else _timed_decision(
        inputs, timing, checkpoint_cache, results,
    )


def unchanged_checkpoint_time(
    decision: SchedulerCheckpointDecision | None,
    *,
    last_partial_write: object,
    log_error: object,
) -> float:
    """Return the prior checkpoint timestamp through the strict boundary."""
    if decision is not None:
        return decision.last_written
    return partial_timestamp_value(
        last_partial_write,
        context="scheduler_json_partial",
        field="last_partial_write",
        log_error=log_error,
    )


__all__ = (
    "SchedulerCheckpointDecision",
    "scheduler_checkpoint_decision",
    "unchanged_checkpoint_time",
)
