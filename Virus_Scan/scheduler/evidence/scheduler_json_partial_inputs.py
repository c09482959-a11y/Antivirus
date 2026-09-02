"""Strict input and clock resolution for scheduler checkpoint decisions."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.evidence.partial_output_support import (
    emit_partial_output_log,
    partial_every_value,
    partial_force_value,
    partial_output_target,
    partial_result_count,
    partial_timestamp_value,
    partial_total_files_value,
)


@dataclass(frozen=True, slots=True)
class SchedulerCheckpointInputs:
    """Validated count and policy inputs for one checkpoint decision."""

    target: str
    result_count: int
    every: int
    last_written: float
    total_files: int
    force: bool


def resolve_checkpoint_inputs(
    *,
    partial_output_path: object,
    results: object,
    total_files: object,
    partial_output_every: object,
    last_partial_write: object,
    force: object,
    log_error: object,
) -> SchedulerCheckpointInputs | None:
    """Resolve strict checkpoint count inputs without materializing results."""
    context = "scheduler_json_partial"
    target, _reason = partial_output_target(
        partial_output_path, context=context, log_error=log_error,
    )
    result_count = partial_result_count(results, context=context, log_error=log_error)
    every = partial_every_value(partial_output_every, context=context, log_error=log_error)
    if target == "" or result_count is None or every <= 0:
        return None
    return SchedulerCheckpointInputs(
        target=target,
        result_count=result_count,
        every=every,
        last_written=partial_timestamp_value(
            last_partial_write, context=context,
            field="last_partial_write", log_error=log_error,
        ),
        total_files=partial_total_files_value(
            total_files, context=context, log_error=log_error,
        ),
        force=partial_force_value(
            force, context=context, log_error=log_error,
        ),
    )


def resolve_checkpoint_clock(
    now: object,
    environ_get: object,
    log_error: object,
) -> tuple[float, float] | None:
    """Resolve current time and minimum checkpoint interval fail-closed."""
    context = "scheduler_json_partial"
    try:
        current_raw = now()
    except (OSError, RuntimeError, TypeError, ValueError):
        emit_partial_output_log(
            log_error,
            context + ": partial_now rejected without caller hooks: now_failed",
        )
        return None
    current = partial_timestamp_value(
        current_raw,
        context=context,
        field="partial_now",
        log_error=log_error,
    )
    try:
        interval_raw = environ_get(
            "UMIGE_PARTIAL_CHECKPOINT_MIN_INTERVAL_SEC",
            "2.0",
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        interval_raw = "2.0"
        emit_partial_output_log(
            log_error,
            context + ": min_interval rejected without caller hooks: environ_get_failed",
        )
    interval = partial_timestamp_value(
        interval_raw,
        context=context,
        field="min_interval",
        log_error=log_error,
    )
    return current, max(0.25, interval or 2.0)


__all__ = (
    "SchedulerCheckpointInputs",
    "resolve_checkpoint_clock",
    "resolve_checkpoint_inputs",
)
