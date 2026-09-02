"""No-hook scalar ownership for process queue feed policy."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int


_INTEGER_REJECTION_SEED = 0
_FLOAT_REJECTION_SEED = 0.0


@dataclass(frozen=True, slots=True)
class FeedPolicyFieldsRequest:
    pending_multiplier: object
    min_pending_buffer: object
    pending_buffer: object
    max_file_feed_burst: object
    pressure_pending_buffer: object
    keep_pending_full: object


def feed_int(value: object, *, minimum: int = 0, reason: str) -> int:
    if value is None:
        raise ValueError(reason)
    parsed, rejection = scheduler_int(
        value,
        default=_INTEGER_REJECTION_SEED,
        minimum=minimum,
        reason=reason,
    )
    if rejection:
        raise ValueError(rejection)
    return parsed


def feed_float(value: object, *, minimum: float, reason: str) -> float:
    if value is None:
        raise ValueError(reason)
    parsed, rejection = scheduler_float(
        value,
        default=_FLOAT_REJECTION_SEED,
        minimum=minimum,
        reason=reason,
    )
    if rejection:
        raise ValueError(rejection)
    return parsed


def feed_bool(value: object, *, reason: str) -> bool:
    if value is None:
        raise ValueError(reason)
    parsed, rejection = scheduler_bool(value, default=False, reason=reason)
    if rejection:
        raise ValueError(rejection)
    return parsed


def normalize_feed_policy_fields(request: FeedPolicyFieldsRequest) -> tuple[float, int, int, int, int, bool]:
    return (
        feed_float(
            request.pending_multiplier,
            minimum=0.5,
            reason="process_queue_feed_pending_multiplier_rejected",
        ),
        feed_int(
            request.min_pending_buffer,
            minimum=0,
            reason="process_queue_feed_min_pending_rejected",
        ),
        feed_int(
            request.pending_buffer,
            minimum=0,
            reason="process_queue_feed_pending_buffer_rejected",
        ),
        feed_int(
            request.max_file_feed_burst,
            minimum=1,
            reason="process_queue_feed_burst_rejected",
        ),
        feed_int(
            request.pressure_pending_buffer,
            minimum=0,
            reason="process_queue_feed_pressure_pending_rejected",
        ),
        feed_bool(
            request.keep_pending_full,
            reason="process_queue_feed_keep_pending_rejected",
        ),
    )


def normalize_feed_decision_fields(
    *,
    target_workers: object,
    pending_buffer: object,
    desired_file_live: object,
    feed_capacity: object,
) -> tuple[int, int, int, int]:
    return (
        feed_int(target_workers, minimum=0, reason="process_queue_feed_target_workers_rejected"),
        feed_int(pending_buffer, minimum=0, reason="process_queue_feed_pending_buffer_rejected"),
        feed_int(desired_file_live, minimum=0, reason="process_queue_feed_desired_live_rejected"),
        feed_int(feed_capacity, minimum=0, reason="process_queue_feed_capacity_rejected"),
    )


__all__ = (
    "FeedPolicyFieldsRequest",
    "feed_bool",
    "feed_float",
    "feed_int",
    "normalize_feed_decision_fields",
    "normalize_feed_policy_fields",
)
