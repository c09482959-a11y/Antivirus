"""Bounded normalization steps for process-queue startup state."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.orchestration.progress_state_freezing import freeze_scheduler_progress_state
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
)


def normalize_startup_ordered_items(value: object) -> tuple[object, ...]:
    if type(value) not in {list, tuple}:
        raise ValueError("process_queue_startup_ordered_items_rejected")
    return immutable_tuple(value)


def normalize_startup_identity_set(value: object) -> frozenset[str]:
    if type(value) not in {list, tuple, set, frozenset}:
        raise ValueError("process_queue_startup_identities_rejected")
    identities: set[str] = set()
    for item in value:
        if type(item) is not str or not item:
            raise ValueError("process_queue_startup_identity_rejected")
        identities.add(str.__str__(item))
    return frozenset(identities)


def normalize_startup_int_fields(values: dict[str, tuple[object, int]]) -> tuple[dict[str, int], list[str]]:
    normalized: dict[str, int] = {}
    reasons: list[str] = []
    for field_name, field_config in dict.items(values):
        value, minimum = field_config
        parsed, reason = scheduler_int(
            value,
            minimum=minimum,
            reason="process_queue_startup_" + str.__str__(field_name) + "_rejected",
        )
        normalized[field_name] = parsed
        if reason:
            reasons.append(reason)
    return normalized, reasons


def normalize_startup_scalar_fields(
    *,
    queue_last_feed_log: object,
    dynamic_queue_feed: object,
    elastic_scheduler: object,
) -> tuple[float, bool, bool, list[str]]:
    feed_log, feed_reason = scheduler_float(
        queue_last_feed_log,
        minimum=0.0,
        reason="process_queue_startup_feed_log_rejected",
    )
    dynamic_value, dynamic_reason = scheduler_bool(
        dynamic_queue_feed,
        reason="process_queue_startup_dynamic_feed_rejected",
    )
    elastic_value, elastic_reason = scheduler_bool(
        elastic_scheduler,
        reason="process_queue_startup_elastic_rejected",
    )
    return (
        feed_log,
        dynamic_value,
        elastic_value,
        [reason for reason in (feed_reason, dynamic_reason, elastic_reason) if reason],
    )


freeze_startup_progress_state = freeze_scheduler_progress_state


__all__ = (
    "freeze_startup_progress_state",
    "normalize_startup_identity_set",
    "normalize_startup_int_fields",
    "normalize_startup_ordered_items",
    "normalize_startup_scalar_fields",
)
