"""No-hook process-queue dynamic feed support."""
from __future__ import annotations

from typing import Mapping, TYPE_CHECKING

from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_items
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
    scheduler_path_text,
    scheduler_value_snapshot,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_contracts import (
        ProcessQueueDynamicFeedDependencies,
    )


def feed_issue(field_name: str, value: object, reason: str) -> Mapping[str, object]:
    return {
        "process_queue_dynamic_feed_input_rejected": True,
        "field_name": field_name,
        "reason": reason,
        "value": scheduler_value_snapshot(value, field_name=field_name),
    }


def feed_int(
    value: object, *, field_name: str, default: int = 0
) -> tuple[int, tuple[Mapping[str, object], ...]]:
    parsed, reason = scheduler_int(
        value,
        default=default,
        minimum=0,
        reason="process_queue_feed_" + str.__str__(field_name) + "_rejected",
    )
    return (
        (parsed, ())
        if reason == ""
        else (parsed, (feed_issue(field_name, value, reason),))
    )


def feed_float(
    value: object, *, field_name: str, default: float = 0.0
) -> tuple[float, tuple[Mapping[str, object], ...]]:
    parsed, reason = scheduler_float(
        value,
        default=default,
        minimum=0.0,
        reason="process_queue_feed_" + str.__str__(field_name) + "_rejected",
    )
    return (
        (parsed, ())
        if reason == ""
        else (parsed, (feed_issue(field_name, value, reason),))
    )


def feed_bool(
    value: object, *, field_name: str, default: bool = False
) -> tuple[bool, tuple[Mapping[str, object], ...]]:
    parsed, reason = scheduler_bool(
        value,
        default=default,
        reason="process_queue_feed_" + str.__str__(field_name) + "_rejected",
    )
    return (
        (parsed, ())
        if reason == ""
        else (parsed, (feed_issue(field_name, value, reason),))
    )


def record_feed_issue(
    deps: ProcessQueueDynamicFeedDependencies,
    stage: str,
    reason: str,
    *,
    queue_dir: object,
    extra: Mapping[str, object],
) -> None:
    queue_path, path_reason = scheduler_path_text(queue_dir)
    deps.record_issue(
        stage,
        ValueError(reason),
        fatal=False,
        extra={
            "queue_dir": queue_path if path_reason == "" else "",
            "queue_dir_reason": path_reason,
            "detail": materialize_scheduler_mapping(extra),
        },
    )


def safe_recoverable_exceptions(values: object) -> tuple[type[BaseException], ...]:
    out: list[type[BaseException]] = []
    if type(values) is tuple:
        for item in values:
            if type(item) is type:
                try:
                    if issubclass(item, BaseException):
                        out.append(item)
                except TypeError:
                    continue
    return tuple(out) or (OSError, RuntimeError, TypeError, ValueError)


def safe_write_result(value: object) -> tuple[int, int, int]:
    if type(value) is not tuple or len(value) < 3:
        raise ValueError("process_queue_feed_write_result_rejected")
    names = ("cursor", "count", "skipped")
    parsed: list[int] = []
    for index, name in enumerate(names):
        item, reason = scheduler_int(
            value[index],
            default=0,
            minimum=0,
            reason="process_queue_feed_write_" + str.__str__(name) + "_rejected",
        )
        if reason:
            raise ValueError(reason)
        parsed.append(item)
    return parsed[0], parsed[1], parsed[2]


def safe_counts(value: object) -> dict[str, object]:
    if scheduler_mapping_items(value) is None:
        raise ValueError("process_queue_feed_counts_rejected")
    materialized = materialize_scheduler_mapping(value)
    if type(materialized) is not dict:
        raise ValueError("process_queue_feed_counts_materialization_failed")
    return materialized


__all__ = (
    "feed_bool",
    "feed_float",
    "feed_int",
    "feed_issue",
    "record_feed_issue",
    "safe_counts",
    "safe_recoverable_exceptions",
    "safe_write_result",
)
