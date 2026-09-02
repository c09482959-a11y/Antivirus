"""Canonical scheduler JSON policy and publication facade."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.evidence.records import build_scheduler_json_evidence_section
from Virus_Scan.scheduler.evidence.scheduler_json_durable import (
    RawQueueJsonDependencies,
    raw_unlink_quiet,
    write_json_durable,
    write_process_queue_json_durable,
)
from Virus_Scan.scheduler.evidence.scheduler_json_partial import write_partial_scheduler_results
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.evidence.scheduler_json_writer_support import (
    raw_policy_int,
    raw_policy_issue_label,
    raw_policy_label,
    raw_policy_rejected_reason,
)


def _record_raw_policy_issue(
    record_suppressed: Callable[[str, BaseException], object] | None,
    where: str,
    exc: BaseException,
) -> None:
    if record_suppressed is None:
        return
    try:
        record_suppressed(where, exc)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS:
        return


def _raw_int_policy(
    name: str,
    *,
    default: int,
    minimum: int,
    runtime_value: Callable[..., object],
    record_suppressed: Callable[[str, BaseException], object] | None,
) -> int:
    label = raw_policy_label(name)
    try:
        raw_value = runtime_value(name, default)
    except (TypeError, ValueError, RuntimeError) as exc:
        _record_raw_policy_issue(record_suppressed, raw_policy_issue_label(label), exc)
        raw_value = default
    parsed, reason = raw_policy_int(
        raw_value,
        default_value=default,
        minimum=minimum,
        rejected_reason=raw_policy_rejected_reason(label),
    )
    if reason:
        _record_raw_policy_issue(record_suppressed, raw_policy_issue_label(label), ValueError(reason))
    return parsed


def raw_chunk_bytes(
    *,
    default: int = 65536,
    runtime_value: Callable[..., object],
    record_suppressed: Callable[[str, BaseException], object] | None = None,
) -> int:
    return _raw_int_policy(
        "GLOBAL_RAW_QUEUE_CHUNK_BYTES",
        default=default,
        minimum=1,
        runtime_value=runtime_value,
        record_suppressed=record_suppressed,
    )


def raw_queue_max_chunks(
    *,
    default: int = 192,
    runtime_value: Callable[..., object],
    record_suppressed: Callable[[str, BaseException], object] | None = None,
) -> int:
    return _raw_int_policy(
        "GLOBAL_RAW_QUEUE_MAX_CHUNKS",
        default=default,
        minimum=1,
        runtime_value=runtime_value,
        record_suppressed=record_suppressed,
    )


def raw_queue_enabled(
    *,
    runtime_value: Callable[..., object],
    record_suppressed: Callable[[str, BaseException], object] | None = None,
) -> bool:
    try:
        raw_value = runtime_value("GLOBAL_RAW_QUEUE_ENABLED", default=False)
    except (TypeError, ValueError, RuntimeError) as exc:
        _record_raw_policy_issue(record_suppressed, "raw_queue_enabled_policy_issue", exc)
        raw_value = False
    enabled, reason = scheduler_bool(
        raw_value, default=False, reason="raw_queue_enabled_policy_rejected"
    )
    if reason:
        _record_raw_policy_issue(record_suppressed, "raw_queue_enabled_policy_issue", ValueError(reason))
    return enabled


def raw_queue_min_bytes(
    *,
    default: int = 0,
    runtime_value: Callable[..., object],
    record_suppressed: Callable[[str, BaseException], object] | None = None,
) -> int:
    return _raw_int_policy(
        "GLOBAL_RAW_QUEUE_MIN_BYTES",
        default=default,
        minimum=0,
        runtime_value=runtime_value,
        record_suppressed=record_suppressed,
    )


def build_scheduler_json_section(
    records: object, *, checkpoint_status: object = None, replay_status: object = None
) -> dict[str, object]:
    """Build the canonical final-JSON scheduler section from immutable evidence."""
    return build_scheduler_json_evidence_section(
        records,
        checkpoint_status={} if checkpoint_status is None else checkpoint_status,
        replay_status={} if replay_status is None else replay_status,
    )


__all__ = (
    "RawQueueJsonDependencies",
    "build_scheduler_json_section",
    "raw_chunk_bytes",
    "raw_queue_enabled",
    "raw_queue_max_chunks",
    "raw_queue_min_bytes",
    "raw_unlink_quiet",
    "write_json_durable",
    "write_partial_scheduler_results",
    "write_process_queue_json_durable",
)
