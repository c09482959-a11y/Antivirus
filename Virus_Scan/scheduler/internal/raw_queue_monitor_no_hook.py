"""No-hook support for raw queue monitor evidence."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_text,
)
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_path


@dataclass(frozen=True)
class PlainSchedulerMappingDecision:
    status: str
    reason: str
    mapping: dict[str, object]
    evidence: Mapping[str, object] | None = None


@dataclass(frozen=True)
class QueueDirPathDecision:
    status: str
    reason: str
    path: Path | None
    evidence: object = None


@dataclass(frozen=True)
class DiskBusyTimeDecision:
    status: str
    reason: str
    busy_time: float | None


def plain_scheduler_mapping_decision(value: object, *, field_name: str) -> PlainSchedulerMappingDecision:
    """Materialize exact scheduler-owned mappings without caller hooks and expose failure state."""
    if value is None:
        return PlainSchedulerMappingDecision(
            status="missing",
            reason="missing_scheduler_mapping",
            mapping={},
        )
    reason = (
        str.__add__("unsupported_", str.__str__(field_name))
        if type(field_name) is str and field_name
        else "unsupported_scheduler_mapping"
    )
    items = no_hook_mapping_items(value)
    if items is None:
        evidence = unsupported_scheduler_value_evidence(value, field_name=field_name)
        return PlainSchedulerMappingDecision(
            status="unsupported",
            reason=reason,
            mapping={"pressure": False, "reason": reason, "evidence": evidence},
            evidence=evidence,
        )
    materialized = materialize_scheduler_mapping(immutable_mapping(tuple(items)))
    if type(materialized) is dict:
        return PlainSchedulerMappingDecision(status="accepted", reason="", mapping=materialized)
    evidence = unsupported_scheduler_value_evidence(value, field_name=field_name)
    return PlainSchedulerMappingDecision(
        status="unsupported_materialized",
        reason=reason,
        mapping={"pressure": False, "reason": reason, "evidence": evidence},
        evidence=evidence,
    )


def plain_scheduler_mapping(value: object, *, field_name: str) -> dict[str, object]:
    """Materialize exact scheduler-owned mappings without caller hooks."""
    return plain_scheduler_mapping_decision(value, field_name=field_name).mapping


def exact_reason_text(value: object, *, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_scheduler_reason",
        unsupported_reason="unsafe_scheduler_reason_rejected",
    )
    if reason:
        return default
    return text


def env_float(env: Mapping[str, object], name: str, default: float) -> float:
    items = no_hook_mapping_items(env)
    if items is None:
        return default
    value = dict.get(dict(items), name, default)
    metric, reason = no_hook_finite_float(value, default=default)
    return default if reason else metric


def env_int(env: Mapping[str, object], name: str, default: int) -> int:
    items = no_hook_mapping_items(env)
    if items is None:
        return default
    value = dict.get(dict(items), name, default)
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason="raw_queue_monitor_integer_rejected",
        non_finite_reason="raw_queue_monitor_integer_non_finite",
        allow_exact_text=True,
    )
    return default if reason else parsed


def queue_dir_path_decision(queue_dir: object, report: Callable[..., object]) -> QueueDirPathDecision:
    if queue_dir is None:
        return QueueDirPathDecision(status="missing", reason="missing_queue_dir", path=None)
    frozen = freeze_live_scheduler_path(queue_dir)
    if type(frozen) is str and frozen:
        return QueueDirPathDecision(status="accepted", reason="", path=Path(frozen), evidence=frozen)
    report("io_pressure_queue_dir_rejected", None, fatal=False, extra={"queue_dir_evidence": frozen})
    return QueueDirPathDecision(status="unsupported", reason="io_pressure_queue_dir_rejected", path=None, evidence=frozen)


def queue_dir_path(queue_dir: object, report: Callable[..., object]) -> Path | None:
    return queue_dir_path_decision(queue_dir, report).path


def disk_busy_time_decision(value: object) -> DiskBusyTimeDecision:
    items = no_hook_mapping_items(value)
    if items is not None:
        mapping = dict(items)
        metric, reason = no_hook_finite_float(dict.get(mapping, "busy_time"), default=0.0)
        if reason:
            return DiskBusyTimeDecision(status="rejected", reason=reason, busy_time=None)
        return DiskBusyTimeDecision(status="accepted", reason="", busy_time=metric)
    return DiskBusyTimeDecision(status="unsupported", reason="unsupported_disk_io_counters", busy_time=None)


def disk_busy_time(value: object) -> float | None:
    return disk_busy_time_decision(value).busy_time


__all__ = (
    "DiskBusyTimeDecision",
    "PlainSchedulerMappingDecision",
    "QueueDirPathDecision",
    "disk_busy_time",
    "disk_busy_time_decision",
    "env_float",
    "env_int",
    "exact_reason_text",
    "plain_scheduler_mapping",
    "plain_scheduler_mapping_decision",
    "queue_dir_path",
    "queue_dir_path_decision",
)
