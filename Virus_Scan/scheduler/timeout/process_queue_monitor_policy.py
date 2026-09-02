"""Timeout-owned process-queue monitor timing policy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.timeout.process_queue_monitor_values import (
    MonitorClampEvidenceRequest,
    monitor_float_config,
    record_monitor_maximum_if_needed,
    record_monitor_minimum_if_needed,
)




def _env_value(env: Mapping[str, str], key: str, default: str) -> object:
    if type(env) is dict and dict.__contains__(env, key):
        return dict.__getitem__(env, key)
    return scheduler_mapping_value(env, key, default=default)


@dataclass(frozen=True)
class ProcessQueueMonitorPolicy:
    monitor_sleep_sec: float
    per_file_timeout_sec: float
    progress_stall_sec: float
    idle_grace_sec: float
    monitor_heartbeat_sec: float
    timeout_config_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "timeout_config_evidence", immutable_tuple(self.timeout_config_evidence))


@dataclass(frozen=True, slots=True)
class _BoundedMonitorFloatRequest:
    setting: str
    raw_value: object
    parser_replacement_value: float
    minimum_value: float
    minimum_replacement_value: float
    recoverable_exceptions: tuple[type[BaseException], ...]
    maximum_value: float | None = None
    maximum_replacement_value: float | None = None
    value_when_non_positive: float | None = None


def _bounded_monitor_float(
    request: _BoundedMonitorFloatRequest,
) -> tuple[float, tuple[Mapping[str, object], ...]]:
    parsed = monitor_float_config(
        setting=request.setting,
        raw_value=request.raw_value,
        replacement=request.parser_replacement_value,
        recoverable_exceptions=request.recoverable_exceptions,
    )
    evidence = parsed.evidence
    evidence += record_monitor_minimum_if_needed(
        MonitorClampEvidenceRequest(
            evidence=evidence,
            setting=request.setting,
            raw_value=request.raw_value,
            parsed_value=parsed.value,
            boundary_value=request.minimum_value,
            replacement_value=request.minimum_replacement_value,
        )
    )
    if request.maximum_value is not None:
        evidence += record_monitor_maximum_if_needed(
            MonitorClampEvidenceRequest(
                evidence=evidence,
                setting=request.setting,
                raw_value=request.raw_value,
                parsed_value=parsed.value,
                boundary_value=request.maximum_value,
                replacement_value=(
                    request.maximum_value
                    if request.maximum_replacement_value is None
                    else request.maximum_replacement_value
                ),
            )
        )
    value = parsed.value
    if request.value_when_non_positive is not None and value <= 0:
        value = request.value_when_non_positive
    value = max(request.minimum_value, value)
    if request.maximum_value is not None:
        value = min(request.maximum_value, value)
    return value, evidence


def process_queue_monitor_policy(
    *,
    env: Mapping[str, str],
    configured_per_file_timeout_sec: float,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> ProcessQueueMonitorPolicy:
    monitor_sleep_sec, monitor_sleep_evidence = _bounded_monitor_float(
        _BoundedMonitorFloatRequest(
            setting="UMIGE_QUEUE_MONITOR_SLEEP_SEC",
            raw_value=_env_value(env, "UMIGE_QUEUE_MONITOR_SLEEP_SEC", "1.0"),
            parser_replacement_value=1.0,
            minimum_value=0.2,
            minimum_replacement_value=1.0,
            maximum_value=5.0,
            maximum_replacement_value=5.0,
            recoverable_exceptions=recoverable_exceptions,
        )
    )
    configured, configured_reason = scheduler_float(
        configured_per_file_timeout_sec,
        default=0.0,
        reason="configured_per_file_timeout_sec_rejected",
        non_finite_reason="configured_per_file_timeout_sec_non_finite",
    )
    per_file_raw_value = (
        configured
        if configured_reason == "" and configured > 0
        else _env_value(env, "UMIGE_PER_FILE_TIMEOUT_SEC", "0")
    )
    per_file_timeout_sec, per_file_timeout_evidence = _bounded_monitor_float(
        _BoundedMonitorFloatRequest(
            setting="UMIGE_PER_FILE_TIMEOUT_SEC",
            raw_value=per_file_raw_value,
            parser_replacement_value=0.0,
            minimum_value=30.0,
            minimum_replacement_value=300.0,
            value_when_non_positive=300.0,
            recoverable_exceptions=recoverable_exceptions,
        )
    )
    computed_progress_value = (
        per_file_timeout_sec * 2.0
        if per_file_timeout_sec > 0
        else 0.0
    )
    progress_replacement_value = max(300.0, computed_progress_value)
    progress_stall_sec, progress_evidence = _bounded_monitor_float(
        _BoundedMonitorFloatRequest(
            setting="UMIGE_QUEUE_PROGRESS_STALL_SEC",
            raw_value=_env_value(env, "UMIGE_QUEUE_PROGRESS_STALL_SEC", "0"),
            parser_replacement_value=0.0,
            minimum_value=60.0,
            minimum_replacement_value=progress_replacement_value,
            value_when_non_positive=progress_replacement_value,
            recoverable_exceptions=recoverable_exceptions,
        )
    )
    idle_grace_sec, idle_evidence = _bounded_monitor_float(
        _BoundedMonitorFloatRequest(
            setting="UMIGE_QUEUE_DRAIN_TERMINATE_SEC",
            raw_value=_env_value(env, "UMIGE_QUEUE_DRAIN_TERMINATE_SEC", "45"),
            parser_replacement_value=45.0,
            minimum_value=5.0,
            minimum_replacement_value=45.0,
            recoverable_exceptions=recoverable_exceptions,
        )
    )
    monitor_heartbeat_sec, heartbeat_evidence = _bounded_monitor_float(
        _BoundedMonitorFloatRequest(
            setting="UMIGE_QUEUE_MONITOR_HEARTBEAT_SEC",
            raw_value=_env_value(env, "UMIGE_QUEUE_MONITOR_HEARTBEAT_SEC", "30"),
            parser_replacement_value=30.0,
            minimum_value=1.0,
            minimum_replacement_value=30.0,
            recoverable_exceptions=recoverable_exceptions,
        )
    )
    evidence = (
        monitor_sleep_evidence
        + per_file_timeout_evidence
        + progress_evidence
        + idle_evidence
        + heartbeat_evidence
    )
    return ProcessQueueMonitorPolicy(
        monitor_sleep_sec=monitor_sleep_sec,
        per_file_timeout_sec=per_file_timeout_sec,
        progress_stall_sec=progress_stall_sec,
        idle_grace_sec=idle_grace_sec,
        monitor_heartbeat_sec=monitor_heartbeat_sec,
        timeout_config_evidence=tuple(evidence),
    )


__all__ = ("ProcessQueueMonitorPolicy", "process_queue_monitor_policy")
