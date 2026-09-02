"""Timeout-owned value parsing and clamping for process-queue monitor policy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, NamedTuple

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.timeout.process_queue_monitor_evidence import monitor_timeout_config_evidence
from Virus_Scan.scheduler.timeout.process_queue_monitor_decisions import monitor_maximum_evidence_decision, monitor_minimum_evidence_decision


@dataclass(frozen=True, slots=True)
class MonitorSettingValue:
    value: float
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        value, _reason = scheduler_float(value=self.value, default=0.0)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "evidence", immutable_tuple(self.evidence if self.evidence is not None else ()))


class MonitorClampEvidenceRequest(NamedTuple):
    evidence: tuple[Mapping[str, object], ...]
    setting: str
    raw_value: object
    parsed_value: float
    boundary_value: float
    replacement_value: object


def monitor_float_config(
    *,
    setting: str,
    raw_value: object,
    replacement: float,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> MonitorSettingValue:
    del recoverable_exceptions  # Explicitly unused contract parameters.
    replacement_value, _replacement_reason = scheduler_float(replacement, default=0.0)
    reason_prefix = setting if type(setting) is str and setting else "monitor_setting"
    value, reason = scheduler_float(raw_value, default=replacement_value, reason=reason_prefix + "_float_rejected", non_finite_reason=reason_prefix + "_non_finite")
    if reason:
        return MonitorSettingValue(
            value=replacement_value,
            evidence=(monitor_timeout_config_evidence(setting=setting, raw_value=raw_value, replacement_value=replacement_value, error=ValueError(reason)),),
        )
    return MonitorSettingValue(value=value, evidence=())


def record_monitor_maximum_if_needed(request: MonitorClampEvidenceRequest) -> tuple[Mapping[str, object], ...]:
    if request.evidence:
        return request.evidence
    return monitor_maximum_evidence_decision(
        setting=request.setting,
        raw_value=request.raw_value,
        parsed_value=request.parsed_value,
        maximum_value=request.boundary_value,
        replacement_value=request.replacement_value,
    ).as_evidence()


def record_monitor_minimum_if_needed(request: MonitorClampEvidenceRequest) -> tuple[Mapping[str, object], ...]:
    if request.evidence:
        return request.evidence
    return monitor_minimum_evidence_decision(
        setting=request.setting,
        raw_value=request.raw_value,
        parsed_value=request.parsed_value,
        minimum_value=request.boundary_value,
        replacement_value=request.replacement_value,
    ).as_evidence()


__all__ = (
    "MonitorSettingValue",
    "MonitorClampEvidenceRequest",
    "monitor_float_config",
    "record_monitor_maximum_if_needed",
    "record_monitor_minimum_if_needed",
)
