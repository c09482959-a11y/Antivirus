"""Replayable decisions for process-queue monitor clamp evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float
from Virus_Scan.scheduler.timeout.process_queue_monitor_evidence import monitor_timeout_config_evidence


@dataclass(frozen=True, slots=True)
class MonitorClampEvidenceDecision:
    """Typed replayable decision for monitor clamp evidence projection."""

    accepted: bool
    reason: str
    setting: str
    comparison: str
    parsed: float
    boundary: float
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "accepted", self.accepted if type(self.accepted) is bool else False)
        object.__setattr__(self, "reason", self.reason if type(self.reason) is str and self.reason else "monitor_clamp_evidence_decision")
        object.__setattr__(self, "setting", self.setting if type(self.setting) is str and self.setting else "monitor_setting")
        object.__setattr__(self, "comparison", self.comparison if type(self.comparison) is str and self.comparison else "unknown")
        object.__setattr__(self, "parsed", self.parsed if type(self.parsed) is float else float.__float__(self.parsed) if type(self.parsed) is int else 0.0)
        object.__setattr__(self, "boundary", self.boundary if type(self.boundary) is float else float.__float__(self.boundary) if type(self.boundary) is int else 0.0)
        object.__setattr__(self, "evidence", tuple(self.evidence))

    def as_evidence(self) -> tuple[Mapping[str, object], ...]:
        """Return the immutable evidence tuple projection."""
        return self.evidence



def monitor_maximum_evidence_decision(
    *,
    setting: object,
    raw_value: object,
    parsed_value: object,
    maximum_value: object,
    replacement_value: object,
) -> MonitorClampEvidenceDecision:
    """Return replayable decision for process monitor maximum evidence."""
    safe_setting = setting if type(setting) is str and setting else "monitor_setting"
    replacement_metric, _replacement_reason = scheduler_float(replacement_value, default=0.0)
    parsed, parsed_reason = scheduler_float(parsed_value, default=replacement_metric)
    upper, upper_reason = scheduler_float(maximum_value, default=replacement_metric)
    if parsed_reason or upper_reason:
        return MonitorClampEvidenceDecision(
            accepted=False,
            reason="monitor_maximum_unavailable",
            setting=safe_setting,
            comparison="maximum",
            parsed=parsed,
            boundary=upper,
        )
    if parsed > upper:
        return MonitorClampEvidenceDecision(
            accepted=True,
            reason="monitor_maximum_exceeded",
            setting=safe_setting,
            comparison="maximum",
            parsed=parsed,
            boundary=upper,
            evidence=(
                monitor_timeout_config_evidence(
                    setting=safe_setting,
                    raw_value=raw_value,
                    replacement_value=replacement_value,
                    error=ValueError(safe_setting + " above maximum " + float.__str__(upper)),
                ),
            ),
        )
    return MonitorClampEvidenceDecision(
        accepted=True,
        reason="monitor_maximum_within_bounds",
        setting=safe_setting,
        comparison="maximum",
        parsed=parsed,
        boundary=upper,
    )


def monitor_minimum_evidence_decision(
    *,
    setting: object,
    raw_value: object,
    parsed_value: object,
    minimum_value: object,
    replacement_value: object,
) -> MonitorClampEvidenceDecision:
    """Return replayable decision for process monitor minimum evidence."""
    safe_setting = setting if type(setting) is str and setting else "monitor_setting"
    replacement_metric, _replacement_reason = scheduler_float(replacement_value, default=0.0)
    parsed, parsed_reason = scheduler_float(parsed_value, default=replacement_metric)
    lower, lower_reason = scheduler_float(minimum_value, default=0.0)
    if parsed_reason or lower_reason:
        return MonitorClampEvidenceDecision(
            accepted=False,
            reason="monitor_minimum_unavailable",
            setting=safe_setting,
            comparison="minimum",
            parsed=parsed,
            boundary=lower,
        )
    if parsed < lower:
        return MonitorClampEvidenceDecision(
            accepted=True,
            reason="monitor_minimum_below_bounds",
            setting=safe_setting,
            comparison="minimum",
            parsed=parsed,
            boundary=lower,
            evidence=(
                monitor_timeout_config_evidence(
                    setting=safe_setting,
                    raw_value=raw_value,
                    replacement_value=replacement_value,
                    error=ValueError(safe_setting + " below minimum " + float.__str__(lower)),
                ),
            ),
        )
    return MonitorClampEvidenceDecision(
        accepted=True,
        reason="monitor_minimum_within_bounds",
        setting=safe_setting,
        comparison="minimum",
        parsed=parsed,
        boundary=lower,
    )


__all__ = (
    "MonitorClampEvidenceDecision",
    "monitor_maximum_evidence_decision",
    "monitor_minimum_evidence_decision",
)
