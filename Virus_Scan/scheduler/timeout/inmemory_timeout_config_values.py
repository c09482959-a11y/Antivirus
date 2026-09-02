"""Typed timeout configuration value coercion and evidence helpers."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping, NamedTuple

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_error_detail, scheduler_evidence_text, scheduler_float, scheduler_int, scheduler_value_snapshot



def _timeout_reason(setting: object, suffix: str) -> str:
    safe_setting = scheduler_evidence_text(
        setting,
        missing_text="timeout_config_setting",
        field_name="timeout_config_setting",
    )
    safe_suffix = suffix if type(suffix) is str and suffix else "rejected"
    return safe_setting + "_" + safe_suffix


def timeout_config_evidence(*, setting: object, raw_value: object, default_value: object, error: BaseException) -> Mapping[str, object]:
    safe_setting = scheduler_evidence_text(
        setting,
        missing_text="timeout_config_setting",
        field_name="timeout_config_setting",
    )
    return MappingProxyType(
        {
            "stage": "inmemory_timeout_config",
            "setting": safe_setting,
            "raw_value": scheduler_value_snapshot(raw_value, field_name=safe_setting),
            "default_value": scheduler_value_snapshot(default_value, field_name=safe_setting + "_default"),
            "error_category": no_hook_type_name(error),
            "error_source": "inmemory_timeout_config.build",
            "detail": scheduler_error_detail(error),
            "timeout_failure": True,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_reproduce": True,
        }
    )


def coerce_int_config(*, setting: object, raw_value: object, default: int) -> tuple[int, tuple[Mapping[str, object], ...]]:
    default_value, _default_reason = scheduler_int(default, default=0)
    value, reason = scheduler_int(raw_value, default=default_value, reason=_timeout_reason(setting, "integer_rejected"))
    if reason:
        return default_value, (timeout_config_evidence(setting=setting, raw_value=raw_value, default_value=default_value, error=ValueError(reason)),)
    return value, ()


def coerce_float_config(*, setting: object, raw_value: object, default: float) -> tuple[float, tuple[Mapping[str, object], ...]]:
    default_value, _default_reason = scheduler_float(default, default=0.0)
    value, reason = scheduler_float(
        raw_value,
        default=default_value,
        reason=_timeout_reason(setting, "float_rejected"),
        non_finite_reason=_timeout_reason(setting, "non_finite"),
    )
    if reason:
        return default_value, (timeout_config_evidence(setting=setting, raw_value=raw_value, default_value=default_value, error=ValueError(reason)),)
    return value, ()


def minimum_config_evidence(*, setting: object, raw_value: object, minimum_value: object, default_value: object) -> Mapping[str, object]:
    safe_setting = scheduler_evidence_text(
        setting,
        missing_text="timeout_config_setting",
        field_name="timeout_config_setting",
    )
    safe_minimum, _minimum_reason = scheduler_float(minimum_value, default=0.0)
    return timeout_config_evidence(
        setting=safe_setting,
        raw_value=raw_value,
        default_value=default_value,
        error=ValueError(safe_setting + " below minimum " + float.__str__(safe_minimum)),
    )



class MinimumConfigEvidenceDecision(NamedTuple):
    """Replayable decision for minimum timeout config evidence."""

    accepted: bool
    reason: str
    evidence: tuple[Mapping[str, object], ...]

    def as_evidence(self) -> tuple[Mapping[str, object], ...]:
        """Return the immutable evidence tuple projection."""
        return self.evidence


class MinimumConfigEvidenceRequest(NamedTuple):
    """Typed request for minimum timeout config evidence decisions."""

    evidence: tuple[Mapping[str, object], ...]
    setting: object
    raw_value: object
    parsed_value: float
    minimum_value: float
    default_value: object


def minimum_config_evidence_decision(request: MinimumConfigEvidenceRequest) -> MinimumConfigEvidenceDecision:
    if request.evidence:
        return MinimumConfigEvidenceDecision(
            accepted=True,
            reason="existing_timeout_config_evidence",
            evidence=request.evidence,
        )
    default_metric, _default_reason = scheduler_float(request.default_value, default=0.0)
    parsed, parsed_reason = scheduler_float(request.parsed_value, default=default_metric)
    lower, lower_reason = scheduler_float(request.minimum_value, default=0.0)
    if parsed_reason or lower_reason:
        return MinimumConfigEvidenceDecision(
            accepted=False,
            reason="timeout_config_minimum_unavailable",
            evidence=(),
        )
    if parsed < lower:
        return MinimumConfigEvidenceDecision(
            accepted=True,
            reason="timeout_config_minimum_below_bounds",
            evidence=(
                minimum_config_evidence(
                    setting=request.setting,
                    raw_value=request.raw_value,
                    minimum_value=request.minimum_value,
                    default_value=request.default_value,
                ),
            ),
        )
    return MinimumConfigEvidenceDecision(
        accepted=True,
        reason="timeout_config_minimum_within_bounds",
        evidence=(),
    )


def record_minimum_if_needed(request: MinimumConfigEvidenceRequest) -> tuple[Mapping[str, object], ...]:
    return minimum_config_evidence_decision(request).as_evidence()


__all__ = (
    "MinimumConfigEvidenceDecision",
    "MinimumConfigEvidenceRequest",
    "coerce_float_config",
    "coerce_int_config",
    "minimum_config_evidence",
    "minimum_config_evidence_decision",
    "record_minimum_if_needed",
    "timeout_config_evidence",
)
