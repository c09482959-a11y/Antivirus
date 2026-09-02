"""Queue-owned timeout evidence helpers for orphan-reclaim policy coercion."""
from __future__ import annotations

from dataclasses import dataclass
import math
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping, unsupported_scheduler_value_evidence


@dataclass(frozen=True, slots=True)
class ReclaimTimeoutPolicyEvidence:
    field: str
    raw_value_preview: str
    default_value: object
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def as_record(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stage": "process_queue_reclaim_timeout_policy",
                "reason": (
                    self.field + "_malformed"
                    if type(self.field) is str and self.field
                    else "reclaim_policy_field_malformed"
                ),
                "field": self.field,
                "raw_value_preview": self.raw_value_preview[:240],
                "default_value": self.default_value,
                "error_category": self.error_category,
                "error_source": self.error_source,
                "detail": self.detail[:1000],
                "timeout_failure": True,
                "queue_recovery_failure": True,
                "final_json_must_record": self.final_json_must_record,
                "checkpoint_must_record": self.checkpoint_must_record,
                "replay_must_reproduce": self.replay_must_reproduce,
            }
        )



def _reclaim_timeout_policy_evidence(*, field: str, raw_value: object, default_value: object, reason: str) -> Mapping[str, object]:
    field_text, field_reason = no_hook_text(field, missing_reason="missing_reclaim_policy_field", unsupported_reason="unsafe_reclaim_policy_field")
    owned_field = field_text if field_reason == "" and field_text else "reclaim_policy_field"
    value_text, value_reason = no_hook_text(raw_value, missing_reason="missing_reclaim_policy_value", unsupported_reason="unsafe_reclaim_policy_value")
    return ReclaimTimeoutPolicyEvidence(
        field=owned_field,
        raw_value_preview=value_text[:240] if value_reason == "" and value_text else "<" + no_hook_type_name(raw_value) + ">",
        default_value=default_value,
        error_category=reason,
        error_source="orphan_recovery_timeout." + owned_field,
        detail=reason,
    ).as_record()


def resolve_reclaim_float_value(*, value: object, field: str, default_value: float, evidence: list[Mapping[str, object]]) -> float:
    default_number, _default_reason = no_hook_finite_float(default_value, default=0.0, minimum=0.0, allow_exact_text=True)
    if value is None:
        return default_number
    number, reason = no_hook_finite_float(
        value,
        default=default_number,
        minimum=None,
        allow_exact_text=True,
        reason="unsafe_reclaim_float_rejected",
        non_finite_reason="non_finite_reclaim_float",
    )
    if reason == "" and number >= 0.0:
        return number
    if reason == "":
        reason = "negative_reclaim_float"
    evidence.append(_reclaim_timeout_policy_evidence(field=field, raw_value=value, default_value=default_number, reason=reason))
    return default_number


def resolve_reclaim_int_value(*, value: object, field: str, default_value: int, evidence: list[Mapping[str, object]]) -> int:
    default_number, _default_reason = no_hook_finite_float(default_value, default=0.0, minimum=0.0, allow_exact_text=True)
    if value is None:
        return int(default_number)
    number, reason = no_hook_finite_float(
        value,
        default=default_number,
        minimum=None,
        allow_exact_text=True,
        reason="unsafe_reclaim_int_rejected",
        non_finite_reason="non_finite_reclaim_int",
    )
    if reason == "" and number >= 0.0 and math.floor(number) == number:
        return int(number)
    if reason == "":
        reason = "negative_reclaim_int" if number < 0.0 else "non_integral_reclaim_int"
    evidence.append(_reclaim_timeout_policy_evidence(field=field, raw_value=value, default_value=int(default_number), reason=reason))
    return int(default_number)


def job_mapping(job: object, evidence: list[Mapping[str, object]]) -> Mapping[str, object]:
    items = no_hook_mapping_items(job)
    if items is not None:
        return immutable_mapping(tuple((key, value) for key, value in items))
    evidence.append(
        _reclaim_timeout_policy_evidence(
            field="job_record",
            raw_value=job,
            default_value=materialize_scheduler_mapping(
                unsupported_scheduler_value_evidence(job, field_name="job_record")
            ),
            reason="non_materializable_reclaim_job_record",
        )
    )
    return immutable_mapping(
        {
            "job_record_unavailable": True,
            "unsupported_job_record": unsupported_scheduler_value_evidence(job, field_name="job_record"),
        }
    )


__all__ = (
    "ReclaimTimeoutPolicyEvidence",
    "job_mapping",
    "resolve_reclaim_float_value",
    "resolve_reclaim_int_value",
)
