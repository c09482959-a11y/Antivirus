"""Typed replayable decisions for raw-stage job executor projections."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_plain_instance_dict
from Virus_Scan.scheduler.execution.scan_job_executor_support import raw_job_text
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value


@dataclass(frozen=True, slots=True)
class RawRecoveryTextDecision:
    text: str
    reason: str
    field_name: str
    accepted: bool


@dataclass(frozen=True, slots=True)
class RawStageJobPredicateDecision:
    eligible: bool
    reason: str


@dataclass(frozen=True, slots=True)
class RawStageJobProcessDecision:
    processed: bool
    reason: str


def raw_recovery_text_decision(decision: object, *, field_name: str) -> RawRecoveryTextDecision:
    instance_data = no_hook_plain_instance_dict(decision)
    if instance_data is None:
        return RawRecoveryTextDecision("", "raw_recovery_" + field_name + "_decision_unavailable", field_name, accepted=False)
    text, reason = raw_job_text(dict.get(instance_data, field_name), default_text="", field_name="recovery_" + field_name)
    if reason:
        return RawRecoveryTextDecision("", reason, field_name, accepted=False)
    if not text:
        return RawRecoveryTextDecision("", "raw_recovery_" + field_name + "_blank", field_name, accepted=False)
    return RawRecoveryTextDecision(text, "", field_name, accepted=True)


def raw_stage_job_predicate_decision(job: Mapping[str, object], *, only_file_id: str | None = None) -> RawStageJobPredicateDecision:
    items = no_hook_mapping_items(job)
    if items is None:
        return RawStageJobPredicateDecision(eligible=False, reason="raw_stage_job_mapping_unavailable")
    if scheduler_mapping_item_value(items, "job_type") != "raw_stage":
        return RawStageJobPredicateDecision(eligible=False, reason="raw_stage_job_type_not_raw_stage")
    if only_file_id and scheduler_mapping_item_value(items, "file_id") != only_file_id:
        return RawStageJobPredicateDecision(eligible=False, reason="raw_stage_job_file_id_mismatch")
    return RawStageJobPredicateDecision(eligible=True, reason="")


def raw_stage_job_unclaimed_decision() -> RawStageJobProcessDecision:
    return RawStageJobProcessDecision(processed=False, reason="raw_stage_job_not_claimed")


__all__ = (
    "RawRecoveryTextDecision",
    "RawStageJobPredicateDecision",
    "RawStageJobProcessDecision",
    "raw_recovery_text_decision",
    "raw_stage_job_predicate_decision",
    "raw_stage_job_unclaimed_decision",
)
