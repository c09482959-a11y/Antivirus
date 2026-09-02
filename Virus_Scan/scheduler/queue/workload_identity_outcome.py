"""Typed scheduler workload identity decision outcomes."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value
from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import FrozenSchedulerMapping, materialize_scheduler_mapping
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items_status

_MISSING_WORKLOAD_VALUE = object()

@dataclass(frozen=True, slots=True)
class WorkloadIdentityTextOutcome:
    value: str
    reason: str


@dataclass(frozen=True, slots=True)
class WorkloadIdentityItemsOutcome:
    items: tuple[tuple[object, object], ...]
    reason: str


@dataclass(frozen=True, slots=True)
class WorkloadIdentityValueOutcome:
    value: object
    found: bool
    reason: str


@dataclass(frozen=True, slots=True)
class WorkloadIdentityConfidenceOutcome:
    value: float
    reason: str


@dataclass(frozen=True, slots=True)
class WorkloadIdentityTagsOutcome:
    value: frozenset[str]
    reason: str


@dataclass(frozen=True, slots=True)
class WorkloadIdentityDecision:
    workload: str
    reason: str
    magic_stage: str
    magic_type: str
    confidence: float
    tags: frozenset[str]

    @property
    def accepted(self) -> bool:
        return self.workload != ""


def _exact_lower_text_outcome(value: object) -> WorkloadIdentityTextOutcome:
    if type(value) is str:
        return WorkloadIdentityTextOutcome(str.__str__(value).lower(), "")
    return WorkloadIdentityTextOutcome("", "workload_identity_text_not_exact_str")



def _identity_value_outcome(items: tuple[tuple[object, object], ...], key: str) -> WorkloadIdentityValueOutcome:
    value = scheduler_mapping_item_value(items, key, _MISSING_WORKLOAD_VALUE)
    if value is _MISSING_WORKLOAD_VALUE:
        return WorkloadIdentityValueOutcome(None, False, "missing_workload_identity_" + key)
    return WorkloadIdentityValueOutcome(value, True, "")




def workload_from_identity_outcome(identity: Mapping[str, object] | object) -> WorkloadIdentityDecision:
    """Map scheduler-owned identity evidence onto workload lanes with replayable rejection reasons."""
    identity_items, identity_reason = no_hook_mapping_items_status(identity)
    if identity_items is not None:
        items_outcome = WorkloadIdentityItemsOutcome(tuple((key, value) for key, value in identity_items), "")
    elif type(identity) is FrozenSchedulerMapping:
        materialized = materialize_scheduler_mapping(identity)
        materialized_items, materialized_reason = no_hook_mapping_items_status(materialized)
        if materialized_items is not None:
            items_outcome = WorkloadIdentityItemsOutcome(tuple((key, value) for key, value in materialized_items), "")
        else:
            items_outcome = WorkloadIdentityItemsOutcome((), "workload_identity_frozen_mapping_" + materialized_reason)
    else:
        items_outcome = WorkloadIdentityItemsOutcome((), "workload_identity_mapping_" + identity_reason)
    if items_outcome.reason:
        return WorkloadIdentityDecision("", items_outcome.reason, "", "", 0.0, frozenset())
    magic_stage_outcome = _exact_lower_text_outcome(_identity_value_outcome(items_outcome.items, "magic_stage").value)
    magic_type_outcome = _exact_lower_text_outcome(_identity_value_outcome(items_outcome.items, "magic_type").value)
    confidence_value = _identity_value_outcome(items_outcome.items, "confidence").value
    confidence_metric, confidence_reason = no_hook_finite_float(confidence_value, default=0.0, minimum=0.0, maximum=1.0, allow_exact_text=True)
    confidence_outcome = WorkloadIdentityConfidenceOutcome(0.0, confidence_reason) if confidence_reason else WorkloadIdentityConfidenceOutcome(confidence_metric, "")
    tags_value = _identity_value_outcome(items_outcome.items, "tags").value
    if tags_value is None:
        tags_outcome = WorkloadIdentityTagsOutcome(frozenset(), "missing_workload_identity_tags")
    elif type(tags_value) is str:
        tag_text = str.__str__(tags_value).lower()
        if tag_text:
            tags_outcome = WorkloadIdentityTagsOutcome(frozenset((tag_text,)), "")
        else:
            tags_outcome = WorkloadIdentityTagsOutcome(frozenset(), "blank_workload_identity_tag")
    elif type(tags_value) is not tuple and type(tags_value) is not list and type(tags_value) is not set and type(tags_value) is not frozenset:
        tags_outcome = WorkloadIdentityTagsOutcome(frozenset(), "unsupported_workload_identity_tags")
    else:
        tags: set[str] = set()
        rejected_tag = False
        for tag_item in tags_value:
            if type(tag_item) is not str:
                rejected_tag = True
                continue
            item_text = str.__str__(tag_item).lower()
            if item_text:
                tags.add(item_text)
            else:
                rejected_tag = True
        tag_reason = "workload_identity_tag_item_rejected" if rejected_tag else ""
        tags_outcome = WorkloadIdentityTagsOutcome(frozenset(tags), tag_reason)
    magic_stage = magic_stage_outcome.value
    magic_type = magic_type_outcome.value
    confidence = confidence_outcome.value
    tags = tags_outcome.value
    if confidence < 0.75:
        reason = confidence_outcome.reason or "workload_identity_confidence_below_threshold"
        return WorkloadIdentityDecision("", reason, magic_stage, magic_type, confidence, tags)
    if magic_stage == "archive" or "archive_file" in tags:
        return WorkloadIdentityDecision("archive", "", magic_stage, magic_type, confidence, tags)
    if magic_stage == "binary" or magic_type in {"pe_mz", "elf", "macho"} or "pe_file" in tags:
        workload = "dotnet" if magic_type == "pe_mz" else "raw"
        return WorkloadIdentityDecision(workload, "", magic_stage, magic_type, confidence, tags)
    if magic_stage == "image" or "filetype_image" in tags or "image_file" in tags:
        return WorkloadIdentityDecision("image", "", magic_stage, magic_type, confidence, tags)
    if magic_stage == "asset" or ({"media_file", "font_file", "unity_container_asset", "unity_asset"} & tags):
        # No separate asset lane exists; passive assets belong with the cheap
        # image/media lane, not generic/raw/dotnet admission.
        return WorkloadIdentityDecision("image", "", magic_stage, magic_type, confidence, tags)
    if magic_stage == "runtime":
        return WorkloadIdentityDecision("script", "", magic_stage, magic_type, confidence, tags)
    return WorkloadIdentityDecision("", "unsupported_workload_identity_stage", magic_stage, magic_type, confidence, tags)


__all__ = (
    "WorkloadIdentityConfidenceOutcome",
    "WorkloadIdentityDecision",
    "WorkloadIdentityItemsOutcome",
    "WorkloadIdentityTagsOutcome",
    "WorkloadIdentityTextOutcome",
    "WorkloadIdentityValueOutcome",
    "workload_from_identity_outcome",
)
