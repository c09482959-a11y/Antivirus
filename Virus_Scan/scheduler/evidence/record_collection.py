"""No-hook collection of scheduler evidence sources."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision
from Virus_Scan.scheduler.internal.immutable_outputs import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value


from Virus_Scan.scheduler.evidence.record_collection_decisions import (
    SchedulerEvidenceMappingItemsDecision,
    SchedulerEvidenceNestedSourceDecision,
    SchedulerEvidenceRecordShapeDecision,
    SchedulerEvidenceSequenceDecision,
    SchedulerEvidenceSourceCollectionDecision,
)


def collect_scheduler_evidence_decision(*sources: object) -> SchedulerEvidenceSourceCollectionDecision:
    """Collect immutable scheduler evidence records with replayable source decisions."""
    records: list[SchedulerEvidenceRecord] = []
    reasons: list[str] = []
    for source in sources:
        decision = _collect_scheduler_evidence_source_decision(source)
        records.extend(decision.records)
        reasons.append(decision.reason)
    return SchedulerEvidenceSourceCollectionDecision(tuple(records), ";".join(reasons))


def collect_scheduler_evidence(*sources: object) -> tuple[SchedulerEvidenceRecord, ...]:
    """Collect immutable scheduler evidence records without caller-owned hooks."""
    return collect_scheduler_evidence_decision(*sources).records


def looks_like_evidence_record_decision(value: Mapping[str, object]) -> SchedulerEvidenceRecordShapeDecision:
    items_decision = scheduler_evidence_mapping_items_decision(value)
    if items_decision.items is None:
        return SchedulerEvidenceRecordShapeDecision(looks_like=False, reason=items_decision.reason, keys=())
    return looks_like_evidence_record_items_decision(items_decision.items)


def looks_like_evidence_record(value: Mapping[str, object]) -> bool:
    return looks_like_evidence_record_decision(value).looks_like


def _collect_scheduler_mapping_source_decision(
    items: tuple[tuple[object, object], ...],
) -> SchedulerEvidenceSourceCollectionDecision:
    record_shape = looks_like_evidence_record_items_decision(items)
    if record_shape.looks_like:
        record_mapping: dict[str, object] = dict(items)
        return SchedulerEvidenceSourceCollectionDecision(
            (SchedulerEvidenceRecord.from_mapping(record_mapping),),
            "record_mapping_source",
        )
    nested_decision = scheduler_evidence_nested_source_decision(items)
    if not nested_decision.found:
        return SchedulerEvidenceSourceCollectionDecision((), nested_decision.reason)
    nested = collect_scheduler_evidence_decision(nested_decision.source)
    return SchedulerEvidenceSourceCollectionDecision(nested.records, "nested_" + nested.reason)


def _scheduler_evidence_sequence_items_decision(source: object) -> SchedulerEvidenceSequenceDecision:
    if type(source) is list:
        return SchedulerEvidenceSequenceDecision(items=tuple(source), reason="list_sequence_source")
    if type(source) is tuple:
        return SchedulerEvidenceSequenceDecision(items=source, reason="tuple_sequence_source")
    if type(source) in {set, frozenset}:
        return SchedulerEvidenceSequenceDecision(items=tuple(source), reason="set_sequence_source")
    return SchedulerEvidenceSequenceDecision(items=None, reason="unsupported_sequence_source")


def _scheduler_evidence_sequence_items(source: object) -> tuple[object, ...] | None:
    return _scheduler_evidence_sequence_items_decision(source).items


def _collect_scheduler_sequence_source_decision(
    sequence_items: tuple[object, ...],
) -> SchedulerEvidenceSourceCollectionDecision:
    records: list[SchedulerEvidenceRecord] = []
    reasons: list[str] = []
    for item in sequence_items:
        decision = _collect_scheduler_evidence_source_decision(item)
        records.extend(decision.records)
        reasons.append(decision.reason)
    return SchedulerEvidenceSourceCollectionDecision(tuple(records), "sequence:" + ";".join(reasons))


def _collect_scheduler_evidence_source_decision(source: object) -> SchedulerEvidenceSourceCollectionDecision:
    if source is None:
        return SchedulerEvidenceSourceCollectionDecision((), "missing_source")
    if type(source) is SchedulerEvidenceRecord:
        return SchedulerEvidenceSourceCollectionDecision((source,), "record_source")
    items_decision = scheduler_evidence_mapping_items_decision(source)
    if items_decision.items is not None:
        return _collect_scheduler_mapping_source_decision(items_decision.items)
    sequence_items = _scheduler_evidence_sequence_items(source)
    if sequence_items is not None:
        return _collect_scheduler_sequence_source_decision(sequence_items)
    return SchedulerEvidenceSourceCollectionDecision(
        (unsupported_scheduler_evidence_source(source),),
        items_decision.reason,
    )


def scheduler_evidence_mapping_items_decision(source: object) -> SchedulerEvidenceMappingItemsDecision:
    frozen_decision = frozen_scheduler_items_decision(source)
    if frozen_decision.accepted:
        return SchedulerEvidenceMappingItemsDecision(frozen_decision.items, "frozen_scheduler_items")
    if type(source) in {dict, MappingProxyType}:
        return SchedulerEvidenceMappingItemsDecision(no_hook_mapping_items(source), "exact_mapping_items")
    return SchedulerEvidenceMappingItemsDecision(None, "unsupported_mapping_source")


def scheduler_evidence_mapping_items(source: object) -> tuple[tuple[object, object], ...] | None:
    return scheduler_evidence_mapping_items_decision(source).items


def scheduler_evidence_nested_source_decision(items: tuple[tuple[object, object], ...]) -> SchedulerEvidenceNestedSourceDecision:
    evidence = scheduler_mapping_item_value(items, "evidence")
    if evidence is not None:
        return SchedulerEvidenceNestedSourceDecision(found=True, source=evidence, reason="evidence_field")
    scheduler_evidence = scheduler_mapping_item_value(items, "scheduler_evidence")
    if scheduler_evidence is not None:
        return SchedulerEvidenceNestedSourceDecision(found=True, source=scheduler_evidence, reason="scheduler_evidence_field")
    return SchedulerEvidenceNestedSourceDecision(found=False, source=None, reason="missing_nested_evidence_source")


def scheduler_evidence_nested_source(items: tuple[tuple[object, object], ...]) -> object:
    decision = scheduler_evidence_nested_source_decision(items)
    return decision.source if decision.found else None


def unsupported_scheduler_evidence_source(source: object) -> SchedulerEvidenceRecord:
    return SchedulerEvidenceRecord(
        stage="scheduler_evidence_collection",
        state="failed",
        error_category="scheduler_evidence_source_rejected",
        error_source="scheduler.evidence.records",
        message="scheduler evidence source could not be collected without caller hooks",
        context={
            "unsupported_scheduler_evidence_source": unsupported_scheduler_value_evidence(
                source,
                field_name="scheduler_evidence_source",
            ),
            "value_type": no_hook_type_name(source),
        },
        fatal=True,
    )


def looks_like_evidence_record_items_decision(items: tuple[tuple[object, object], ...]) -> SchedulerEvidenceRecordShapeDecision:
    keys = tuple(key for key, _value in items if type(key) is str)
    if "stage" not in keys:
        return SchedulerEvidenceRecordShapeDecision(looks_like=False, reason="missing_stage_key", keys=keys)
    if not any(key in keys for key in ("state", "error_category", "message", "error_source")):
        return SchedulerEvidenceRecordShapeDecision(looks_like=False, reason="missing_evidence_state_key", keys=keys)
    return SchedulerEvidenceRecordShapeDecision(looks_like=True, reason="record_shape", keys=keys)


def looks_like_evidence_record_items(items: tuple[tuple[object, object], ...]) -> bool:
    return looks_like_evidence_record_items_decision(items).looks_like


__all__ = (
    "SchedulerEvidenceMappingItemsDecision",
    "SchedulerEvidenceNestedSourceDecision",
    "SchedulerEvidenceRecordShapeDecision",
    "SchedulerEvidenceSequenceDecision",
    "SchedulerEvidenceSourceCollectionDecision",
    "collect_scheduler_evidence",
    "collect_scheduler_evidence_decision",
    "looks_like_evidence_record",
    "looks_like_evidence_record_decision",
    "scheduler_evidence_mapping_items_decision",
    "scheduler_evidence_nested_source_decision",
)
