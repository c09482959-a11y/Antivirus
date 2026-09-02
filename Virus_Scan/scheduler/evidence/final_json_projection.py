"""Canonical scheduler evidence projection for final JSON records."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.evidence.final_json_checkpoint_projection import failure_record_from_checkpoint_status
from Virus_Scan.scheduler.evidence.final_json_compact_error_projection import build_final_json_compact_error_section
from Virus_Scan.scheduler.evidence.final_json_contract_projection import failure_records_from_scheduler_contract_status
from Virus_Scan.scheduler.evidence.final_json_evidence_mapping import collect_scheduler_evidence_values_from_mapping, dedupe_evidence
from Virus_Scan.scheduler.evidence.final_json_exact_fields import exact_mapping_or_none, exact_mapping_value, is_exact_mapping
from Virus_Scan.scheduler.evidence.final_json_failure_projection import failure_record_from_scheduler_result
from Virus_Scan.scheduler.evidence.final_json_passive_status_projection import failure_records_from_passive_scheduler_statuses
from Virus_Scan.scheduler.evidence.final_json_queue_projection import failure_records_from_queue_status
from Virus_Scan.scheduler.evidence.final_json_replay_projection import failure_record_from_replay_status
from Virus_Scan.scheduler.evidence.final_json_scheduler_result_projection import failure_records_from_scheduler_result_status
from Virus_Scan.scheduler.evidence.final_json_scheduler_status_projection import failure_record_from_existing_scheduler_section
from Virus_Scan.scheduler.evidence.final_json_status_sources import checkpoint_status_from_record, replay_status_from_record
from Virus_Scan.scheduler.evidence.final_json_trace_projection import failure_records_from_trace_status
from Virus_Scan.scheduler.evidence.records import build_scheduler_json_evidence_section, collect_scheduler_evidence
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping

_EXPLICIT_NESTED_EVIDENCE_KEYS = ("timeout_evidence", "scan_integrity")


@dataclass(frozen=True)
class FinalJsonSchedulerSectionDecision:
    section: dict[str, object] | None
    reason: str
    record_is_mapping: bool
    evidence_count: int


def build_final_json_scheduler_section_decision(record: Mapping[str, object]) -> FinalJsonSchedulerSectionDecision:
    """Return replayable final-JSON scheduler projection state for one scan result."""
    if not is_exact_mapping(record):
        return FinalJsonSchedulerSectionDecision(
            section=None,
            reason="record_not_exact_mapping",
            record_is_mapping=False,
            evidence_count=0,
        )
    existing = exact_mapping_or_none(exact_mapping_value(record, "scheduler"))
    if existing is not None and (
        exact_mapping_value(existing, "scheduler_status") is not None
        or exact_mapping_value(existing, "evidence") is not None
    ):
        checkpoint_status = checkpoint_status_from_record(record, existing)
        replay_status = replay_status_from_record(record, existing)
        collected = list(collect_scheduler_evidence(existing))
        collected.extend(collect_scheduler_evidence_values_from_mapping(existing, record, default_stage_prefix="scheduler"))
        existing_status_synthetic = failure_record_from_existing_scheduler_section(record, existing)
        if existing_status_synthetic is not None and not collected:
            collected.append(existing_status_synthetic)
        checkpoint_synthetic = failure_record_from_checkpoint_status(record, checkpoint_status)
        if checkpoint_synthetic is not None:
            collected.append(checkpoint_synthetic)
        replay_synthetic = failure_record_from_replay_status(record, replay_status)
        if replay_synthetic is not None:
            collected.append(replay_synthetic)
        collected.extend(failure_records_from_queue_status(record, existing))
        collected.extend(failure_records_from_scheduler_result_status(record, existing))
        collected.extend(failure_records_from_scheduler_contract_status(record, existing))
        collected.extend(failure_records_from_trace_status(record, existing))
        collected.extend(failure_records_from_passive_scheduler_statuses(record, existing))
        evidence = dedupe_evidence(collected)
        if not evidence:
            materialized = materialize_scheduler_mapping(existing)
            return FinalJsonSchedulerSectionDecision(
                section=materialized,
                reason="existing_scheduler_section_without_evidence",
                record_is_mapping=True,
                evidence_count=0,
            )
        return FinalJsonSchedulerSectionDecision(
            section=build_scheduler_json_evidence_section(
                evidence,
                checkpoint_status=checkpoint_status,
                replay_status=replay_status,
            ),
            reason="existing_scheduler_evidence_projected",
            record_is_mapping=True,
            evidence_count=len(evidence),
        )
    sources: list[object] = []
    sources.extend(collect_scheduler_evidence_values_from_mapping(record, record))
    for key in _EXPLICIT_NESTED_EVIDENCE_KEYS:
        nested = exact_mapping_or_none(exact_mapping_value(record, key))
        if nested is not None:
            sources.extend(collect_scheduler_evidence_values_from_mapping(nested, record, default_stage_prefix=key))
    collected = list(collect_scheduler_evidence(sources))
    synthetic = failure_record_from_scheduler_result(record)
    if synthetic is not None:
        collected.append(synthetic)
    checkpoint_synthetic = failure_record_from_checkpoint_status(record, checkpoint_status_from_record(record, None))
    if checkpoint_synthetic is not None:
        collected.append(checkpoint_synthetic)
    replay_synthetic = failure_record_from_replay_status(record, replay_status_from_record(record, None))
    if replay_synthetic is not None:
        collected.append(replay_synthetic)
    collected.extend(failure_records_from_queue_status(record))
    collected.extend(failure_records_from_scheduler_result_status(record))
    collected.extend(failure_records_from_scheduler_contract_status(record))
    collected.extend(failure_records_from_trace_status(record))
    collected.extend(failure_records_from_passive_scheduler_statuses(record))
    evidence = dedupe_evidence(collected)
    if not evidence:
        return FinalJsonSchedulerSectionDecision(
            section=None,
            reason="scheduler_evidence_not_found",
            record_is_mapping=True,
            evidence_count=0,
        )
    return FinalJsonSchedulerSectionDecision(
        section=build_scheduler_json_evidence_section(
            evidence,
            checkpoint_status=checkpoint_status_from_record(record, None),
            replay_status=replay_status_from_record(record, None),
        ),
        reason="record_scheduler_evidence_projected",
        record_is_mapping=True,
        evidence_count=len(evidence),
    )


def build_final_json_scheduler_section(record: Mapping[str, object]) -> dict[str, object] | None:
    """Return canonical scheduler final-JSON evidence for one scan result."""
    return build_final_json_scheduler_section_decision(record).section

__all__ = (
    "FinalJsonSchedulerSectionDecision",
    "build_final_json_compact_error_section",
    "build_final_json_scheduler_section",
    "build_final_json_scheduler_section_decision",
)
