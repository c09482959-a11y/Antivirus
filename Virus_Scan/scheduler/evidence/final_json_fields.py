"""Scheduler-owned final JSON field assembly.

Reporting may own the surrounding compact scan result, but the scheduler section,
status mirror, and failure-evidence mirror are assembled here so Phase 11 keeps
scheduler evidence/checkpoint/JSON ownership in the scheduler boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scheduler.evidence.final_json_projection import (
    build_final_json_compact_error_section,
    build_final_json_scheduler_section,
)
from Virus_Scan.scheduler.evidence.final_json_exact_fields import is_exact_mapping
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence


_EMPTY_FINAL_JSON_FIELDS: Mapping[str, object] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class FinalJsonSchedulerFieldsDecision:
    """Replayable decision for scheduler-owned final JSON field projection."""

    fields: Mapping[str, object]
    reason: str
    accepted: bool
    record_is_mapping: bool



def _scheduler_fields_failure(reason: str, value: object) -> dict[str, object]:
    evidence = unsupported_scheduler_value_evidence(value, field_name="scheduler_section")
    evidence["scheduler_projection_failed"] = True
    evidence["reason"] = reason if type(reason) is str else "scheduler_section_unavailable"
    return {
        "scheduler": evidence,
        "scheduler_status": "failed",
        "scheduler_failure_evidence": [evidence],
    }


def build_final_json_scheduler_fields_decision(record: Mapping[str, object]) -> FinalJsonSchedulerFieldsDecision:
    """Return replayable scheduler-owned final JSON field projection state."""
    if not is_exact_mapping(record):
        return FinalJsonSchedulerFieldsDecision(
            fields=_scheduler_fields_failure("unsupported_scheduler_record", record),
            reason="unsupported_scheduler_record",
            accepted=False,
            record_is_mapping=False,
        )
    section = build_final_json_scheduler_section(record)
    if section is None:
        return FinalJsonSchedulerFieldsDecision(
            fields=_EMPTY_FINAL_JSON_FIELDS,
            reason="scheduler_evidence_absent",
            accepted=True,
            record_is_mapping=True,
        )
    return FinalJsonSchedulerFieldsDecision(
        fields=scheduler_fields_from_section(section),
        reason="scheduler_fields_projected",
        accepted=True,
        record_is_mapping=True,
    )


def build_final_json_scheduler_fields(record: Mapping[str, object]) -> Mapping[str, object]:
    """Return scheduler-owned final JSON fields for one compact record."""
    return build_final_json_scheduler_fields_decision(record).fields


def build_final_json_compact_error_fields(
    record: Mapping[str, object],
    *,
    error_type: str,
    message: str = "",
) -> dict[str, object]:
    """Return scheduler-owned final JSON fields for compact-result failures."""
    return scheduler_fields_from_section(
        build_final_json_compact_error_section(record, error_type=error_type, message=message)
    )


def scheduler_fields_from_section(section: Mapping[str, object] | None) -> dict[str, object]:
    """Project a scheduler evidence section into final JSON mirror fields."""
    if section is None:
        return _scheduler_fields_failure("scheduler_section_missing", section)
    materialized = materialize_scheduler_mapping(section)
    if type(materialized) is not dict:
        return _scheduler_fields_failure("scheduler_section_materialization_failed", section)
    return {
        "scheduler": materialized,
        "scheduler_status": dict.get(materialized, "scheduler_status"),
        "scheduler_failure_evidence": dict.get(materialized, "evidence", []),
    }


__all__ = (
    "FinalJsonSchedulerFieldsDecision",
    "build_final_json_compact_error_fields",
    "build_final_json_scheduler_fields",
    "build_final_json_scheduler_fields_decision",
    "scheduler_fields_from_section",
)
