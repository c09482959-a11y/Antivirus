"""Timeout-owned evidence deduplication for retry/cancel publications."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_items
from Virus_Scan.scheduler.evidence.evidence_identity_support import evidence_identity_value
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_text


def _retry_indexed_field_name(field_name: object, index: int) -> str:
    if type(index) is int and type(index) is not bool:
        index_text = int.__str__(index)
    else:
        index_text = "unknown"
    return (
        scheduler_evidence_text(
            field_name,
            missing_text="timeout_retry_evidence",
            field_name="timeout_retry_evidence_field",
        )
        + "["
        + index_text
        + "]"
    )


def _projection_failure(value: object, *, field_name: str, reason: str) -> Mapping[str, object]:
    record = unsupported_scheduler_value_evidence(value, field_name=field_name)
    record["stage"] = "inmemory_timeout_evidence_projection"
    record["reason"] = reason
    record["error_source"] = "scheduler.timeout.inmemory_timeout_retry_evidence"
    return record


def evidence_identity(record: Mapping[str, object]) -> tuple[object, ...]:
    """Return a stable, no-hook evidence identity used for deduplication."""

    return (
        evidence_identity_value(record, "stage"),
        evidence_identity_value(record, "job_id"),
        evidence_identity_value(record, "reason"),
        evidence_identity_value(record, "action"),
        evidence_identity_value(record, "pid"),
        evidence_identity_value(record, "attempt"),
        evidence_identity_value(record, "generation"),
        evidence_identity_value(record, "lifecycle_state"),
        evidence_identity_value(record, "error_category"),
        evidence_identity_value(record, "error_source"),
        evidence_identity_value(record, "detail"),
    )


def evidence_not_already_present(
    *,
    candidates: tuple[Mapping[str, object], ...],
    existing: tuple[Mapping[str, object], ...],
) -> tuple[Mapping[str, object], ...]:
    """Project only candidate evidence not already present in existing output."""

    existing_records = no_hook_sequence_items(existing) if type(existing) in (tuple, list) else ()
    candidate_records = no_hook_sequence_items(candidates) if type(candidates) in (tuple, list) else ()
    seen = {
        evidence_identity(record)
        for record in existing_records
        if scheduler_mapping_items(record) is not None
    }
    projected: list[Mapping[str, object]] = []
    for index, candidate in enumerate(candidate_records):
        if scheduler_mapping_items(candidate) is None:
            projected.append(
                _projection_failure(
                    candidate,
                    field_name=_retry_indexed_field_name("candidate_evidence", index),
                    reason="candidate_evidence_record_rejected",
                )
            )
            continue
        candidate_dict = materialize_scheduler_mapping(candidate)
        if type(candidate_dict) is not dict:
            projected.append(
                _projection_failure(
                    candidate,
                    field_name=_retry_indexed_field_name("candidate_evidence", index),
                    reason="candidate_evidence_materialization_failed",
                )
            )
            continue
        identity = evidence_identity(candidate_dict)
        if identity in seen:
            continue
        seen.add(identity)
        projected.append(candidate_dict)
    return tuple(projected)


__all__ = ("evidence_identity", "evidence_not_already_present")
