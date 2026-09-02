"""Queue-owned cancel-only evidence projection helpers."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_items, scheduler_mapping_value
from Virus_Scan.scheduler.evidence.evidence_identity_support import evidence_identity_value
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


def _cancel_projection_failure(value: object, *, field_name: str, reason: str) -> Mapping[str, object]:
    record = unsupported_scheduler_value_evidence(value, field_name=field_name)
    record["stage"] = "inmemory_cancel_evidence_projection"
    record["reason"] = reason
    record["error_source"] = "scheduler.queue.inmemory_cancel_evidence"
    return record



def cancel_evidence_identity(record: Mapping[str, object]) -> tuple[object, ...]:
    """Return a stable identity for cancel-only evidence dedupe."""

    return (
        evidence_identity_value(record, "stage"),
        evidence_identity_value(record, "job_id"),
        evidence_identity_value(record, "generation"),
        evidence_identity_value(record, "reason"),
        evidence_identity_value(record, "flags"),
        evidence_identity_value(record, "error_category"),
        evidence_identity_value(record, "error_source"),
        evidence_identity_value(record, "detail"),
    )


def cancel_publication_evidence_from_record(record: object) -> tuple[Mapping[str, object], ...]:
    """Return immutable cancel-publication evidence already stored on a job record."""

    if scheduler_mapping_items(record) is None:
        return (_cancel_projection_failure(
            record,
            field_name="job_record",
            reason="cancel_job_record_rejected",
        ),)
    evidence = scheduler_mapping_value(record, "cancel_publication_evidence")
    if evidence is None:
        return ()
    if scheduler_mapping_items(evidence) is None:
        return (_cancel_projection_failure(
            evidence,
            field_name="cancel_publication_evidence",
            reason="cancel_publication_evidence_rejected",
        ),)
    materialized = materialize_scheduler_mapping(evidence)
    if type(materialized) is dict:
        return (materialized,)
    return (_cancel_projection_failure(
        evidence,
        field_name="cancel_publication_evidence",
        reason="cancel_publication_evidence_materialization_failed",
    ),)



__all__ = (
    "cancel_evidence_identity",
    "cancel_publication_evidence_from_record",
)
