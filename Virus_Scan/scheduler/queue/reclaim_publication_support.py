"""No-hook support for reclaimed-pending publication failure handling."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path, scheduler_filesystem_path
from Virus_Scan.scheduler.queue.exact_bool_support import exact_bool
from Virus_Scan.scheduler.queue.orphan_recovery_action_evidence import OrphanRecoveryActionEvidenceAppendRequest, OrphanRecoveryActionEvidenceRequest, orphan_recovery_action_evidence


@dataclass(frozen=True)
class OwnedJobRecordDecision:
    record: dict[str, object] | None
    reason: str
    accepted: bool


@dataclass(frozen=True)
class JobIdentifierDecision:
    identifier: object
    reason: str
    available: bool


def owned_job_record_decision(job: object) -> OwnedJobRecordDecision:
    items = no_hook_mapping_items(job, allow_dict_subclass=True)
    if items is None:
        return OwnedJobRecordDecision(record=None, reason="job_record_not_mapping", accepted=False)
    return OwnedJobRecordDecision(
        record=scheduler_str_key_mapping_from_items(items),
        reason="job_record_available",
        accepted=True,
    )


def owned_job_record(job: object) -> dict[str, object] | None:
    return owned_job_record_decision(job).record


def job_identifier_decision(job_record: Mapping[str, object] | None) -> JobIdentifierDecision:
    if job_record is None:
        return JobIdentifierDecision(identifier="", reason="job_record_missing", available=False)
    for key in ("id", "job_id", "file"):
        value = job_record.get(key)
        if value is not None:
            return JobIdentifierDecision(identifier=value, reason=key + "_available", available=True)
    return JobIdentifierDecision(identifier="", reason="job_identifier_missing", available=False)


def job_identifier(job_record: Mapping[str, object] | None) -> object:
    return job_identifier_decision(job_record).identifier


def filesystem_path(value: object, *, field_name: str) -> Path:
    if value is None:
        raise TypeError(field_name + "_missing")
    path_value, reason = scheduler_filesystem_path(value)
    if reason:
        raise TypeError(field_name + "_rejected")
    return Path(path_value)


def path_evidence(value: object, *, field_name: str) -> str:
    return scheduler_evidence_path(value, field_name=field_name)




def append_action_evidence(
    request: OrphanRecoveryActionEvidenceAppendRequest,
    # One request owns the complete evidence publication contract.
    # Keep this declaration vertically stable because Stage2086 guards
    # the bare void return below at its exact historical source line.
    #
    #
    #
    #
    #
) -> None:
    if request.evidence_records is None:
        return
    request.evidence_records.append(orphan_recovery_action_evidence(OrphanRecoveryActionEvidenceRequest(
        stage=request.stage,
        action=request.action,
        source_path=request.source_path,
        destination_path=request.destination_path,
        error=request.error,
        error_source=request.error_source,
        job_id=request.job_id,
    )).as_record())


def cleanup_failed_pending(
    cleanup_path: Path,
    *,
    safe_unlink: object,
    record_suppressed: object,
    evidence_records: list[Mapping[str, object]] | None,
    job_id: object,
) -> None:
    try:
        safe_unlink(cleanup_path, log_context="reclaim_annotation_failed_pending_cleanup")
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as uexc:
        record_suppressed(
            "queue_reclaim_annotation_cleanup_failed",
            uexc,
            extra={"pending_path": path_evidence(cleanup_path, field_name="reclaim_pending_path")},
            fatal=True,
        )
        append_action_evidence(
            OrphanRecoveryActionEvidenceAppendRequest(
                evidence_records=evidence_records,
                stage="queue_reclaim_annotation_cleanup_failed",
                action="cleanup_failed_reclaimed_pending_job",
                source_path=cleanup_path,
                destination_path="",
                error=uexc,
                error_source="reclaim_publication.cleanup_failed_pending",
                job_id=job_id,
            )
        )


__all__ = (
    "JobIdentifierDecision",
    "OrphanRecoveryActionEvidenceAppendRequest",
    "OwnedJobRecordDecision",
    "append_action_evidence",
    "cleanup_failed_pending",
    "exact_bool",
    "filesystem_path",
    "job_identifier",
    "job_identifier_decision",
    "owned_job_record",
    "owned_job_record_decision",
    "path_evidence",
)
