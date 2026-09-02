"""Queue-owned publication evidence helpers for in-memory retry recovery.

This module owns retry/cancel/lifecycle/result publication evidence and cancel
payload publication.  It does not own worker execution, timeout policy, or
scheduler orchestration.
"""
from __future__ import annotations

from typing import MutableMapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_evidence_text,
    scheduler_exception_text,
)
from Virus_Scan.scheduler.queue.inmemory_retry_lifecycle_evidence import InMemoryRetryLifecycleEvidence
from Virus_Scan.scheduler.queue.inmemory_retry_result_evidence import (
    InMemoryRetryExhaustionResultEvidence,
    InMemoryRetryPendingPublicationEvidence,
    InMemoryRetryResultPublicationEvidence,
)
from Virus_Scan.scheduler.queue.inmemory_retry_cancel_publication import (
    publish_cancel_payload,
)
from Virus_Scan.scheduler.queue.retry_evidence_support import (
    retry_evidence_int,
    retry_history_snapshot,
    retry_mapping_snapshot,
)


def _record_publication_failure(
    *,
    record: object,
    evidence: object,
    expected_type: type,
    failed_field: str,
    evidence_field: str,
    action: str,
) -> dict[str, object]:
    updated = retry_mapping_snapshot(record, field_name="retry_record")
    if type(evidence) is not expected_type:
        expected_name = "retry_publication_evidence"
        try:
            name = type.__getattribute__(expected_type, "__name__")
        except (AttributeError, TypeError, RuntimeError):
            name = ""
        if type(name) is str and name:
            expected_name = str.__str__(name)
        raise TypeError(
            "scheduler retry publication requires exact "
            + expected_name
        )
    evidence_record = dict(evidence.as_record())
    updated[failed_field] = True
    updated[evidence_field] = evidence_record
    history = retry_history_snapshot(dict.get(updated, "history"))
    updated["history"] = (
        *history,
        {
            "reason": action,
            "action": action,
            failed_field: True,
            evidence_field: evidence_record,
        },
    )
    return updated


def retry_pending_publication_evidence(*, job_id: int, generation: int, reason: object, path: object, error: BaseException) -> InMemoryRetryPendingPublicationEvidence:
    return InMemoryRetryPendingPublicationEvidence(
        job_id=retry_evidence_int(job_id, field_name="job_id"),
        generation=retry_evidence_int(generation, field_name="generation"),
        reason=scheduler_evidence_text(reason, missing_text="retry_pending_publication", field_name="retry_reason"),
        file=scheduler_evidence_path(path, field_name="retry_path"),
        error_category=no_hook_type_name(error),
        error_source="inmemory_retry_recovery.pending_publication",
        detail=scheduler_exception_text(error),
    )


def record_retry_pending_publication_failure(*, record: MutableMapping[str, object], evidence: InMemoryRetryPendingPublicationEvidence) -> dict[str, object]:
    return _record_publication_failure(
        record=record,
        evidence=evidence,
        expected_type=InMemoryRetryPendingPublicationEvidence,
        failed_field="retry_pending_publication_failed",
        evidence_field="retry_pending_publication_evidence",
        action="retry_pending_publication_failed",
    )


def retry_result_publication_evidence(*, job_id: int, generation: int, reason: object, path: object, error: BaseException) -> InMemoryRetryResultPublicationEvidence:
    return InMemoryRetryResultPublicationEvidence(
        job_id=retry_evidence_int(job_id, field_name="job_id"),
        generation=retry_evidence_int(generation, field_name="generation"),
        reason=scheduler_evidence_text(reason, missing_text="retry_result_publication", field_name="retry_reason"),
        file=scheduler_evidence_path(path, field_name="retry_path"),
        error_category=no_hook_type_name(error),
        error_source="inmemory_retry_recovery.results_publication",
        detail=scheduler_exception_text(error),
    )


def record_retry_result_publication_failure(*, record: MutableMapping[str, object], evidence: InMemoryRetryResultPublicationEvidence) -> dict[str, object]:
    return _record_publication_failure(
        record=record,
        evidence=evidence,
        expected_type=InMemoryRetryResultPublicationEvidence,
        failed_field="retry_result_publication_failed",
        evidence_field="retry_result_publication_evidence",
        action="retry_result_publication_failed",
    )


def retry_lifecycle_evidence(*, job_id: int, generation: int, reason: object, lifecycle_state: str, error: BaseException) -> InMemoryRetryLifecycleEvidence:
    return InMemoryRetryLifecycleEvidence(
        job_id=retry_evidence_int(job_id, field_name="job_id"),
        generation=retry_evidence_int(generation, field_name="generation"),
        reason=scheduler_evidence_text(reason, missing_text="retry", field_name="retry_reason"),
        lifecycle_state=scheduler_evidence_text(
            lifecycle_state,
            missing_text="retry_lifecycle",
            field_name="retry_lifecycle_state",
        ),
        error_category=no_hook_type_name(error),
        error_source="inmemory_retry_recovery.lifecycle_recorder",
        detail=scheduler_exception_text(error),
    )


def retry_exhaustion_result_evidence(*, job_id: int, generation: int, reason: object, path: object, error: BaseException) -> InMemoryRetryExhaustionResultEvidence:
    return InMemoryRetryExhaustionResultEvidence(
        job_id=retry_evidence_int(job_id, field_name="job_id"),
        generation=retry_evidence_int(generation, field_name="generation"),
        reason=scheduler_evidence_text(reason, missing_text="retry_exhausted", field_name="retry_reason"),
        file=scheduler_evidence_path(path, field_name="retry_path"),
        error_category=no_hook_type_name(error),
        error_source="inmemory_retry_recovery.worker_error_result",
        detail=scheduler_exception_text(error),
    )


def record_retry_lifecycle_failure(*, record: MutableMapping[str, object], evidence: InMemoryRetryLifecycleEvidence) -> dict[str, object]:
    return _record_publication_failure(
        record=record,
        evidence=evidence,
        expected_type=InMemoryRetryLifecycleEvidence,
        failed_field="retry_lifecycle_publication_failed",
        evidence_field="retry_lifecycle_publication_evidence",
        action="retry_lifecycle_publication_failed",
    )


__all__ = (
    "publish_cancel_payload",
    "record_retry_lifecycle_failure",
    "record_retry_pending_publication_failure",
    "record_retry_result_publication_failure",
    "retry_exhaustion_result_evidence",
    "retry_lifecycle_evidence",
    "retry_pending_publication_evidence",
    "retry_result_publication_evidence",
)
