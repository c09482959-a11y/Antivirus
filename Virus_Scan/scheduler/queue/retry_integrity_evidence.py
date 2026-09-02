"""Queue-owned immutable retry integrity evidence records."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_exception_text,
)
from Virus_Scan.scheduler.queue.retry_evidence_support import (
    normalize_retry_evidence,
    retry_evidence_int,
)


def _normalize_integrity_evidence(
    instance: object,
    expected_type: type,
    *,
    include_original_error: bool = False,
) -> None:
    text_fields: tuple[str, ...] = (
        "file",
        "error_category",
        "error_source",
        "detail",
    )
    if include_original_error:
        text_fields += ("original_error",)
    normalize_retry_evidence(
        instance,
        expected_type=expected_type,
        integer_fields=("attempt",),
        text_fields=text_fields,
    )

@dataclass(frozen=True, slots=True)
class QueueRetryIntegrityClearEvidence:
    file: str
    attempt: int
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        _normalize_integrity_evidence(self, QueueRetryIntegrityClearEvidence)

    def as_record(self) -> dict[str, object]:
        return {
            "stage": "queue_retry_integrity_clear",
            "file": self.file,
            "attempt": self.attempt,
            "error_category": self.error_category,
            "error_source": self.error_source,
            "detail": self.detail,
            "final_json_must_record": self.final_json_must_record,
            "checkpoint_must_record": self.checkpoint_must_record,
            "replay_must_reproduce": self.replay_must_reproduce,
        }

    def as_scan_integrity(self) -> dict[str, object]:
        return {
            "queue_retry_integrity_clear_failed": True,
            "queue_retry_integrity_clear_evidence": self.as_record(),
            "queue_failure": True,
            "had_degraded_stage": True,
            "allow_learning": False,
        }


@dataclass(frozen=True, slots=True)
class QueueRetryIntegrityPersistenceEvidence:
    file: str
    attempt: int
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        _normalize_integrity_evidence(self, QueueRetryIntegrityPersistenceEvidence)

    def as_record(self) -> dict[str, object]:
        return {
            "stage": "queue_retry_integrity_persistence",
            "file": self.file,
            "attempt": self.attempt,
            "error_category": self.error_category,
            "error_source": self.error_source,
            "detail": self.detail,
            "final_json_must_record": self.final_json_must_record,
            "checkpoint_must_record": self.checkpoint_must_record,
            "replay_must_reproduce": self.replay_must_reproduce,
        }

    def as_scan_integrity(self) -> dict[str, object]:
        return {
            "queue_retry_integrity_persistence_failed": True,
            "queue_retry_integrity_persistence_evidence": self.as_record(),
            "queue_failure": True,
            "had_degraded_stage": True,
            "allow_learning": False,
        }


@dataclass(frozen=True, slots=True)
class QueueRetryIntegrityPersistenceReportEvidence:
    file: str
    attempt: int
    error_category: str
    error_source: str
    detail: str
    original_error: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        _normalize_integrity_evidence(
            self,
            QueueRetryIntegrityPersistenceReportEvidence,
            include_original_error=True,
        )

    def as_record(self) -> dict[str, object]:
        return {
            "stage": "queue_retry_integrity_persistence_report",
            "file": self.file,
            "attempt": self.attempt,
            "error_category": self.error_category,
            "error_source": self.error_source,
            "detail": self.detail,
            "original_error": self.original_error,
            "final_json_must_record": self.final_json_must_record,
            "checkpoint_must_record": self.checkpoint_must_record,
            "replay_must_reproduce": self.replay_must_reproduce,
        }

    def as_scan_integrity(self) -> dict[str, object]:
        return {
            "queue_retry_integrity_persistence_report_failed": True,
            "queue_retry_integrity_persistence_report_evidence": self.as_record(),
            "queue_failure": True,
            "had_degraded_stage": True,
            "allow_learning": False,
        }


def retry_integrity_clear_evidence(*, path: object, attempt: int, error: BaseException) -> QueueRetryIntegrityClearEvidence:
    return QueueRetryIntegrityClearEvidence(
        file=scheduler_evidence_path(path, field_name="retry_path"),
        attempt=retry_evidence_int(attempt, field_name="attempt"),
        error_category=no_hook_type_name(error),
        error_source="queue.retry_policy.clear_integrity",
        detail=scheduler_exception_text(error),
    )


def retry_integrity_persistence_evidence(*, path: object, attempt: int, error: BaseException) -> QueueRetryIntegrityPersistenceEvidence:
    return QueueRetryIntegrityPersistenceEvidence(
        file=scheduler_evidence_path(path, field_name="retry_path"),
        attempt=retry_evidence_int(attempt, field_name="attempt"),
        error_category=no_hook_type_name(error),
        error_source="queue.retry_policy.set_integrity",
        detail=scheduler_exception_text(error),
    )


def retry_integrity_persistence_report_evidence(
    *, path: object, attempt: int, error: BaseException, original_error: BaseException
) -> QueueRetryIntegrityPersistenceReportEvidence:
    return QueueRetryIntegrityPersistenceReportEvidence(
        file=scheduler_evidence_path(path, field_name="retry_path"),
        attempt=retry_evidence_int(attempt, field_name="attempt"),
        error_category=no_hook_type_name(error),
        error_source="queue.retry_policy.report_retry_log_failure",
        detail=scheduler_exception_text(error),
        original_error=scheduler_exception_text(original_error),
    )


__all__ = (
    "QueueRetryIntegrityClearEvidence",
    "QueueRetryIntegrityPersistenceEvidence",
    "QueueRetryIntegrityPersistenceReportEvidence",
    "retry_integrity_clear_evidence",
    "retry_integrity_persistence_evidence",
    "retry_integrity_persistence_report_evidence",
)
