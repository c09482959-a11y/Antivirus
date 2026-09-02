"""Queue-owned immutable retry publication evidence records."""
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

@dataclass(frozen=True, slots=True)
class QueueRetryLogPublicationEvidence:
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
        normalize_retry_evidence(
            self,
            expected_type=QueueRetryLogPublicationEvidence,
            integer_fields=("attempt",),
            text_fields=(
                "file",
                "error_category",
                "error_source",
                "detail",
                "original_error",
            ),
        )

    def as_record(self) -> dict[str, object]:
        return {
            "stage": "queue_retry_log_publication",
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
            "queue_retry_log_publication_failed": True,
            "queue_retry_log_publication_evidence": self.as_record(),
            "queue_failure": True,
            "had_degraded_stage": True,
            "allow_learning": False,
        }


def retry_log_publication_evidence(*, path: object, attempt: int, error: BaseException, original_error: BaseException) -> QueueRetryLogPublicationEvidence:
    return QueueRetryLogPublicationEvidence(
        file=scheduler_evidence_path(path, field_name="retry_path"),
        attempt=retry_evidence_int(attempt, field_name="attempt"),
        error_category=no_hook_type_name(error),
        error_source="queue.retry_policy.report_retry_log_failure",
        detail=scheduler_exception_text(error),
        original_error=scheduler_exception_text(original_error),
    )


__all__ = ("QueueRetryLogPublicationEvidence", "retry_log_publication_evidence")
