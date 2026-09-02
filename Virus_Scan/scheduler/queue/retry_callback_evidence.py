"""Queue-owned immutable retry callback evidence records."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_evidence_text,
    scheduler_exception_text,
)
from Virus_Scan.scheduler.queue.retry_evidence_support import (
    normalize_retry_evidence,
    retry_evidence_int,
)

@dataclass(frozen=True, slots=True)
class QueueRetryPolicyCallbackEvidence:
    file: str
    attempt: int
    callback_name: str
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        normalize_retry_evidence(
            self,
            expected_type=QueueRetryPolicyCallbackEvidence,
            integer_fields=("attempt",),
            text_fields=(
                "file",
                "callback_name",
                "error_category",
                "error_source",
                "detail",
            ),
        )

    def as_record(self) -> dict[str, object]:
        return {
            "stage": "queue_retry_policy_callback",
            "file": self.file,
            "attempt": self.attempt,
            "callback_name": self.callback_name,
            "error_category": self.error_category,
            "error_source": self.error_source,
            "detail": self.detail,
            "final_json_must_record": self.final_json_must_record,
            "checkpoint_must_record": self.checkpoint_must_record,
            "replay_must_reproduce": self.replay_must_reproduce,
        }

    def as_scan_integrity(self) -> dict[str, object]:
        return {
            "queue_retry_policy_callback_failed": True,
            "queue_retry_policy_callback_evidence": self.as_record(),
            "queue_failure": True,
            "had_degraded_stage": True,
            "allow_learning": False,
        }


def retry_policy_callback_evidence(*, path: object, attempt: int, callback_name: str, error: BaseException) -> QueueRetryPolicyCallbackEvidence:
    callback_text = scheduler_evidence_text(
        callback_name,
        missing_text="missing_retry_callback_name",
        field_name="retry_callback_name",
    )
    return QueueRetryPolicyCallbackEvidence(
        file=scheduler_evidence_path(path, field_name="retry_path"),
        attempt=retry_evidence_int(attempt, field_name="attempt"),
        callback_name=callback_text,
        error_category=no_hook_type_name(error),
        error_source="queue.retry_policy." + callback_text,
        detail=scheduler_exception_text(error),
    )


__all__ = ("QueueRetryPolicyCallbackEvidence", "retry_policy_callback_evidence")
