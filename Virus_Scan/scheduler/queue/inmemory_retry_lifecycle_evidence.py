"""Lifecycle publication evidence contracts for in-memory retry recovery."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scheduler.queue.retry_evidence_support import (
    normalize_retry_evidence,
)


@dataclass(frozen=True, slots=True)
class InMemoryRetryLifecycleEvidence:
    """Immutable evidence that retry lifecycle publication failed."""

    job_id: int
    generation: int
    reason: str
    lifecycle_state: str
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        normalize_retry_evidence(
            self,
            expected_type=InMemoryRetryLifecycleEvidence,
            integer_fields=("job_id", "generation"),
            text_fields=(
                "reason",
                "lifecycle_state",
                "error_category",
                "error_source",
                "detail",
            ),
        )

    def as_record(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stage": "inmemory_retry_lifecycle_publication",
                "job_id": self.job_id,
                "generation": self.generation,
                "reason": self.reason,
                "lifecycle_state": self.lifecycle_state,
                "error_category": self.error_category,
                "error_source": self.error_source,
                "detail": self.detail[:1000],
                "final_json_must_record": self.final_json_must_record,
                "checkpoint_must_record": self.checkpoint_must_record,
                "replay_must_reproduce": self.replay_must_reproduce,
            }
        )

    def as_scan_integrity(self) -> dict[str, object]:
        return {
            "queue_failure": True,
            "had_degraded_stage": True,
            "retry_lifecycle_publication_failed": True,
            "retry_lifecycle_publication_job_id": self.job_id,
            "retry_lifecycle_publication_generation": self.generation,
            "retry_lifecycle_publication_state": self.lifecycle_state,
            "retry_lifecycle_publication_reason": self.reason,
            "retry_lifecycle_publication_error_category": self.error_category,
            "retry_lifecycle_publication_error_source": self.error_source,
            "retry_lifecycle_publication_detail": self.detail[:1000],
            "allow_learning": False,
        }
