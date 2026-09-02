"""Retry result and pending publication evidence contracts."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scheduler.queue.retry_evidence_support import (
    normalize_retry_evidence,
)


def _normalize_result_evidence(instance: object, expected_type: type) -> None:
    normalize_retry_evidence(
        instance,
        expected_type=expected_type,
        integer_fields=("job_id", "generation"),
        text_fields=(
            "reason",
            "file",
            "error_category",
            "error_source",
            "detail",
        ),
    )


@dataclass(frozen=True, slots=True)
class InMemoryRetryExhaustionResultEvidence:
    """Immutable evidence that retry exhaustion result construction failed."""

    job_id: int
    generation: int
    reason: str
    file: str
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        _normalize_result_evidence(
            self,
            InMemoryRetryExhaustionResultEvidence,
        )

    def as_record(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stage": "inmemory_retry_exhaustion_result",
                "job_id": self.job_id,
                "generation": self.generation,
                "reason": self.reason,
                "file": self.file,
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
            "retry_exhaustion_result_failed": True,
            "retry_exhaustion_result_job_id": self.job_id,
            "retry_exhaustion_result_generation": self.generation,
            "retry_exhaustion_result_reason": self.reason,
            "retry_exhaustion_result_error_category": self.error_category,
            "retry_exhaustion_result_error_source": self.error_source,
            "retry_exhaustion_result_detail": self.detail[:1000],
            "allow_learning": False,
        }


@dataclass(frozen=True, slots=True)
class InMemoryRetryPendingPublicationEvidence:
    """Immutable evidence that retry work could not be requeued."""

    job_id: int
    generation: int
    reason: str
    file: str
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        _normalize_result_evidence(
            self,
            InMemoryRetryPendingPublicationEvidence,
        )

    def as_record(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stage": "inmemory_retry_pending_publication",
                "job_id": self.job_id,
                "generation": self.generation,
                "reason": self.reason,
                "file": self.file,
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
            "retry_pending_publication_failed": True,
            "retry_pending_publication_job_id": self.job_id,
            "retry_pending_publication_generation": self.generation,
            "retry_pending_publication_reason": self.reason,
            "retry_pending_publication_error_category": self.error_category,
            "retry_pending_publication_error_source": self.error_source,
            "retry_pending_publication_detail": self.detail[:1000],
            "allow_learning": False,
        }


@dataclass(frozen=True, slots=True)
class InMemoryRetryResultPublicationEvidence:
    """Immutable evidence that exhausted retry result publication failed."""

    job_id: int
    generation: int
    reason: str
    file: str
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        _normalize_result_evidence(
            self,
            InMemoryRetryResultPublicationEvidence,
        )

    def as_record(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stage": "inmemory_retry_result_publication",
                "job_id": self.job_id,
                "generation": self.generation,
                "reason": self.reason,
                "file": self.file,
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
            "retry_result_publication_failed": True,
            "retry_result_publication_job_id": self.job_id,
            "retry_result_publication_generation": self.generation,
            "retry_result_publication_reason": self.reason,
            "retry_result_publication_error_category": self.error_category,
            "retry_result_publication_error_source": self.error_source,
            "retry_result_publication_detail": self.detail[:1000],
            "allow_learning": False,
        }
