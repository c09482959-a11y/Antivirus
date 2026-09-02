"""Cancel publication evidence contracts for in-memory retry recovery."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, NoReturn

from Virus_Scan.scheduler.queue.retry_evidence_support import (
    normalize_retry_evidence,
)


_CANCEL_PUBLICATION_EXACT_EVIDENCE_CONTRACT = "cancel publication result requires exact evidence contract"


def _raise_cancel_publication_exact_evidence_contract() -> NoReturn:
    raise TypeError(_CANCEL_PUBLICATION_EXACT_EVIDENCE_CONTRACT)


@dataclass(frozen=True, slots=True)
class InMemoryCancelPublicationEvidence:
    """Immutable evidence that retry/cancel publication failed or degraded."""

    job_id: int
    generation: int
    reason: str
    error_category: str
    error_source: str
    detail: str
    flags: int | None = None
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        normalize_retry_evidence(
            self,
            expected_type=InMemoryCancelPublicationEvidence,
            integer_fields=("job_id", "generation"),
            optional_integer_fields=("flags",),
            text_fields=(
                "reason",
                "error_category",
                "error_source",
                "detail",
            ),
        )

    def as_record(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stage": "inmemory_retry_cancel_publication",
                "job_id": self.job_id,
                "generation": self.generation,
                "reason": self.reason,
                "flags": self.flags,
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
            "retry_cancel_publication_failed": True,
            "retry_cancel_publication_job_id": self.job_id,
            "retry_cancel_publication_generation": self.generation,
            "retry_cancel_publication_reason": self.reason,
            "retry_cancel_publication_error_category": self.error_category,
            "retry_cancel_publication_error_source": self.error_source,
            "retry_cancel_publication_detail": self.detail[:1000],
            "allow_learning": False,
        }


@dataclass(frozen=True, slots=True)
class InMemoryCancelPublicationResult:
    """Immutable output for one cancel/retry publication attempt."""

    published: bool
    evidence: InMemoryCancelPublicationEvidence | None = None

    def __post_init__(self) -> None:
        normalize_retry_evidence(
            self,
            expected_type=InMemoryCancelPublicationResult,
            boolean_fields=("published",),
        )
        if (
            self.evidence is not None
            and type(self.evidence) is not InMemoryCancelPublicationEvidence
        ):
            _raise_cancel_publication_exact_evidence_contract()

    def as_history_extra(self) -> dict[str, object]:
        if self.evidence is None:
            return {"cancel_publication_published": self.published}
        return {
            "cancel_publication_published": self.published,
            "cancel_publication_failed": True,
            "cancel_publication_evidence": dict(
                InMemoryCancelPublicationEvidence.as_record(self.evidence)
            ),
        }
