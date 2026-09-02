"""Queue-owned evidence for malformed in-memory retry contracts."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scheduler.queue.retry_evidence_support import (
    normalize_retry_evidence,
)


@dataclass(frozen=True, slots=True)
class InMemoryRetryContractEvidence:
    job_id: int
    generation: int
    reason: str
    field: str
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def __post_init__(self) -> None:
        normalize_retry_evidence(
            self,
            expected_type=InMemoryRetryContractEvidence,
            integer_fields=("job_id", "generation"),
            text_fields=(
                "reason",
                "field",
                "error_category",
                "error_source",
                "detail",
            ),
        )

    def as_record(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stage": "inmemory_retry_contract",
                "job_id": self.job_id,
                "generation": self.generation,
                "reason": self.reason,
                "field": self.field,
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
            "inmemory_retry_contract_failed": True,
            "inmemory_retry_contract_job_id": self.job_id,
            "inmemory_retry_contract_generation": self.generation,
            "inmemory_retry_contract_reason": self.reason,
            "inmemory_retry_contract_field": self.field,
            "inmemory_retry_contract_error_category": self.error_category,
            "inmemory_retry_contract_error_source": self.error_source,
            "inmemory_retry_contract_detail": self.detail[:1000],
            "allow_learning": False,
        }


__all__ = ("InMemoryRetryContractEvidence",)
