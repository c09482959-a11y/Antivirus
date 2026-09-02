"""Immutable queue claim contracts."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.scheduler.contracts.contract_fields import (
    contract_int,
    contract_mapping_rejected,
    contract_mapping_value,
    contract_text,
    merge_contract_issues,
)
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping


@dataclass(frozen=True, slots=True)
class QueueClaim:
    job_id: str
    file: str = ""
    worker_id: str = ""
    generation: int = 0
    attempt: int = 0
    metadata: Mapping[str, object] = field(default_factory=immutable_mapping)

    def __post_init__(self) -> None:
        job_id, job_issue = contract_text(self.job_id, field_name="job_id", default="")
        file_text, file_issue = contract_text(self.file, field_name="file", default="")
        worker_id, worker_issue = contract_text(self.worker_id, field_name="worker_id", default="")
        generation, generation_issue = contract_int(self.generation, field_name="generation", default=0, minimum=0)
        attempt, attempt_issue = contract_int(self.attempt, field_name="attempt", default=0, minimum=0)
        metadata_issues = merge_contract_issues(job_issue, file_issue, worker_issue, generation_issue, attempt_issue)
        metadata = immutable_mapping(self.metadata)
        if metadata_issues:
            current = materialize_scheduler_mapping(metadata)
            if type(current) is not dict:
                current = {}
            current["queue_claim_contract_rejections"] = tuple(metadata_issues)
            metadata = immutable_mapping(current)
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "file", file_text)
        object.__setattr__(self, "worker_id", worker_id)
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "attempt", attempt)
        object.__setattr__(self, "metadata", metadata)

    def as_dict(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "file": self.file,
            "worker_id": self.worker_id,
            "generation": self.generation,
            "attempt": self.attempt,
            "metadata": materialize_scheduler_mapping(self.metadata),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "QueueClaim":
        metadata = contract_mapping_value(value, "metadata", default={})
        mapping_issues = contract_mapping_rejected(value, field_name="queue_claim_mapping")
        if mapping_issues:
            metadata = {"queue_claim_contract_rejections": mapping_issues}
        return cls(
            job_id=contract_mapping_value(value, "job_id", default=""),
            file=contract_mapping_value(value, "file", default=""),
            worker_id=contract_mapping_value(value, "worker_id", default=""),
            generation=contract_mapping_value(value, "generation", default=0),
            attempt=contract_mapping_value(value, "attempt", default=0),
            metadata=metadata,
        )


__all__ = ("QueueClaim",)
