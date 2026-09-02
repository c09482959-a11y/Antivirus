"""Immutable retry decision and exhaustion contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.contracts.contract_fields import (
    contract_bool,
    contract_int,
    contract_mapping_value,
    contract_sequence,
    contract_text,
    merge_contract_issues,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_snapshots import immutable_snapshot_tuple


@dataclass(frozen=True, slots=True)
class RetryDecision:
    retry_allowed: bool
    exhausted: bool = False
    attempt: int = 0
    max_attempts: int = 0
    reason: str = ""
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        retry_allowed, retry_allowed_issue = contract_bool(self.retry_allowed, field_name="retry_allowed", default=False)
        exhausted, exhausted_issue = contract_bool(self.exhausted, field_name="exhausted", default=False)
        attempt, attempt_issue = contract_int(self.attempt, field_name="attempt", default=0, minimum=0)
        max_attempts, max_attempts_issue = contract_int(self.max_attempts, field_name="max_attempts", default=0, minimum=0)
        reason, reason_issue = contract_text(self.reason, field_name="reason", default="")
        evidence_items, evidence_issue = contract_sequence(self.evidence, field_name="evidence")
        object.__setattr__(self, "retry_allowed", retry_allowed)
        object.__setattr__(self, "exhausted", exhausted)
        object.__setattr__(self, "attempt", attempt)
        object.__setattr__(self, "max_attempts", max_attempts)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "evidence", immutable_snapshot_tuple(merge_contract_issues(evidence_items, retry_allowed_issue, exhausted_issue, attempt_issue, max_attempts_issue, reason_issue, evidence_issue)))

    def as_dict(self) -> dict[str, object]:
        return {
            "retry_allowed": self.retry_allowed,
            "exhausted": self.exhausted,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "reason": self.reason,
            "evidence": materialize_scheduler_mapping(self.evidence),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "RetryDecision":
        return cls(
            retry_allowed=contract_mapping_value(value, "retry_allowed", default=False),
            exhausted=contract_mapping_value(value, "exhausted", default=False),
            attempt=contract_mapping_value(value, "attempt", default=0),
            max_attempts=contract_mapping_value(value, "max_attempts", default=0),
            reason=contract_mapping_value(value, "reason", default=""),
            evidence=contract_mapping_value(value, "evidence", default=()),
        )


@dataclass(frozen=True, slots=True)
class RetryExhaustionResult:
    exhausted: bool = True
    job_id: str = ""
    reason: str = "retry_exhausted"
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        exhausted, exhausted_issue = contract_bool(self.exhausted, field_name="exhausted", default=True)
        job_id, job_id_issue = contract_text(self.job_id, field_name="job_id", default="")
        reason, reason_issue = contract_text(self.reason, field_name="reason", default="retry_exhausted")
        evidence_items, evidence_issue = contract_sequence(self.evidence, field_name="evidence")
        object.__setattr__(self, "exhausted", exhausted)
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "evidence", immutable_snapshot_tuple(merge_contract_issues(evidence_items, exhausted_issue, job_id_issue, reason_issue, evidence_issue)))

    def as_dict(self) -> dict[str, object]:
        return {
            "exhausted": self.exhausted,
            "job_id": self.job_id,
            "reason": self.reason,
            "evidence": materialize_scheduler_mapping(self.evidence),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "RetryExhaustionResult":
        return cls(
            exhausted=contract_mapping_value(value, "exhausted", default=True),
            job_id=contract_mapping_value(value, "job_id", default=""),
            reason=contract_mapping_value(value, "reason", default="retry_exhausted"),
            evidence=contract_mapping_value(value, "evidence", default=()),
        )


__all__ = ("RetryDecision", "RetryExhaustionResult")
