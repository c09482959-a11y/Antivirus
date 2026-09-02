"""Immutable timeout result contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.contracts.contract_fields import (
    contract_bool,
    contract_float,
    contract_mapping_value,
    contract_sequence,
    contract_text,
    merge_contract_issues,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_snapshots import immutable_snapshot_tuple


@dataclass(frozen=True, slots=True)
class TimeoutResult:
    timed_out: bool = False
    elapsed_sec: float = 0.0
    budget_sec: float = 0.0
    stage: str = "timeout"
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        timed_out, timed_out_issue = contract_bool(self.timed_out, field_name="timed_out", default=False)
        elapsed_sec, elapsed_issue = contract_float(self.elapsed_sec, field_name="elapsed_sec", default=0.0, minimum=0.0)
        budget_sec, budget_issue = contract_float(self.budget_sec, field_name="budget_sec", default=0.0, minimum=0.0)
        stage, stage_issue = contract_text(self.stage, field_name="stage", default="timeout")
        evidence_items, evidence_issue = contract_sequence(self.evidence, field_name="evidence")
        object.__setattr__(self, "timed_out", timed_out)
        object.__setattr__(self, "elapsed_sec", elapsed_sec)
        object.__setattr__(self, "budget_sec", budget_sec)
        object.__setattr__(self, "stage", stage)
        object.__setattr__(self, "evidence", immutable_snapshot_tuple(merge_contract_issues(evidence_items, timed_out_issue, elapsed_issue, budget_issue, stage_issue, evidence_issue)))

    def as_dict(self) -> dict[str, object]:
        return {
            "timed_out": self.timed_out,
            "elapsed_sec": self.elapsed_sec,
            "budget_sec": self.budget_sec,
            "stage": self.stage,
            "evidence": materialize_scheduler_mapping(self.evidence),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "TimeoutResult":
        return cls(
            timed_out=contract_mapping_value(value, "timed_out", default=False),
            elapsed_sec=contract_mapping_value(value, "elapsed_sec", default=0.0),
            budget_sec=contract_mapping_value(value, "budget_sec", default=0.0),
            stage=contract_mapping_value(value, "stage", default="timeout"),
            evidence=contract_mapping_value(value, "evidence", default=()),
        )


__all__ = ("TimeoutResult",)
