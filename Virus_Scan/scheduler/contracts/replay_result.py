"""Immutable replay snapshot and comparison contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.contracts.contract_fields import (
    contract_bool,
    contract_mapping_value,
    contract_sequence,
    contract_text,
    merge_contract_issues,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_snapshots import immutable_snapshot_tuple


@dataclass(frozen=True, slots=True)
class ReplaySnapshot:
    replay_id: str = ""
    records: tuple[Mapping[str, object], ...] = ()
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        replay_id, replay_id_issue = contract_text(self.replay_id, field_name="replay_id", default="")
        records, records_issue = contract_sequence(self.records, field_name="records")
        evidence, evidence_issue = contract_sequence(self.evidence, field_name="evidence")
        object.__setattr__(self, "replay_id", replay_id)
        object.__setattr__(self, "records", immutable_snapshot_tuple(merge_contract_issues(records, records_issue)))
        object.__setattr__(self, "evidence", immutable_snapshot_tuple(merge_contract_issues(evidence, replay_id_issue, evidence_issue)))

    def as_dict(self) -> dict[str, object]:
        return {
            "replay_id": self.replay_id,
            "records": materialize_scheduler_mapping(self.records),
            "evidence": materialize_scheduler_mapping(self.evidence),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "ReplaySnapshot":
        return cls(
            replay_id=contract_mapping_value(value, "replay_id", default=""),
            records=contract_mapping_value(value, "records", default=()),
            evidence=contract_mapping_value(value, "evidence", default=()),
        )


@dataclass(frozen=True, slots=True)
class ReplayComparisonResult:
    matched: bool
    expected: ReplaySnapshot
    actual: ReplaySnapshot
    mismatches: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.expected, ReplaySnapshot) or not isinstance(self.actual, ReplaySnapshot):
            exception_message = "ReplayComparisonResult requires ReplaySnapshot boundaries"
            raise TypeError(exception_message)
        matched, matched_issue = contract_bool(self.matched, field_name="matched", default=False)
        mismatches, mismatches_issue = contract_sequence(self.mismatches, field_name="mismatches")
        object.__setattr__(self, "matched", matched)
        object.__setattr__(self, "mismatches", immutable_snapshot_tuple(merge_contract_issues(mismatches, matched_issue, mismatches_issue)))

    def as_dict(self) -> dict[str, object]:
        return {
            "matched": self.matched,
            "expected": self.expected.as_dict(),
            "actual": self.actual.as_dict(),
            "mismatches": materialize_scheduler_mapping(self.mismatches),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "ReplayComparisonResult":
        return cls(
            matched=contract_mapping_value(value, "matched", default=False),
            expected=ReplaySnapshot.from_mapping(contract_mapping_value(value, "expected", default={}) or {}),
            actual=ReplaySnapshot.from_mapping(contract_mapping_value(value, "actual", default={}) or {}),
            mismatches=contract_mapping_value(value, "mismatches", default=()),
        )


__all__ = ("ReplaySnapshot", "ReplayComparisonResult")
