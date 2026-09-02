"""Replay mismatch result ownership for deterministic scheduler comparisons."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping, cast
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.scheduler.contracts.replay_result import ReplayComparisonResult, ReplaySnapshot
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text
from Virus_Scan.scheduler.replay.replay_comparison_record import QueueReplayComparisonRecord
_REPLAY_COMPARISON_REQUIRES_CANONICAL_SNAPSHOT = "scheduler replay comparison requires canonical snapshot"
class SchedulerReplayMismatchError(RuntimeError):
    """Replay mismatch carrying immutable comparison evidence."""
    def __init__(self, comparison_result: ReplayComparisonResult) -> None:
        super().__init__("scheduler replay comparison mismatch")
        self.comparison_result = comparison_result
@dataclass(frozen=True, slots=True)
class QueueReplayComparisonSnapshot:
    records: tuple[QueueReplayComparisonRecord, ...]
    def __post_init__(self) -> None:
        if self.records is None:
            records: tuple[QueueReplayComparisonRecord, ...] = ()
        elif type(self.records) in {list, tuple}:
            records = tuple(self.records)
        else:
            exception_message = "scheduler replay snapshot records require exact tuple"
            raise TypeError(exception_message)
        if any(type(record) is not QueueReplayComparisonRecord for record in records):
            exception_message = "scheduler replay snapshot contains unsupported record"
            raise TypeError(exception_message)
        object.__setattr__(self, "records", tuple(sorted(records, key=QueueReplayComparisonRecord.sort_key)))
    @classmethod
    def from_results(cls, results: object) -> "QueueReplayComparisonSnapshot":
        source_results: tuple[object, ...]
        if results is None:
            source_results = ()
        elif type(results) is tuple:
            source_results = cast("tuple[object, ...]", results)
        elif type(results) is list:
            source_results = tuple(cast("list[object]", results))
        else:
            exception_message = "scheduler replay results require exact sequence"
            raise TypeError(exception_message)
        materialized_records: list[QueueReplayComparisonRecord] = []
        for result in source_results:
            result_items = no_hook_mapping_items(result)
            if result_items is None:
                exception_message = "scheduler replay result requires exact mapping"
                raise TypeError(exception_message)
            materialized_records.append(
                QueueReplayComparisonRecord.from_result(cast("Mapping[str, object]", dict(result_items)))
            )
        records: tuple[QueueReplayComparisonRecord, ...] = tuple(materialized_records)
        ordered = tuple(sorted(records, key=QueueReplayComparisonRecord.sort_key))
        job_ids = [record.job_id for record in ordered]
        if len(job_ids) != len(set(job_ids)):
            exception_message = "scheduler replay snapshot contains duplicate job ids"
            raise RuntimeError(exception_message)
        file_ids = [record.file_identity for record in ordered]
        if len(file_ids) != len(set(file_ids)):
            exception_message = "scheduler replay snapshot contains duplicate file identities"
            raise RuntimeError(exception_message)
        return cls(ordered)
    @property
    def job_count(self) -> int:
        return len(self.records)
    @property
    def emitted_result_count(self) -> int:
        return len(self.records)
    @property
    def duplicate_count(self) -> int:
        return sum(record.duplicate_count for record in self.records)
    @property
    def recovery_count(self) -> int:
        return sum(record.recovery_count for record in self.records)
    @property
    def failed_count(self) -> int:
        return sum(record.failed_count for record in self.records)
    def assert_equivalent(self, other: "QueueReplayComparisonSnapshot") -> None:
        if type(other) is not QueueReplayComparisonSnapshot:
            raise RuntimeError(_REPLAY_COMPARISON_REQUIRES_CANONICAL_SNAPSHOT)
        comparison = build_replay_comparison_result(self, other)
        if not comparison.matched:
            raise SchedulerReplayMismatchError(comparison)
    def as_dict(self) -> dict[str, object]:
        return {
            "job_count": self.job_count,
            "emitted_result_count": self.emitted_result_count,
            "duplicate_count": self.duplicate_count,
            "recovery_count": self.recovery_count,
            "failed_count": self.failed_count,
            "records": [QueueReplayComparisonRecord.as_dict(record) for record in self.records],
        }
def _snapshot_mapping(snapshot: object) -> dict[object, object]:
    if type(snapshot) is ReplaySnapshot:
        snapshot_value = ReplaySnapshot.as_dict(snapshot)
    elif type(snapshot) is QueueReplayComparisonSnapshot:
        snapshot_value = QueueReplayComparisonSnapshot.as_dict(snapshot)
    else:
        exception_message = "scheduler replay comparison requires exact ReplaySnapshot or QueueReplayComparisonSnapshot"
        raise TypeError(exception_message)
    snapshot_items = no_hook_mapping_items(snapshot_value)
    if snapshot_items is None:
        exception_message = "scheduler replay snapshot mapping unavailable"
        raise TypeError(exception_message)
    return dict(snapshot_items)
def _records_by_job(snapshot: object) -> dict[str, Mapping[str, object]]:
    snapshot_mapping = _snapshot_mapping(snapshot)
    records = no_hook_sequence_items(dict.get(snapshot_mapping, "records"))
    indexed: dict[str, Mapping[str, object]] = {}
    for index, record in enumerate(records):
        record_items = no_hook_mapping_items(record)
        if record_items is None:
            indexed["unsupported_replay_record_" + int.__str__(index)] = {
                "replay_record_rejected": True,
            }
            continue
        record_snapshot = dict(record_items)
        job_id, reason = scheduler_text(
            dict.get(record_snapshot, "job_id"),
            unsupported_reason="scheduler_replay_job_id_rejected",
        )
        if reason or job_id == "":
            job_id = "missing_replay_job_id_" + int.__str__(index)
            record_snapshot["replay_job_id_rejected"] = reason or "missing_replay_job_id"
        indexed[job_id] = record_snapshot
    return indexed
def _snapshot_contract(replay_id: str, snapshot: object) -> ReplaySnapshot:
    snapshot_mapping = _snapshot_mapping(snapshot)
    records = no_hook_sequence_items(dict.get(snapshot_mapping, "records"))
    return ReplaySnapshot(replay_id=replay_id, records=records, evidence=())
def _missing_mismatch(kind: str, job_id: str, record: Mapping[str, object]) -> dict[str, object]:
    record_items = no_hook_mapping_items(record)
    record_snapshot = dict(record_items) if record_items is not None else {
        "replay_record_rejected": True,
    }
    return {
        "mismatch_type": kind,
        "job_id": job_id,
        "record": record_snapshot,
        "error_category": "replay_mismatch",
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }
def build_replay_mismatches(expected_snapshot: object, actual_snapshot: object) -> tuple[Mapping[str, object], ...]:
    expected_records = _records_by_job(expected_snapshot)
    actual_records = _records_by_job(actual_snapshot)
    mismatches: list[Mapping[str, object]] = []
    for job_id in sorted(set(expected_records) | set(actual_records), key=str.casefold):
        expected = expected_records.get(job_id)
        actual = actual_records.get(job_id)
        if expected is None and actual is not None:
            mismatches.append(_missing_mismatch("unexpected_job", job_id, actual))
            continue
        if actual is None and expected is not None:
            mismatches.append(_missing_mismatch("missing_job", job_id, expected))
            continue
        if expected is None or actual is None:
            continue
        expected_items = no_hook_mapping_items(expected)
        actual_items = no_hook_mapping_items(actual)
        expected_mapping = dict(expected_items) if expected_items is not None else {}
        actual_mapping = dict(actual_items) if actual_items is not None else {}
        for field in sorted(set(expected_mapping) | set(actual_mapping), key=str.casefold):
            left = dict.get(expected_mapping, field)
            right = dict.get(actual_mapping, field)
            if left != right:
                mismatches.append({
                    "mismatch_type": "field_mismatch",
                    "job_id": job_id,
                    "field": field,
                    "expected": left,
                    "actual": right,
                    "error_category": "replay_mismatch",
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_record": True,
                })
    return tuple(mismatches)
def build_replay_comparison_result(expected_snapshot: object, actual_snapshot: object) -> ReplayComparisonResult:
    mismatches = build_replay_mismatches(expected_snapshot, actual_snapshot)
    return ReplayComparisonResult(
        matched=not mismatches,
        expected=_snapshot_contract("expected", expected_snapshot),
        actual=_snapshot_contract("actual", actual_snapshot),
        mismatches=mismatches,
    )
__all__ = (
    "QueueReplayComparisonRecord",
    "QueueReplayComparisonSnapshot",
    "SchedulerReplayMismatchError",
    "build_replay_comparison_result",
    "build_replay_mismatches",
)
