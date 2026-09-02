"""Canonical scheduler evidence record ownership.

Queue, worker, timeout, retry, replay, and checkpoint domains produce immutable
SchedulerEvidenceRecord values; this module owns deterministic evidence
collection and the final JSON-ready scheduler evidence section.  It does
not mutate queue, worker, timeout, retry, replay, checkpoint, or runtime state.
"""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_items, scheduler_mapping_value
from Virus_Scan.scheduler.evidence.record_collection import collect_scheduler_evidence
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping


@dataclass(frozen=True, slots=True)
class ExactFlagValueDecision:
    flag: bool
    reason: str
    value_type: str


@dataclass(frozen=True, slots=True)
class RecordStageFlagDecision:
    matches: bool
    reason: str
    stage_fragment: str


def _exact_flag_value_decision(value: object) -> ExactFlagValueDecision:
    value_type = type(value).__name__
    if type(value) is bool:
        return ExactFlagValueDecision(value, "bool_flag", value_type)
    if type(value) is int:
        return ExactFlagValueDecision(value != 0, "int_flag", value_type)
    if type(value) is str:
        text_flag = str.__str__(value).strip().lower() in {"1", "true", "yes", "on"}
        return ExactFlagValueDecision(text_flag, "text_flag", value_type)
    return ExactFlagValueDecision(False, "unsupported_flag_value", value_type)


def _exact_flag_value(value: object) -> bool:
    return _exact_flag_value_decision(value).flag


def _evidence_status_mapping(value: object) -> Mapping[str, object]:
    items = scheduler_mapping_items(value)
    if items is None:
        return immutable_mapping()
    return immutable_mapping(scheduler_str_key_mapping_from_items(items))


@dataclass(frozen=True, slots=True)
class SchedulerEvidenceBundle:
    """Immutable scheduler evidence bundle for JSON/checkpoint/replay writers."""

    records: tuple[SchedulerEvidenceRecord, ...] = ()
    checkpoint_status: Mapping[str, object] = field(default_factory=immutable_mapping)
    replay_status: Mapping[str, object] = field(default_factory=immutable_mapping)

    def __post_init__(self) -> None:
        source_records = () if self.records is None else self.records
        records = collect_scheduler_evidence(source_records)
        object.__setattr__(self, "records", records)
        object.__setattr__(self, "checkpoint_status", immutable_mapping(self.checkpoint_status))
        object.__setattr__(self, "replay_status", immutable_mapping(self.replay_status))

    @property
    def fatal(self) -> bool:
        return any(record.fatal for record in self.records)

    @property
    def degraded(self) -> bool:
        return len(self.records) > 0

    @property
    def status(self) -> str:
        if self.fatal:
            return "fatal"
        if self.degraded:
            return "degraded"
        return "ok"

    def as_dict(self) -> dict[str, object]:
        return build_scheduler_json_evidence_section(
            self.records,
            checkpoint_status=self.checkpoint_status,
            replay_status=self.replay_status,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "SchedulerEvidenceBundle":
        if scheduler_mapping_items(value) is None:
            return cls(records=(SchedulerEvidenceRecord.from_mapping(value),))
        evidence_source = scheduler_mapping_value(value, "evidence", default=())
        checkpoint_status = _evidence_status_mapping(scheduler_mapping_value(value, "checkpoint", default={}))
        replay_status = _evidence_status_mapping(scheduler_mapping_value(value, "replay_comparison_result", default={}))
        return cls(
            records=collect_scheduler_evidence(evidence_source),
            checkpoint_status=checkpoint_status,
            replay_status=replay_status,
        )


def coerce_scheduler_evidence_record(value: SchedulerEvidenceRecord | Mapping[str, object]) -> SchedulerEvidenceRecord:
    if type(value) is SchedulerEvidenceRecord:
        return value
    items = scheduler_mapping_items(value)
    if items is not None:
        return SchedulerEvidenceRecord.from_mapping(dict(items))
    exception_message = "scheduler evidence requires SchedulerEvidenceRecord or mapping"
    raise TypeError(exception_message)


def build_scheduler_evidence_bundle(
    *sources: object,
    checkpoint_status: Mapping[str, object] | None = None,
    replay_status: Mapping[str, object] | None = None,
) -> SchedulerEvidenceBundle:
    return SchedulerEvidenceBundle(
        records=collect_scheduler_evidence(*sources),
        checkpoint_status={} if checkpoint_status is None else checkpoint_status,
        replay_status={} if replay_status is None else replay_status,
    )


def build_scheduler_json_evidence_section(
    records: Iterable[SchedulerEvidenceRecord | Mapping[str, object]],
    *,
    checkpoint_status: Mapping[str, object] | None = None,
    replay_status: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build the canonical scheduler section consumed by final JSON/checkpoint paths."""
    evidence = tuple(coerce_scheduler_evidence_record(record) for record in collect_scheduler_evidence(records if records is not None else ()))
    status = "fatal" if any(record.fatal for record in evidence) else ("degraded" if evidence else "ok")
    evidence_dicts = tuple(record.as_dict() for record in evidence)
    return {
        "scheduler_status": status,
        "degraded": len(evidence) > 0,
        "fatal": status == "fatal",
        "evidence": [dict(item) for item in evidence_dicts],
        "queue_claims": _records_for_stage(evidence_dicts, "queue_claim"),
        "queue_integrity_result": _records_for_stage(evidence_dicts, "queue_integrity"),
        "queue_recovery_result": _records_for_stage(evidence_dicts, "queue_recovery"),
        "worker_lifecycle_events": _records_for_stage(evidence_dicts, "worker_lifecycle"),
        "worker_failures": _records_for_stage(evidence_dicts, "worker"),
        "timeout_decisions": _records_for_stage(evidence_dicts, "timeout"),
        "retry_decisions": _records_for_stage(evidence_dicts, "retry"),
        "retry_exhaustion": _records_for_stage(evidence_dicts, "retry_exhaustion"),
        "orphan_recovery": _records_for_stage(evidence_dicts, "orphan_recovery"),
        "replay_comparison_result": materialize_scheduler_mapping({} if replay_status is None else replay_status),
        "checkpoint": materialize_scheduler_mapping({} if checkpoint_status is None else checkpoint_status),
        "fatal_vs_recoverable": {
            "fatal": [dict(item) for item in evidence_dicts if _exact_flag_value(dict.get(item, "fatal"))],
            "recoverable": [dict(item) for item in evidence_dicts if not _exact_flag_value(dict.get(item, "fatal"))],
        },
    }


def _records_for_stage(records: Iterable[Mapping[str, object]], stage_fragment: str) -> list[dict[str, object]]:
    fragment = str.__str__(stage_fragment) if type(stage_fragment) is str else ""
    selected: list[dict[str, object]] = []
    for record in records:
        stage_value = record.get("stage", "")
        category_value = record.get("error_category", "")
        stage = str.__str__(stage_value) if type(stage_value) is str else ""
        category = str.__str__(category_value) if type(category_value) is str else ""
        if fragment in stage or fragment in category or _record_flag_matches_stage(record, fragment):
            selected.append(dict(record))
    return selected


def _record_flag_matches_stage_decision(record: Mapping[str, object], stage_fragment: str) -> RecordStageFlagDecision:
    if stage_fragment == "retry":
        return RecordStageFlagDecision(_exact_flag_value(record.get("retry_state_affected")), "retry_state_flag", stage_fragment)
    if stage_fragment == "timeout":
        return RecordStageFlagDecision(_exact_flag_value(record.get("timeout_state_affected")), "timeout_state_flag", stage_fragment)
    return RecordStageFlagDecision(False, "unsupported_stage_fragment", stage_fragment)


def _record_flag_matches_stage(record: Mapping[str, object], stage_fragment: str) -> bool:
    return _record_flag_matches_stage_decision(record, stage_fragment).matches


__all__ = (
    "ExactFlagValueDecision",
    "RecordStageFlagDecision",
    "SchedulerEvidenceBundle",
    "build_scheduler_evidence_bundle",
    "build_scheduler_json_evidence_section",
    "coerce_scheduler_evidence_record",
    "collect_scheduler_evidence",
)
