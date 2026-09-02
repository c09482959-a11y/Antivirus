"""Status-source extraction for scheduler final JSON projection."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scheduler.evidence.final_json_contract_support import mapping_from_scheduler_value
from Virus_Scan.scheduler.evidence.final_json_exact_fields import exact_mapping_value, is_empty_placeholder, is_exact_mapping
from Virus_Scan.scheduler.internal.immutable_outputs import unsupported_scheduler_value_evidence

_MISSING = object()
_EMPTY_REPLAY_STATUS: Mapping[str, object] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class SchedulerReplayStatusDecision:
    """Replayable decision for scheduler replay-status extraction."""

    status: Mapping[str, object]
    reason: str
    accepted: bool
    source_found: bool



def _status_source_failure(reason: str, value: object, *, field_name: str) -> Mapping[str, object]:
    evidence = unsupported_scheduler_value_evidence(value, field_name=field_name)
    evidence["scheduler_status_source_failed"] = True
    evidence["reason"] = reason if type(reason) is str else "scheduler_status_source_failed"
    return evidence


def checkpoint_status_from_record(record: Mapping[str, object], existing: Mapping[str, object] | None) -> Mapping[str, object]:
    saw_exact_source = False
    for source in (existing, record):
        if not is_exact_mapping(source):
            continue
        saw_exact_source = True
        for key in ("checkpoint", "checkpoint_status", "scheduler_checkpoint"):
            raw_value = exact_mapping_value(source, key, default=_MISSING)
            if raw_value is _MISSING:
                continue
            if is_empty_placeholder(raw_value):
                if key == "checkpoint":
                    continue
                return mapping_from_scheduler_value(raw_value)
            value = mapping_from_scheduler_value(raw_value)
            if value:
                return value
    if not saw_exact_source:
        return _status_source_failure(
            "unsupported_checkpoint_status_source",
            record,
            field_name="scheduler_checkpoint_status_source",
        )
    return _checkpoint_reference_status(record)


def _checkpoint_reference_status(record: Mapping[str, object]) -> Mapping[str, object]:
    keys = ("checkpoint_path", "checkpoint_status", "checkpoint_reference", "replay_checkpoint_reference")
    out: dict[str, object] = {}
    unsupported: dict[str, object] = {}
    for key in keys:
        value = exact_mapping_value(record, key)
        if value is None:
            continue
        if type(value) is str:
            text = str.__str__(value)
            if text:
                out[key] = text
            continue
        if type(value) in {bool, int}:
            out[key] = value
            continue
        unsupported[key] = unsupported_scheduler_value_evidence(value, field_name=key)
    if unsupported:
        return {
            "status": "failed",
            "failed": True,
            "error_category": "scheduler_checkpoint_reference_unsupported",
            "error_source": "scheduler.evidence.final_json_status_sources",
            "message": "checkpoint reference contains unsupported scheduler value",
            "unsupported_checkpoint_references": unsupported,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }
    return out


def replay_status_from_record_decision(
    record: Mapping[str, object],
    existing: Mapping[str, object] | None,
) -> SchedulerReplayStatusDecision:
    """Return replayable scheduler replay-status extraction state."""
    saw_exact_source = False
    for source in (existing, record):
        if not is_exact_mapping(source):
            continue
        saw_exact_source = True
        for key in ("replay_comparison_result", "replay_result", "replay_status", "scheduler_replay"):
            raw_value = exact_mapping_value(source, key, default=_MISSING)
            if raw_value is _MISSING:
                continue
            if is_empty_placeholder(raw_value):
                return SchedulerReplayStatusDecision(
                    status=mapping_from_scheduler_value(raw_value),
                    reason="empty_replay_status_projected",
                    accepted=False,
                    source_found=True,
                )
            value = mapping_from_scheduler_value(raw_value)
            if value:
                return SchedulerReplayStatusDecision(
                    status=value,
                    reason="replay_status_projected",
                    accepted=True,
                    source_found=True,
                )
    if not saw_exact_source:
        return SchedulerReplayStatusDecision(
            status=_status_source_failure("unsupported_replay_status_source", record, field_name="scheduler_replay_status_source"),
            reason="unsupported_replay_status_source",
            accepted=False,
            source_found=False,
        )
    return SchedulerReplayStatusDecision(
        status=_EMPTY_REPLAY_STATUS,
        reason="replay_status_absent",
        accepted=True,
        source_found=True,
    )


def replay_status_from_record(record: Mapping[str, object], existing: Mapping[str, object] | None) -> Mapping[str, object]:
    return replay_status_from_record_decision(record, existing).status


__all__ = (
    "SchedulerReplayStatusDecision",
    "checkpoint_status_from_record",
    "mapping_from_scheduler_value",
    "replay_status_from_record",
    "replay_status_from_record_decision",
)
