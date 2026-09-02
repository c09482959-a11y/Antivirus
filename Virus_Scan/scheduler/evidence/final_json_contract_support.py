"""Shared support for scheduler contract-status final JSON projection."""
from __future__ import annotations

from typing import Iterable, Mapping, TYPE_CHECKING

from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.evidence.final_json_contract_support_decisions import empty_scheduler_status_decision

if TYPE_CHECKING:
    from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord


def mapping_from_scheduler_value(value: object) -> Mapping[str, object]:
    empty_decision = empty_scheduler_status_decision(value)
    if empty_decision.is_empty:
        return {
            "status": "failed",
            "failed": True,
            "empty_scheduler_status": True,
            "error_category": "scheduler_status_empty",
            "error_source": "scheduler.evidence.final_json_contract_support",
            "message": "scheduler status value was empty or unavailable",
            "reason": empty_decision.reason,
            "value_type": no_hook_type_name(value),
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }
    materialized = materialize_scheduler_mapping(value)
    if isinstance(materialized, Mapping):
        return materialized
    return {
        "status": "failed",
        "failed": True,
        "error_category": "scheduler_mapping_materialization_not_mapping",
        "error_source": "scheduler.evidence.final_json_contract_support",
        "message": "scheduler status materialized to non-mapping value",
        "value_type": no_hook_type_name(value),
        "materialized_type": no_hook_type_name(materialized),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }



def _mapping_materialization_failure(value: object, exc: BaseException) -> Mapping[str, object]:
    return {
        "status": "failed",
        "failed": True,
        "error_category": "scheduler_mapping_materialization_failed",
        "error_source": "scheduler.evidence.final_json_contract_support",
        "message": "scheduler mapping materialization failed",
        "exception_type": no_hook_type_name(exc),
        "value_type": no_hook_type_name(value),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }



def scheduler_status_sources(record: Mapping[str, object], existing: Mapping[str, object] | None) -> tuple[Mapping[str, object], ...]:
    sources: list[Mapping[str, object]] = []
    if isinstance(existing, Mapping):
        sources.append(existing)
    if isinstance(record, Mapping):
        sources.append(record)
    return tuple(sources)


def dedupe_scheduler_evidence_records(records: Iterable[SchedulerEvidenceRecord]) -> tuple[SchedulerEvidenceRecord, ...]:
    out: list[SchedulerEvidenceRecord] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for record in records:
        key = (record.stage, record.error_category, record.queue_id, record.job_id, record.worker_id, record.path)
        if key in seen:
            continue
        seen.add(key)
        out.append(record)
    return tuple(out)


def dedupe_contract_records(records: Iterable[SchedulerEvidenceRecord]) -> tuple[SchedulerEvidenceRecord, ...]:
    return dedupe_scheduler_evidence_records(records)


__all__ = ("dedupe_contract_records", "dedupe_scheduler_evidence_records", "mapping_from_scheduler_value", "scheduler_status_sources")
