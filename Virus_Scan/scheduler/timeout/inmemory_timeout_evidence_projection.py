"""Projection of timeout/retry evidence onto in-memory job records."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.contracts.evidence_record_support import (
    scheduler_mapping_items,
    scheduler_mapping_value,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.timeout.inmemory_timeout_retry_evidence import evidence_identity


@dataclass(frozen=True)
class TimeoutEvidenceJobRecordDecision:
    status: str
    reason: str
    record: dict[str, object] | None


@dataclass(frozen=True)
class TimeoutEvidenceAppendDecision:
    status: str
    reason: str
    appended: bool


def job_record_for_timeout_evidence_decision(job_records: object, job_id: object) -> TimeoutEvidenceJobRecordDecision:
    if type(job_records) is not dict:
        return TimeoutEvidenceJobRecordDecision(status="unsupported_records", reason="unsupported_timeout_job_records", record=None)
    candidates: tuple[object, ...] = (job_id,)
    if type(job_id) is str and str.__str__(job_id).isdecimal():
        candidates = (job_id, int(str.__str__(job_id), 10))
    elif type(job_id) is int and type(job_id) is not bool:
        candidates = (job_id, int.__str__(job_id))
    for candidate in candidates:
        record = dict.get(job_records, candidate)
        if type(record) is dict:
            return TimeoutEvidenceJobRecordDecision(status="accepted", reason="", record=record)
    return TimeoutEvidenceJobRecordDecision(status="missing_record", reason="missing_timeout_job_record", record=None)


def job_record_for_timeout_evidence(job_records: object, job_id: object) -> object:
    return job_record_for_timeout_evidence_decision(job_records, job_id).record


def _existing_timeout_evidence_identities(record: Mapping[str, object]) -> set[tuple[object, ...]]:
    identities: set[tuple[object, ...]] = set()
    raw_evidence = scheduler_mapping_value(record, "timeout_retry_evidence", default=())
    evidence_items = no_hook_sequence_items(raw_evidence) if type(raw_evidence) in (tuple, list) else ()
    for evidence in evidence_items:
        if scheduler_mapping_items(evidence) is not None:
            identities.add(evidence_identity(evidence))
    return identities


def _append_timeout_evidence_once_decision(
    *,
    record: dict[str, object],
    evidence: Mapping[str, object],
) -> TimeoutEvidenceAppendDecision:
    evidence_dict = materialize_scheduler_mapping(evidence)
    if type(evidence_dict) is not dict:
        return TimeoutEvidenceAppendDecision(status="unsupported_evidence", reason="unsupported_timeout_evidence", appended=False)
    evidence_key = evidence_identity(evidence_dict)
    if evidence_key in _existing_timeout_evidence_identities(record):
        return TimeoutEvidenceAppendDecision(status="duplicate", reason="duplicate_timeout_evidence", appended=False)
    raw_current = dict.get(record, "timeout_retry_evidence", ())
    current_items = no_hook_sequence_items(raw_current) if type(raw_current) in (tuple, list) else ()
    current_records = tuple(
        materialize_scheduler_mapping(item)
        for item in current_items
        if scheduler_mapping_items(item) is not None
    )
    record["timeout_retry_evidence"] = (*current_records, evidence_dict)
    record["timeout_retry_evidence_recorded"] = True
    raw_history = dict.get(record, "history", ())
    history = no_hook_sequence_items(raw_history) if type(raw_history) in (tuple, list) else ()
    record["history"] = (*history, {'reason': dict.get(evidence_dict, 'reason', 'timeout_retry_evidence'), 'action': dict.get(evidence_dict, 'action', 'timeout_retry_evidence'), 'timeout_retry_evidence': evidence_dict})
    return TimeoutEvidenceAppendDecision(status="appended", reason="", appended=True)



def attach_timeout_evidence_to_job_records(
    *,
    job_records: object,
    evidence_records: tuple[Mapping[str, object], ...],
) -> None:
    records = no_hook_sequence_items(evidence_records) if type(evidence_records) in (tuple, list) else ()
    for evidence in records:
        if scheduler_mapping_items(evidence) is None:
            continue
        record = job_record_for_timeout_evidence(
            job_records,
            scheduler_mapping_value(evidence, "job_id"),
        )
        if record is None:
            continue
        _append_timeout_evidence_once_decision(record=record, evidence=evidence)
