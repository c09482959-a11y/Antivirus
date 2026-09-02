"""Memory-toxicity active-job and job-record lookup helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, MutableMapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items


@dataclass(frozen=True)
class MemoryToxicityLookupDecision:
    status: str
    reason: str
    value: object


def memory_toxicity_owned_pid_decision(info: object) -> MemoryToxicityLookupDecision:
    """Return a replayable decision for active-job pid ownership lookup."""

    info_items = no_hook_mapping_items(info)
    if info_items is None:
        return MemoryToxicityLookupDecision(
            status="unsupported_active_info",
            reason="unsupported_active_job_info",
            value=None,
        )
    for key, value in info_items:
        if key == "pid":
            return MemoryToxicityLookupDecision(status="accepted", reason="", value=value)
    return MemoryToxicityLookupDecision(
        status="missing_active_pid",
        reason="missing_active_job_pid",
        value=None,
    )


def memory_toxicity_job_record_decision(
    job_records: MutableMapping[object, object] | None,
    job_id: object,
) -> MemoryToxicityLookupDecision:
    """Return a replayable decision for memory-toxicity job record lookup."""

    if job_records is None:
        return MemoryToxicityLookupDecision(status="missing_records", reason="missing_job_records", value=None)
    record = job_records.get(job_id)
    if isinstance(record, MutableMapping):
        return MemoryToxicityLookupDecision(status="accepted", reason="", value=record)
    return MemoryToxicityLookupDecision(status="missing_record", reason="missing_memory_toxicity_job_record", value=None)


def memory_toxicity_job_record_for(job_records: MutableMapping[object, object] | None, job_id: object) -> object:
    """Return a mutable scheduler job record for memory-toxicity evidence attachment."""

    return memory_toxicity_job_record_decision(job_records, job_id).value


def memory_toxicity_owned_jobs(*, active: Mapping[object, object], pid: object) -> tuple[object, ...]:
    """Return jobs currently owned by a worker pid."""

    active_items = no_hook_mapping_items(active) or ()
    owned: list[object] = []
    for job_id, info in active_items:
        pid_decision = memory_toxicity_owned_pid_decision(info)
        if pid_decision.status == "accepted" and pid_decision.value == pid:
            owned.append(job_id)
    return tuple(owned)


def memory_toxicity_affected_info_decision(*, active: Mapping[object, object], job_id: object) -> MemoryToxicityLookupDecision:
    """Return a replayable decision for affected active-job info lookup."""

    if job_id is None:
        return MemoryToxicityLookupDecision(status="missing_job_id", reason="missing_affected_job_id", value=None)
    info = active.get(job_id)
    if isinstance(info, MutableMapping):
        return MemoryToxicityLookupDecision(status="accepted", reason="", value=info)
    return MemoryToxicityLookupDecision(status="missing_info", reason="missing_affected_job_info", value=None)


def memory_toxicity_affected_info(*, active: Mapping[object, object], job_id: object) -> object:
    """Return mutable active info for the affected job when available."""

    return memory_toxicity_affected_info_decision(active=active, job_id=job_id).value


__all__ = (
    "MemoryToxicityLookupDecision",
    "memory_toxicity_affected_info",
    "memory_toxicity_affected_info_decision",
    "memory_toxicity_job_record_decision",
    "memory_toxicity_job_record_for",
    "memory_toxicity_owned_jobs",
    "memory_toxicity_owned_pid_decision",
)
