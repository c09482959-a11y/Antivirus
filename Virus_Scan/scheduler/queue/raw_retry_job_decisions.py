"""Typed raw retry job preparation decisions with replayable reasons."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from Virus_Scan.scheduler.queue.default_text_support import queue_default_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int
from Virus_Scan.scheduler.internal.status_predicates import scheduler_status_equals, scheduler_status_not
from Virus_Scan.scheduler.queue.recovery_contract import build_inmemory_retry_transition, retry_already_pending

RawRetryMappingStatus = Literal["accepted", "rejected"]
RawRetryTimestampStatus = Literal["accepted", "missing", "rejected"]
RawRetryJobStatus = Literal["accepted", "rejected"]


@dataclass(frozen=True, slots=True)
class RawRetryMappingDecision:
    """Replayable no-hook mapping materialization outcome."""

    status: RawRetryMappingStatus
    mapping: dict[str, object]
    reason: str

    @property
    def accepted(self) -> bool:
        return scheduler_status_equals(self.status, "accepted")


@dataclass(frozen=True, slots=True)
class RawRetryTimestampDecision:
    """Replayable no-hook timestamp materialization outcome."""

    status: RawRetryTimestampStatus
    timestamp: float | None
    reason: str

    @property
    def accepted(self) -> bool:
        return scheduler_status_not(self.status, "rejected")


@dataclass(frozen=True, slots=True)
class RawRetryJobDecision:
    """Replayable raw retry job preparation outcome."""

    status: RawRetryJobStatus
    retry_job: dict[str, object] | None
    reason: str
    attempt: int
    max_retries: int
    result_mapping_reason: str
    timestamp_reason: str

    @property
    def accepted(self) -> bool:
        return scheduler_status_equals(self.status, "accepted")


def raw_retry_mapping_decision(value: object, *, rejected_reason: str) -> RawRetryMappingDecision:
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return RawRetryMappingDecision("rejected", {}, rejected_reason)
    return RawRetryMappingDecision("accepted", scheduler_str_key_mapping_from_items(items), "mapping_accepted")


def raw_retry_timestamp_decision(value: object | None) -> RawRetryTimestampDecision:
    if value is None:
        return RawRetryTimestampDecision("missing", None, "raw_retry_timestamp_missing")
    parsed, reason = scheduler_float(value, default=0.0, minimum=0.0, reason="raw_retry_timestamp_rejected")
    if reason:
        return RawRetryTimestampDecision("rejected", 0.0, str.__str__(reason))
    return RawRetryTimestampDecision("accepted", parsed, "raw_retry_timestamp_accepted")


def raw_retry_text(value: object, default: str) -> str:
    return queue_default_text(value, default)


def raw_retry_job_decision(
    job: object,
    result: object,
    *,
    max_retries_default: int = 1,
    now: float | None = None,
) -> RawRetryJobDecision:
    job_decision = raw_retry_mapping_decision(job, rejected_reason="raw_retry_job_mapping_rejected")
    if not job_decision.accepted:
        return RawRetryJobDecision("rejected", None, job_decision.reason, 0, max_retries_default, "not_evaluated", "not_evaluated")
    job_record = job_decision.mapping
    if retry_already_pending(job_record):
        return RawRetryJobDecision("rejected", None, "raw_retry_already_pending", 0, max_retries_default, "not_evaluated", "not_evaluated")
    attempt, _attempt_reason = scheduler_int(dict.get(job_record, "attempt"), default=0)
    max_retries, _max_reason = scheduler_int(dict.get(job_record, "max_retries"), default=max_retries_default)
    if attempt >= max_retries:
        return RawRetryJobDecision("rejected", None, "raw_retry_attempts_exhausted", attempt, max_retries, "not_evaluated", "not_evaluated")
    result_decision = raw_retry_mapping_decision(result, rejected_reason="raw_retry_result_mapping_rejected")
    result_record = result_decision.mapping if result_decision.accepted else {}
    last_error = raw_retry_text(dict.get(result_record, "error"), "")[:500]
    timestamp_decision = raw_retry_timestamp_decision(now)
    transition = build_inmemory_retry_transition(
        job_record,
        last_error if last_error != "" else "raw_retry",
        pid=dict.get(job_record, "worker_pid"),
        now=timestamp_decision.timestamp,
    )
    retry_job = transition.as_record()
    retry_job["attempt"] = transition.new_generation
    retry_job["max_retries"] = max_retries
    retry_job["retried"] = True
    retry_job["last_error"] = last_error
    retry_job["raw_retry_from_attempt"] = transition.old_generation
    job_type = raw_retry_text(dict.get(retry_job, "job_type"), "raw_stage")
    retry_job["job_type"] = job_type if job_type != "" else "raw_stage"
    return RawRetryJobDecision(
        "accepted",
        retry_job,
        "raw_retry_job_prepared",
        attempt,
        max_retries,
        result_decision.reason,
        timestamp_decision.reason,
    )


__all__ = (
    "RawRetryJobDecision",
    "RawRetryJobStatus",
    "RawRetryMappingDecision",
    "RawRetryMappingStatus",
    "RawRetryTimestampDecision",
    "RawRetryTimestampStatus",
    "raw_retry_job_decision",
    "raw_retry_mapping_decision",
    "raw_retry_text",
    "raw_retry_timestamp_decision",
)
