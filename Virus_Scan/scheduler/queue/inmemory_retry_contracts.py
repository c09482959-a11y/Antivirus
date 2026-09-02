"""Immutable in-memory retry recovery contracts and validation helpers.

This module owns retry-recovery scalar/history contract coercion and the
immutable retry decision result.  It is queue-owned and intentionally has no
runtime, worker, timeout, or orchestration imports.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, MutableMapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_text,
    scheduler_exception_text,
)
from Virus_Scan.scheduler.queue.inmemory_retry_contract_evidence import InMemoryRetryContractEvidence
from Virus_Scan.scheduler.queue.retry_evidence_support import (
    retry_evidence_int,
    retry_history_snapshot,
    retry_mapping_snapshot,
)

INMEMORY_RETRY_RECOVERY_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, OverflowError)
_RETRY_CONTRACT_FAILURE_REQUIRES_EXACT_EVIDENCE = "retry contract failure requires exact evidence contract"


@dataclass(frozen=True, slots=True)
class InMemoryRetryDecision:
    retried: bool
    completed_delta: int = 0
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        if type(self.retried) is not bool:
            exception_message = "retry decision retried flag requires exact bool"
            raise TypeError(exception_message)
        object.__setattr__(
            self,
            "completed_delta",
            retry_evidence_int(
                self.completed_delta,
                field_name="completed_delta",
            ),
        )
        object.__setattr__(self, "evidence", immutable_tuple(self.evidence))



def retry_contract_evidence(*, job_id: int, generation: int, reason: object, field: str, error: BaseException) -> InMemoryRetryContractEvidence:
    field_text = scheduler_evidence_text(field, missing_text="retry_field", field_name="retry_field")
    return InMemoryRetryContractEvidence(
        job_id=retry_evidence_int(job_id, field_name="job_id"),
        generation=retry_evidence_int(generation, field_name="generation"),
        reason=scheduler_evidence_text(reason, missing_text="retry_contract", field_name="retry_reason"),
        field=field_text,
        error_category=no_hook_type_name(error),
        error_source="inmemory_retry_recovery." + field_text,
        detail=scheduler_exception_text(error),
    )


def record_retry_contract_failure(*, record: MutableMapping[str, object], evidence: InMemoryRetryContractEvidence) -> dict[str, object]:
    updated = retry_mapping_snapshot(record, field_name="retry_record")
    if type(evidence) is not InMemoryRetryContractEvidence:
        raise TypeError(_RETRY_CONTRACT_FAILURE_REQUIRES_EXACT_EVIDENCE)
    evidence_record = dict(
        InMemoryRetryContractEvidence.as_record(evidence)
    )
    failures = retry_history_snapshot(
        dict.get(updated, "retry_contract_failures")
    )
    updated["retry_contract_failed"] = True
    updated["retry_contract_failures"] = (*failures, evidence_record)
    history = retry_history_snapshot(dict.get(updated, "history"))
    updated["history"] = (
        *history,
        {
            "reason": "retry_contract_failed",
            "action": "retry_contract_failed",
            "retry_contract_evidence": evidence_record,
        },
    )
    return updated


def retry_suppression_record_failure_error(primary_error: BaseException, record_error: BaseException) -> RuntimeError:
    return RuntimeError(
        scheduler_exception_text(primary_error)
        + "; suppression_record_failed="
        + scheduler_exception_text(record_error)
    )


def safe_retry_int(*, value: object, replacement_value: int, job_id: int, generation: int, reason: object, field: str, record: MutableMapping[str, object]) -> tuple[int, dict[str, object]]:
    try:
        return (
            retry_evidence_int(value, field_name=field),
            retry_mapping_snapshot(record, field_name="retry_record"),
        )
    except ValueError as value_exc:
        evidence = retry_contract_evidence(
            job_id=job_id,
            generation=generation,
            reason=reason,
            field=field,
            error=value_exc,
        )
        if evidence.field == "attempt":
            replacement_field_name = "attempt_replacement"
        elif evidence.field == "max_job_retries":
            replacement_field_name = "max_job_retries_replacement"
        elif evidence.field == "pid":
            replacement_field_name = "pid_replacement"
        else:
            replacement_field_name = "retry_replacement"
        return (
            retry_evidence_int(
                replacement_value,
                field_name=replacement_field_name,
            ),
            record_retry_contract_failure(record=record, evidence=evidence),
        )


def safe_retry_history(*, record: MutableMapping[str, object], job_id: int, generation: int, reason: object) -> tuple[object, ...]:
    record_snapshot = retry_mapping_snapshot(
        record,
        field_name="retry_record",
    )
    history = dict.get(record_snapshot, "history")
    if history is None or type(history) in {list, tuple}:
        return retry_history_snapshot(history)
    evidence = retry_contract_evidence(
        job_id=job_id,
        generation=generation,
        reason=reason,
        field="history",
        error=TypeError(
            "history must be list or tuple; value_type=" + no_hook_type_name(history)
        ),
    )
    updated = record_retry_contract_failure(record=record, evidence=evidence)
    if type(record) is dict:
        dict.clear(record)
        dict.update(record, updated)
    return retry_history_snapshot(dict.get(updated, "history"))


def project_retry_contract_failures(*, integrity: dict[str, object], record: MutableMapping[str, object]) -> dict[str, object]:
    failures = retry_history_snapshot(
        dict.get(
            retry_mapping_snapshot(record, field_name="retry_record"),
            "retry_contract_failures",
        )
    )
    if not failures:
        return integrity
    integrity.update(
        {
            "queue_failure": True,
            "had_degraded_stage": True,
            "inmemory_retry_contract_failed": True,
            "inmemory_retry_contract_failures": failures,
            "allow_learning": False,
        }
    )
    return integrity


__all__ = (
    "INMEMORY_RETRY_RECOVERY_EXCEPTIONS",
    "InMemoryRetryDecision",
    "project_retry_contract_failures",
    "record_retry_contract_failure",
    "retry_contract_evidence",
    "retry_suppression_record_failure_error",
    "safe_retry_history",
    "safe_retry_int",
)
