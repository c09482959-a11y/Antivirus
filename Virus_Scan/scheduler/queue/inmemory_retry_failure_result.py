"""Queue-owned failed-result construction for in-memory retry exhaustion.

This module owns conversion of worker-error-result factory/schema failures into
explicit retry-exhaustion evidence.  It does not own retry decisions, queue
mutation, worker lifecycle, or timeout policy.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_evidence_text,
    scheduler_exception_text,
)

from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    INMEMORY_RETRY_RECOVERY_EXCEPTIONS,
    retry_suppression_record_failure_error,
)
from Virus_Scan.scheduler.queue.inmemory_retry_publication import retry_exhaustion_result_evidence


@dataclass(frozen=True, slots=True)
class InMemoryRetryFailureResult:
    result: Mapping[str, object]
    evidence: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        result = self.result if self.result is not None else {}
        object.__setattr__(self, "result", immutable_mapping(result))
        object.__setattr__(self, "evidence", None if self.evidence is None else immutable_mapping(self.evidence))

    def result_dict(self) -> dict[str, object]:
        return materialize_scheduler_mapping(self.result)

    def evidence_dict(self) -> dict[str, object] | None:
        if self.evidence is None:
            return None
        return materialize_scheduler_mapping(self.evidence)



def build_worker_error_result(
    *,
    worker_error_result: Callable[[object, BaseException | str], dict[str, object]],
    path: object,
    error: BaseException,
    job_id: int,
    generation: int,
    reason: object,
) -> InMemoryRetryFailureResult:
    """Return a dict result and immutable evidence if result construction degraded."""
    try:
        result = worker_error_result(path, error)
    except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as result_exc:
        detail_error: BaseException = result_exc
        try:
            record_scheduler_suppressed("suppressed_exception", result_exc)
        except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as record_exc:
            detail_error = retry_suppression_record_failure_error(result_exc, record_exc)
        evidence = retry_exhaustion_result_evidence(
            job_id=job_id,
            generation=int(generation),
            reason=reason,
            path=path,
            error=detail_error,
        )
        return InMemoryRetryFailureResult(
            {
                "file": scheduler_evidence_path(path, field_name="retry_path"),
                "error": scheduler_exception_text(error),
                "scheduler_failure_reason": scheduler_evidence_text(
                    reason,
                    missing_text="retry_exhausted",
                    field_name="retry_reason",
                ),
                "scheduler_retry_count": int(generation),
                "retry_exhaustion_result_failed": True,
                "retry_exhaustion_result_evidence": dict(evidence.as_record()),
                "scan_integrity": evidence.as_scan_integrity(),
            },
            dict(evidence.as_record()),
        )
    if isinstance(result, dict):
        return InMemoryRetryFailureResult(result, None)
    evidence = retry_exhaustion_result_evidence(
        job_id=job_id,
        generation=int(generation),
        reason=reason,
        path=path,
        error=TypeError("worker_error_result must return a dict, got " + no_hook_type_name(result)),
    )
    return InMemoryRetryFailureResult(
        {
            "file": scheduler_evidence_path(path, field_name="retry_path"),
            "error": scheduler_exception_text(error),
            "scheduler_failure_reason": scheduler_evidence_text(
                reason,
                missing_text="retry_exhausted",
                field_name="retry_reason",
            ),
            "scheduler_retry_count": int(generation),
            "retry_exhaustion_result_failed": True,
            "retry_exhaustion_result_evidence": dict(evidence.as_record()),
            "scan_integrity": evidence.as_scan_integrity(),
        },
        dict(evidence.as_record()),
    )


__all__ = ("InMemoryRetryFailureResult", "build_worker_error_result")
