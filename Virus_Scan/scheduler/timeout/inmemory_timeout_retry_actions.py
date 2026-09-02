"""Timeout-owned retry escalation actions for in-memory sweeps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import (
    record_timeout_recovery_failure,
    timeout_retry_evidence as build_timeout_retry_evidence,
)


@dataclass(frozen=True, slots=True)
class RetryOrFailEscalationRequest:
    """Inputs for one queue-owned retry/fail escalation publication."""

    recovery: object
    failures: list[Mapping[str, object]]
    job_id: object
    reason: str
    pid: object
    attempt: object
    timeout_budget: Mapping[str, object]
    source: str
    record_scheduler_suppressed: Callable[[str, BaseException], object]
    recoverable_exceptions: tuple[type[BaseException], ...]


def record_retry_or_fail_escalation(request: RetryOrFailEscalationRequest) -> None:
    """Invoke queue-owned retry/fail and project all produced evidence.

    Timeout owns the escalation decision and evidence boundary. Queue recovery
    still owns the retry mutation. This helper connects the two without allowing
    timeout code to invent retry behavior or silently lose retry decision
    evidence emitted by the recovery coordinator.
    """

    retry_evidence_count = request.recovery.retry_evidence_count()
    try:
        request.recovery.retry_or_fail(request.job_id, request.reason, pid=request.pid)
    except request.recoverable_exceptions as recovery_exc:
        record_timeout_recovery_failure(
            failures=request.failures,
            job_id=request.job_id,
            reason=request.reason,
            pid=request.pid,
            action="retry_or_fail_failed",
            attempt=request.attempt,
            timeout_budget=request.timeout_budget,
            error=recovery_exc,
            source=request.source,
            record_scheduler_suppressed=request.record_scheduler_suppressed,
            recoverable_exceptions=request.recoverable_exceptions,
        )
    request.failures.extend(
        request.recovery.retry_evidence_since(retry_evidence_count)
    )
    request.failures.append(
        build_timeout_retry_evidence(
            job_id=request.job_id,
            reason=request.reason,
            pid=request.pid,
            action="retry_or_fail",
            attempt=request.attempt,
            timeout_budget=request.timeout_budget,
        )
    )


__all__ = ("RetryOrFailEscalationRequest", "record_retry_or_fail_escalation")
