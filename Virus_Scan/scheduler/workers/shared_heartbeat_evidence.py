"""Worker-owned evidence for shared heartbeat table access failures."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_int
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import (
    safe_worker_evidence_label,
    worker_lifecycle_exception_reason,
)


@dataclass(frozen=True, slots=True)
class WorkerSharedHeartbeatFailureEvidence:
    """Immutable evidence for shared heartbeat table access failures."""

    operation: str
    job_id: str
    generation: int | None
    reason: str

    def as_context(self) -> Mapping[str, object]:
        return {
            "worker_shared_heartbeat_failed": True,
            "worker_shared_heartbeat_operation": self.operation,
            "worker_shared_heartbeat_job_id": self.job_id,
            "worker_shared_heartbeat_generation": self.generation,
            "worker_shared_heartbeat_failure_reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class WorkerSharedHeartbeatGenerationDecision:
    generation: int | None
    reason: str
    accepted: bool

    def as_generation(self) -> int | None:
        return self.generation


def _coerce_generation_decision(generation: object) -> WorkerSharedHeartbeatGenerationDecision:
    if generation is None:
        return WorkerSharedHeartbeatGenerationDecision(None, "worker_shared_heartbeat_generation_missing", accepted=False)
    number, reason = worker_int(
        generation,
        replacement=0,
        reason="worker_shared_heartbeat_generation_rejected",
        minimum=0,
    )
    if reason:
        return WorkerSharedHeartbeatGenerationDecision(None, reason, accepted=False)
    return WorkerSharedHeartbeatGenerationDecision(number, "", accepted=True)


def _coerce_generation(generation: object) -> int | None:
    return _coerce_generation_decision(generation).as_generation()



def record_shared_heartbeat_failure(*, operation: object, job_id: object, generation: object, exc: BaseException) -> None:
    evidence = WorkerSharedHeartbeatFailureEvidence(
        operation=safe_worker_evidence_label(operation, replacement_text="heartbeat"),
        job_id=safe_worker_evidence_label(job_id, replacement_text="unknown"),
        generation=_coerce_generation(generation),
        reason=worker_lifecycle_exception_reason(exc),
    )
    try:
        record_suppressed_failure(
            str.__add__(
                "worker_shared_heartbeat_",
                str.__add__(evidence.operation, "_failed"),
            ),
            exc,
            domain="scheduler",
            context=evidence.as_context(),
        )
    except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
        _ = reporting_exc


__all__ = ("WorkerSharedHeartbeatFailureEvidence", "WorkerSharedHeartbeatGenerationDecision", "_coerce_generation_decision", "record_shared_heartbeat_failure")
