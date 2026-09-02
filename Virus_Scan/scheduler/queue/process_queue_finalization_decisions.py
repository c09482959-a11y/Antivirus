"""Replayable process-queue finalization boundary decisions."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float


@dataclass(frozen=True, slots=True)
class QueueFinishClaimPathDecision:
    """Replayable decision for accepting a process-queue claim path."""

    accepted: bool
    reason: str

    def as_bool(self) -> bool:
        return self.accepted


@dataclass(frozen=True, slots=True)
class QueueFinishAttemptDecision:
    """Replayable decision for reading an owned job attempt field."""

    value: object
    accepted: bool
    reason: str

    def as_value(self) -> object:
        return self.value


@dataclass(frozen=True, slots=True)
class IdleOptionalFloatDecision:
    """Replayable decision for optional idle timestamp float projection."""

    value: float | None
    accepted: bool
    reason: str

    def as_value(self) -> float | None:
        return self.value


def queue_finish_claim_path_decision(claim_path: object) -> QueueFinishClaimPathDecision:
    if claim_path is None:
        return QueueFinishClaimPathDecision(accepted=False, reason="queue_finish_claim_path_missing")
    if type(claim_path) is str and str.__str__(claim_path) == "":
        return QueueFinishClaimPathDecision(accepted=False, reason="queue_finish_claim_path_blank")
    return QueueFinishClaimPathDecision(accepted=True, reason="")


def queue_finish_job_attempt_decision(job: object) -> QueueFinishAttemptDecision:
    if type(job) is not dict:
        return QueueFinishAttemptDecision(None, accepted=False, reason="queue_finish_job_attempt_unavailable")
    return QueueFinishAttemptDecision(dict.get(job, "attempt"), accepted=True, reason="")


def idle_optional_float_decision(value: object, *, reason: str) -> IdleOptionalFloatDecision:
    if value is None:
        return IdleOptionalFloatDecision(None, accepted=False, reason="idle_optional_float_missing")
    parsed, parse_reason = scheduler_float(value, default=0.0, minimum=0.0, reason=reason)
    if parse_reason:
        return IdleOptionalFloatDecision(parsed, accepted=False, reason=parse_reason)
    return IdleOptionalFloatDecision(parsed, accepted=True, reason="")


__all__ = (
    "IdleOptionalFloatDecision",
    "QueueFinishAttemptDecision",
    "QueueFinishClaimPathDecision",
    "idle_optional_float_decision",
    "queue_finish_claim_path_decision",
    "queue_finish_job_attempt_decision",
)
