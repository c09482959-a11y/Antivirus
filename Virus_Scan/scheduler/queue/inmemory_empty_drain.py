"""In-memory queue empty-drain retry recovery ownership."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping, MutableSet

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import InMemoryRetryDecision


_EMPTY_DRAIN_RECOVERY_EXCEPTIONS = (
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
    KeyError,
    AttributeError,
)


@dataclass(frozen=True, slots=True)
class InMemoryEmptyDrainRecoveryEvidence:
    """Immutable evidence that empty-drain retry recovery failed for a missing job."""

    job_id: int
    reason: str
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def as_record(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stage": "inmemory_empty_drain_retry_recovery",
                "job_id": int(self.job_id),
                "reason": self.reason,
                "error_category": self.error_category,
                "error_source": self.error_source,
                "detail": self.detail[:1000],
                "timeout_failure": True,
                "retry_failure": True,
                "final_json_must_record": bool(self.final_json_must_record),
                "checkpoint_must_record": bool(self.checkpoint_must_record),
                "replay_must_reproduce": bool(self.replay_must_reproduce),
            }
        )


@dataclass(frozen=True, slots=True)
class InMemoryEmptyDrainRecoveryDecision:
    retried: int
    failed_now: int
    completed_delta: int
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", immutable_tuple(self.evidence))



def requeue_missing_after_empty_drain(
    *,
    total_files: int,
    terminal: MutableSet[int],
    retry_callable: Callable[[int, str], InMemoryRetryDecision],
) -> InMemoryEmptyDrainRecoveryDecision:
    try:
        total_file_count = int(total_files)
    except _EMPTY_DRAIN_RECOVERY_EXCEPTIONS as exc:
        total_file_count = 0
        evidence: tuple[Mapping[str, object], ...] = (
            InMemoryEmptyDrainRecoveryEvidence(
                job_id=-1,
                reason="missing_after_empty_drain_total_files",
                error_category=type(exc).__name__,
                error_source="inmemory_empty_drain.total_files",
                detail=str(exc),
            ).as_record(),
        )
    else:
        if total_file_count >= 0:
            evidence = ()
        else:
            evidence = (
                InMemoryEmptyDrainRecoveryEvidence(
                    job_id=-1,
                    reason="missing_after_empty_drain_total_files",
                    error_category="ValueError",
                    error_source="inmemory_empty_drain.total_files",
                    detail="total_files must be non-negative, got %d" % total_file_count,
                ).as_record(),
            )
            total_file_count = 0
    if evidence and total_file_count == 0:
        return InMemoryEmptyDrainRecoveryDecision(0, 0, 0, evidence)
    missing = tuple(i for i in range(total_file_count) if i not in terminal)
    retried = 0
    failed_now = 0
    completed_delta = 0
    evidence_records: tuple[Mapping[str, object], ...] = evidence
    for job_id in missing:
        try:
            decision = retry_callable(job_id, "missing_after_empty_drain")
        except _EMPTY_DRAIN_RECOVERY_EXCEPTIONS as exc:
            retry_delta = 0
            failed_delta = 1
            completed_job_delta = 0
            retry_evidence = (
                InMemoryEmptyDrainRecoveryEvidence(
                    job_id=int(job_id),
                    reason="missing_after_empty_drain",
                    error_category=type(exc).__name__,
                    error_source="inmemory_empty_drain.retry_callable",
                    detail=str(exc),
                ).as_record(),
            )
        else:
            if type(decision) is InMemoryRetryDecision:
                failed_delta = 0 if decision.retried or decision.completed_delta == 0 else 1
                retry_delta = 1 if decision.retried else 0
                completed_job_delta = decision.completed_delta
                retry_evidence = tuple(decision.evidence)
            else:
                retry_delta = 0
                failed_delta = 1
                completed_job_delta = 0
                retry_evidence = (
                    InMemoryEmptyDrainRecoveryEvidence(
                        job_id=int(job_id),
                        reason="missing_after_empty_drain",
                        error_category="TypeError",
                        error_source="inmemory_empty_drain.retry_callable",
                        detail="retry callable returned unsupported decision type %s"
                        % no_hook_type_name(decision),
                    ).as_record(),
                )
        retried += retry_delta
        failed_now += failed_delta
        completed_delta += completed_job_delta
        evidence_records += retry_evidence
    if missing:
        logging.warning(
            "in-memory scheduler empty-drain recovery missing=%s retried=%s failed=%s",
            len(missing),
            retried,
            failed_now,
        )
    return InMemoryEmptyDrainRecoveryDecision(
        retried,
        failed_now,
        completed_delta,
        evidence_records,
    )


__all__ = (
    "InMemoryEmptyDrainRecoveryDecision",
    "InMemoryEmptyDrainRecoveryEvidence",
    "requeue_missing_after_empty_drain",
)
