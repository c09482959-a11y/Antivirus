"""Canonical process-queue stale-claim recovery owner.

The process queue runner may decide *when* monitor recovery should be sampled,
but recovery/reclaim behavior belongs to reconciliation.  This module owns the
immutable request/dependency boundary for stale active-job recovery so execution
does not directly mutate queue ownership or raw-stage recovery state.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping, MutableMapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path, scheduler_exception_text
from Virus_Scan.scheduler.queue.orphan_recovery import OrphanReclaimRequest, _reclaim_stale_process_queue_jobs
from Virus_Scan.scheduler.queue.process_queue_stale_recovery_decisions import stale_float_value
from Virus_Scan.scheduler.queue.process_queue_stale_recovery_projection import (
    stale_bool,
    stale_optional_float,
    stale_recovered_record,
)


@dataclass(frozen=True)
class ProcessQueueStaleRecoveryRequest:
    """Immutable stale recovery request emitted by the execution monitor."""

    queue_dir: object
    progress_stall_sec: float
    per_file_timeout_sec: float
    raw_stage_progress_state: Mapping[str, tuple[int | None, float]]
    stale_sec: float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_stage_progress_state", immutable_mapping(self.raw_stage_progress_state))


@dataclass(frozen=True)
class ProcessQueueStaleRecoveryDependencies:
    """Explicit reconciliation dependencies for process-queue stale recovery."""

    raw_stage_progress_recent: Callable[..., bool]
    file_has_recent_raw_owner_progress: Callable[..., bool]
    worker_liveness_checker: Callable[..., object]
    worker_terminator: Callable[..., object]
    log_error: Callable[[str], None]
    recoverable_exceptions: tuple[type[BaseException], ...]


@dataclass(frozen=True, slots=True)
class ProcessQueueStaleRecoveryEvidence:
    """Immutable timeout/recovery evidence for stale-claim recovery failure."""

    stage: str
    queue_dir: str
    progress_stall_sec: float
    per_file_timeout_sec: float | None
    error_category: str
    error_source: str
    detail: str
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def as_record(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stage": self.stage,
                "queue_dir": self.queue_dir,
                "progress_stall_sec": stale_float_value(self.progress_stall_sec),
                "per_file_timeout_sec": stale_optional_float(self.per_file_timeout_sec),
                "error_category": self.error_category,
                "error_source": self.error_source,
                "detail": self.detail[:1000],
                "timeout_failure": True,
                "queue_recovery_failure": True,
                "final_json_must_record": stale_bool(self.final_json_must_record),
                "checkpoint_must_record": stale_bool(self.checkpoint_must_record),
                "replay_must_reproduce": stale_bool(self.replay_must_reproduce),
            }
        )


@dataclass(frozen=True)
class ProcessQueueStaleRecoveryOutput:
    """Immutable stale-recovery result snapshot."""

    recovered: Mapping[str, int]
    raw_stage_progress_state: Mapping[str, tuple[int | None, float]]
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "recovered", immutable_mapping(self.recovered))
        object.__setattr__(self, "raw_stage_progress_state", immutable_mapping(self.raw_stage_progress_state))
        object.__setattr__(self, "evidence", immutable_tuple(self.evidence))


def _stale_recovery_evidence(
    *,
    request: ProcessQueueStaleRecoveryRequest,
    stage: str,
    error: BaseException,
    source: str,
) -> Mapping[str, object]:
    evidence = ProcessQueueStaleRecoveryEvidence(
        stage=stage,
        queue_dir=scheduler_evidence_path(request.queue_dir, field_name="process_queue_stale_queue_dir"),
        progress_stall_sec=stale_float_value(request.progress_stall_sec),
        per_file_timeout_sec=request.per_file_timeout_sec,
        error_category=no_hook_type_name(error),
        error_source=source,
        detail=scheduler_exception_text(error),
    )
    return evidence.as_record()


def reconcile_process_queue_stale_recovery(
    request: ProcessQueueStaleRecoveryRequest,
    dependencies: ProcessQueueStaleRecoveryDependencies,
) -> ProcessQueueStaleRecoveryOutput:
    """Reclaim stale process-queue jobs through reconciliation ownership."""

    progress_state: MutableMapping[str, tuple[int | None, float]] = dict(request.raw_stage_progress_state)
    evidence_records: list[Mapping[str, object]] = []
    recovered: Mapping[str, int]
    try:
        recovered = _reclaim_stale_process_queue_jobs(
            OrphanReclaimRequest(
                queue_dir=request.queue_dir,
                stale_sec=request.stale_sec,
                max_retries=None,
                progress_stall_sec=request.progress_stall_sec,
                per_file_timeout_sec=request.per_file_timeout_sec,
                raw_stage_progress_recent=lambda q, quiet_sec=None: dependencies.raw_stage_progress_recent(
                    q,
                    quiet_sec=quiet_sec,
                    state=progress_state,
                ),
                file_has_recent_raw_owner_progress=dependencies.file_has_recent_raw_owner_progress,
                worker_liveness_checker=dependencies.worker_liveness_checker,
                worker_terminator=dependencies.worker_terminator,
            )
        )
    except dependencies.recoverable_exceptions as exc:
        evidence_records.append(
            _stale_recovery_evidence(
                request=request,
                stage="process_queue_stale_recovery_failed",
                error=exc,
                source="process_queue_stale_recovery.reclaim",
            )
        )
        try:
            dependencies.log_error("process queue monitor orphan recovery failed: " + scheduler_exception_text(exc))
        except dependencies.recoverable_exceptions as log_exc:
            evidence_records.append(
                _stale_recovery_evidence(
                    request=request,
                    stage="process_queue_stale_recovery_log_failed",
                    error=log_exc,
                    source="process_queue_stale_recovery.log_error",
                )
            )
        recovered = {"requeued": 0, "failed": 0, "killed": 0, "recovery_failed": 1}
    recovered_record = stale_recovered_record(recovered)
    evidence_records.extend(
        record
        for record in no_hook_sequence_items(recovered_record.get("timeout_retry_evidence"))
        if isinstance(record, Mapping)
    )
    if recovered_record.get("reclaim_failed") and not evidence_records:
        evidence_records.append(
            MappingProxyType(
                {
                    "stage": "process_queue_stale_recovery_reclaim_failed",
                    "queue_dir": scheduler_evidence_path(request.queue_dir, field_name="process_queue_stale_queue_dir"),
                    "progress_stall_sec": stale_float_value(request.progress_stall_sec),
                    "per_file_timeout_sec": stale_optional_float(request.per_file_timeout_sec),
                    "timeout_failure": True,
                    "queue_recovery_failure": True,
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_reproduce": True,
                }
            )
        )
    return ProcessQueueStaleRecoveryOutput(
        recovered=immutable_mapping(recovered_record),
        raw_stage_progress_state=immutable_mapping(dict(progress_state)),
        evidence=tuple(evidence_records),
    )


__all__ = ("ProcessQueueStaleRecoveryDependencies", "ProcessQueueStaleRecoveryEvidence", "ProcessQueueStaleRecoveryOutput", "ProcessQueueStaleRecoveryRequest", "reconcile_process_queue_stale_recovery")
