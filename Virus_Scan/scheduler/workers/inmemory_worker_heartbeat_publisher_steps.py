"""Bounded active-worker heartbeat publication steps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_boundary import safe_bool_result
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_publish_steps import (
    derive_heartbeat_publish_flags,
    heartbeat_timestamp_value,
    load_heartbeat_publish_inputs,
    publish_heartbeat_update,
)
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import worker_lifecycle_exception_reason


@dataclass(frozen=True, slots=True)
class WorkerHeartbeatPublishEvidence:
    """Immutable evidence for failed worker heartbeat publication."""

    job_id: str
    attempt: int
    stage: str
    reason: str
    published: bool = False

    def as_metadata(self) -> Mapping[str, object]:
        return {
            "worker_heartbeat_publish_failed": not self.published,
            "worker_heartbeat_job_id": self.job_id,
            "worker_heartbeat_attempt": self.attempt,
            "worker_heartbeat_stage": self.stage,
            "worker_heartbeat_failure_reason": self.reason,
        }


def record_heartbeat_publish_failure(
    *,
    meta: object,
    evidence: WorkerHeartbeatPublishEvidence,
    record_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Record failed heartbeat publication without treating it as a clean heartbeat."""

    if type(meta) is dict:
        meta["heartbeat_publish_failed"] = True
        meta["heartbeat_publish_evidence"] = dict(evidence.as_metadata())
    try:
        record_suppressed("worker_heartbeat_publish_failed", RuntimeError("worker heartbeat publish failed"))
    except recoverable_exceptions as exc:
        if type(meta) is dict:
            meta["heartbeat_publish_report_failed"] = worker_lifecycle_exception_reason(exc)



def _finish_heartbeat_update(
    *,
    meta_dict: dict[str, object],
    job_id: str,
    attempt: int,
    stage: str,
    input_failure: str,
    flags: object,
    heartbeat_result: object,
    now_hb: float,
    record_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> bool:
    if safe_bool_result(heartbeat_result) is False:
        record_heartbeat_publish_failure(
            meta=meta_dict,
            evidence=WorkerHeartbeatPublishEvidence(
                job_id=job_id,
                attempt=attempt,
                stage=stage,
                reason=input_failure or "shared heartbeat update returned false",
            ),
            record_suppressed=record_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        return flags.should_stop
    meta_dict["last_hb"] = heartbeat_timestamp_value(now_hb)
    meta_dict.pop("heartbeat_publish_failed", None)
    return flags.should_stop


def _record_heartbeat_publish_exception(
    *,
    meta_dict: dict[str, object] | None,
    job_id: str,
    attempt: int,
    stage: str,
    exc: BaseException,
    record_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    record_heartbeat_publish_failure(
        meta=meta_dict,
        evidence=WorkerHeartbeatPublishEvidence(
            job_id=job_id,
            attempt=attempt,
            stage=stage,
            reason="shared heartbeat publication raised " + worker_lifecycle_exception_reason(exc),
        ),
        record_suppressed=record_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )


def publish_one_active_worker_heartbeat(
    *,
    meta: object,
    cfg: dict,
    cancel_table: object,
    heartbeat_table: object,
    heartbeat_flags: object,
    completed_jobs: int,
    cancel_requested: Callable[[object, str, int], bool],
    update_shared_heartbeat: Callable[..., object],
    process_id: int,
    now_hb: float,
    default_rss_limit: float,
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
) -> bool:
    job_id = "unknown"
    attempt = 0
    stage = "scan"
    meta_dict = meta if type(meta) is dict else None
    input_failure = "worker_heartbeat_inputs_unavailable"
    try:
        inputs = load_heartbeat_publish_inputs(
            meta=meta,
            cfg=cfg,
            heartbeat_flags=heartbeat_flags,
            completed_jobs=completed_jobs,
            process_id=process_id,
            default_rss_limit=default_rss_limit,
        )
        job_id = inputs.job_id
        attempt = inputs.attempt
        stage = inputs.stage
        meta_dict = inputs.meta_dict
        input_failure = inputs.input_failure
        if meta_dict is None:
            return False
        flags = derive_heartbeat_publish_flags(
            inputs=inputs,
            cancel_table=cancel_table,
            cancel_requested=cancel_requested,
        )
        if flags.should_stop:
            meta_dict["poisoned_rss_mb"] = flags.rss_mb
        heartbeat_result = publish_heartbeat_update(
            inputs=inputs,
            flags=flags,
            heartbeat_table=heartbeat_table,
            update_shared_heartbeat=update_shared_heartbeat,
        )
        return _finish_heartbeat_update(
            meta_dict=meta_dict,
            job_id=job_id,
            attempt=attempt,
            stage=stage,
            input_failure=input_failure,
            flags=flags,
            heartbeat_result=heartbeat_result,
            now_hb=now_hb,
            record_suppressed=record_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
    except recoverable_exceptions as exc:
        _record_heartbeat_publish_exception(
            meta_dict=meta_dict,
            job_id=job_id,
            attempt=attempt,
            stage=stage,
            exc=exc,
            record_suppressed=record_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
    return False


__all__ = (
    "WorkerHeartbeatPublishEvidence",
    "publish_one_active_worker_heartbeat",
    "record_heartbeat_publish_failure",
)
