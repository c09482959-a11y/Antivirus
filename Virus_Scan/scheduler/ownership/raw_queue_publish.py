"""Canonical raw queue publish ownership helpers."""

from dataclasses import dataclass, replace
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path
from Virus_Scan.scheduler.ownership.raw_queue_publish_boundary import (
    raw_publish_collector_name,
    raw_publish_existing_file_id,
    raw_publish_file_text,
    raw_publish_generated_file_id,
    raw_publish_job_snapshot,
    raw_publish_live_hard_cap,
    raw_publish_reason,
    raw_publish_sequence,
)
from Virus_Scan.scheduler.ownership.raw_queue_publish_locked import publish_locked_raw_stage_job
from Virus_Scan.scheduler.ownership.raw_queue_publish_identity import (
    acquire_raw_queue_identity_lock,
    release_raw_queue_identity_lock,
)
from Virus_Scan.scheduler.ownership.raw_queue_publish_result import (
    RawQueuePublishRequest,
    RawQueuePublishResult,
    raw_queue_publish_result,
    record_raw_queue_publish_failure,
)
from Virus_Scan.scheduler.queue.identity_lock import (
    IdentityLockAcquireDecision,
    IdentityLockReleaseDecision,
)


@dataclass(frozen=True)
class RawQueuePublishDependencies:
    global_raw_dirs: Callable[[object], tuple]
    global_raw_file_id: Callable[[object], str]
    raw_queue_live_count: Callable[[object], int]
    runtime_value: Callable[[str, object], object]
    runtime_int: Callable[[str, int], int]
    umige_retry_max: Callable[[str], int]
    job_identity: Callable[[Mapping[str, object], object], str]
    acquire_identity_lock_decision: Callable[[object, str], IdentityLockAcquireDecision]
    release_identity_lock_decision: Callable[[object], IdentityLockReleaseDecision]
    enqueue_guard: Callable[..., bool]
    write_json_durable: Callable[..., bool]
    identity_index_invalidate: Callable[[object], None]
    hybrid_queue_state_delta: Callable[..., object]
    safe_unlink: Callable[..., object]
    record_suppressed: Callable[[str, BaseException], object]
    recoverable_exceptions: tuple[type[BaseException], ...] = RAW_QUEUE_RECOVERABLE_EXCEPTIONS



def _safe_job_number(raw_job: Mapping[str, object], field: str, deps: RawQueuePublishDependencies, *, default: int = 0) -> int:
    parse_failed_reason = raw_publish_reason(field, "_parse_failed")
    non_finite_reason = raw_publish_reason(field, "_non_finite")
    value, reason = no_hook_exact_nonnegative_int(
        raw_job.get(field), default=default, reason=parse_failed_reason, non_finite_reason=non_finite_reason
    )
    if reason:
        deps.record_suppressed(reason, ValueError(reason))
    return value



def publish_raw_stage_job(queue_dir: object, raw_job: dict[str, object], deps: RawQueuePublishDependencies) -> RawQueuePublishResult:
    """Publish one raw-stage job and return an explicit replayable outcome."""
    pending, _active, _done, _failed, _accum, _locks = deps.global_raw_dirs(queue_dir)
    job, job_reason = raw_publish_job_snapshot(raw_job)
    if job is None:
        deps.record_suppressed(job_reason, ValueError(job_reason))
        return raw_queue_publish_result(RawQueuePublishRequest(published=False, reason=job_reason))
    pending_path, pending_reason = scheduler_filesystem_path(pending)
    if pending_reason:
        deps.record_suppressed(pending_reason, ValueError(pending_reason))
        return raw_queue_publish_result(RawQueuePublishRequest(published=False, reason=pending_reason))

    file_text, file_reason = raw_publish_file_text(job)
    if file_reason:
        deps.record_suppressed(file_reason, ValueError(file_reason))
        file_text = ""
    fid, fid_reason = raw_publish_existing_file_id(job)
    if fid_reason:
        if fid_reason != "raw_publish_file_id_missing":
            deps.record_suppressed(fid_reason, ValueError(fid_reason))
        fid, generated_reason = raw_publish_generated_file_id(deps.global_raw_file_id(file_text))
        if generated_reason:
            deps.record_suppressed(generated_reason, ValueError(generated_reason))
            fid = "raw_unknown"
    seq, seq_reason = raw_publish_sequence(job)
    if seq_reason:
        deps.record_suppressed(seq_reason, ValueError(seq_reason))
    attempt = _safe_job_number(job, "attempt", deps)
    collector = raw_publish_collector_name(job.get("collector"))
    max_retries_default = deps.runtime_int("RAW_MAX_RETRIES", deps.runtime_int("UMIGE_RAW_MAX_RETRIES", 1))
    max_retries = _safe_job_number(job, "max_retries", deps, default=max_retries_default)
    job = {**job, "job_type": "raw_stage", "file": file_text, "file_id": fid, "seq": seq, "attempt": attempt,
           "collector": collector, "max_retries": max_retries}

    live_cap_failure_reason = ""
    try:
        live_cap, cap_reason = raw_publish_live_hard_cap(deps.runtime_value("RAW_LIVE_HARD_CAP", 900))
    except deps.recoverable_exceptions as exc:
        live_cap_failure_reason = "raw_publish_live_cap_failed_closed"
        deps.record_suppressed(live_cap_failure_reason, exc)
        live_cap, cap_reason = 0, ""
    if live_cap_failure_reason:
        return raw_queue_publish_result(
            RawQueuePublishRequest(
                published=False,
                reason=live_cap_failure_reason,
                file_id=fid,
                seq=seq,
                attempt=attempt,
                collector=collector,
            )
        )
    if cap_reason:
        deps.record_suppressed(cap_reason, ValueError(cap_reason))

    live_count_failure_reason = ""
    try:
        live_count = deps.raw_queue_live_count(queue_dir)
    except deps.recoverable_exceptions as exc:
        live_count_failure_reason = "raw_publish_live_count_failed_closed"
        deps.record_suppressed(live_count_failure_reason, exc)
        live_count = 0
    if live_count_failure_reason:
        return raw_queue_publish_result(
            RawQueuePublishRequest(
                published=False,
                reason=live_count_failure_reason,
                file_id=fid,
                seq=seq,
                attempt=attempt,
                collector=collector,
            )
        )
    if live_count >= live_cap:
        reason = "raw_publish_live_cap_exhausted"
        record_raw_queue_publish_failure(deps, reason)
        return raw_queue_publish_result(
            RawQueuePublishRequest(
                published=False,
                reason=reason,
                file_id=fid,
                seq=seq,
                attempt=attempt,
                collector=collector,
            )
        )

    ident = deps.job_identity(job, None)
    lock, rejected = acquire_raw_queue_identity_lock(
        queue_dir,
        ident,
        deps,
        file_id=fid,
        seq=seq,
        attempt=attempt,
        collector=collector,
    )
    if rejected is not None:
        return rejected
    if lock is None:
        raise RuntimeError("raw_publish_identity_lock_result_missing")
    publish_result: RawQueuePublishResult | None = None
    release_succeeded = False
    try:
        publish_result = publish_locked_raw_stage_job(queue_dir, job, deps, pending_path, fid, seq, attempt, collector, ident)
    finally:
        release_succeeded = release_raw_queue_identity_lock(lock, deps)
    if publish_result is None:
        raise RuntimeError("raw_publish_result_missing")
    return publish_result if release_succeeded else replace(publish_result, release_failed=True)


__all__ = ("RawQueuePublishDependencies", "RawQueuePublishResult", "publish_raw_stage_job")
