"""Locked raw queue publication writer contract."""
from __future__ import annotations

from os import PathLike
from pathlib import Path
from typing import Mapping

from Virus_Scan.scheduler.api.contracts import QueueIdentityScanError
from Virus_Scan.scheduler.ownership.raw_queue_publish_boundary import raw_publish_pending_name
from Virus_Scan.scheduler.ownership.raw_queue_publish_result import (
    RawQueuePublishRequest,
    RawQueuePublishResult,
    raw_queue_publish_result,
    record_raw_queue_publish_failure,
)



def publish_locked_raw_stage_job(
    queue_dir: object,
    job: Mapping[str, object],
    deps: object,
    pending_path: str | PathLike[str],
    fid: str,
    seq: int,
    attempt: int,
    collector: str,
    ident: str,
) -> RawQueuePublishResult:
    guard_states = ("pending", "active", "done", "failed", "quarantine")
    guard_failure_reason = ""
    try:
        guard_ok = deps.enqueue_guard(queue_dir, job, identity=ident, states=guard_states)
    except (OSError, TypeError, ValueError, RuntimeError, QueueIdentityScanError) as exc:
        guard_failure_reason = "raw_publish_enqueue_guard_failed_closed"
        deps.record_suppressed(guard_failure_reason, exc)
        guard_ok = False
    if guard_failure_reason:
        return raw_queue_publish_result(
            RawQueuePublishRequest(
                published=False,
                reason=guard_failure_reason,
                file_id=fid,
                seq=seq,
                attempt=attempt,
                collector=collector,
            )
        )
    if not guard_ok:
        reason = "raw_publish_enqueue_guard_rejected"
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

    name = raw_publish_pending_name(fid, seq, attempt, collector)
    tmp = Path(pending_path) / (name + ".tmp")
    final = Path(pending_path) / name
    write_failure_reason = ""
    try:
        write_ok = deps.write_json_durable(tmp, final, job, log_context="raw_publish_tmp_to_pending")
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        write_failure_reason = "raw_publish_write_failed_closed"
        deps.record_suppressed(write_failure_reason, exc)
        try:
            deps.safe_unlink(Path.__str__(tmp), log_context="raw_publish_tmp_cleanup")
        except OSError as cleanup_exc:
            deps.record_suppressed("raw_publish_tmp_cleanup_failed", cleanup_exc)
        write_ok = False
    if write_failure_reason:
        return raw_queue_publish_result(
            RawQueuePublishRequest(
                published=False,
                reason=write_failure_reason,
                pending_name=name,
                file_id=fid,
                seq=seq,
                attempt=attempt,
                collector=collector,
            )
        )
    if not write_ok:
        reason = "raw_publish_write_returned_false"
        record_raw_queue_publish_failure(deps, reason)
        return raw_queue_publish_result(
            RawQueuePublishRequest(
                published=False,
                reason=reason,
                pending_name=name,
                file_id=fid,
                seq=seq,
                attempt=attempt,
                collector=collector,
            )
        )
    try:
        deps.identity_index_invalidate(queue_dir)
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        deps.record_suppressed("raw_publish_identity_index_invalidate_failed", exc)
    try:
        deps.hybrid_queue_state_delta(queue_dir, raw_pending=1)
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        deps.record_suppressed("raw_publish_hybrid_state_delta_failed", exc)
    return raw_queue_publish_result(
        RawQueuePublishRequest(
            published=True,
            reason="raw_publish_published",
            pending_name=name,
            file_id=fid,
            seq=seq,
            attempt=attempt,
            collector=collector,
        )
    )


__all__ = ("publish_locked_raw_stage_job",)
