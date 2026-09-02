"""Canonical queue identity derivation ownership.

Owns deterministic queue job identity strings and queue-job filename
classification. It does not own queue directory mutation, filesystem locks,
claim transitions, scan execution, timeout policy, or evidence serialization.
"""
from __future__ import annotations

from typing import NoReturn

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.scheduler.evidence.process_queue_errors import (
    process_queue_record_suppressed as _process_queue_record_suppressed,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path
from Virus_Scan.scheduler.queue.identity_decisions import (
    IdentityIndexInvalidationDecision,
    QueueJobNameDecision,
)
from Virus_Scan.scheduler.queue.identity_snapshot import QueueJobIdentitySnapshot
from Virus_Scan.scheduler.queue.identity_index import invalidate_queue as _invalidate_queue_identity_index
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_file_identity_for_path


def _record_process_queue_identity_issue(where: str, exc: BaseException, *, extra: dict[str, object] | None = None) -> bool:
    stage, stage_reason = no_hook_text(
        where,
        missing_reason="process_queue_identity_stage_missing",
        unsupported_reason="process_queue_identity_stage_rejected",
    )
    if stage_reason or stage == "":
        stage = "process_queue_identity"
    payload = {"process_queue_stage": stage}
    extra_items = no_hook_mapping_items(extra)
    if extra_items is not None:
        payload.update(dict(extra_items))
    return _process_queue_record_suppressed(stage, exc, extra=payload)


def _raise_process_queue_identity_name_parse_failed(reason: str) -> NoReturn:
    raise ValueError(reason)


def queue_is_job_json_name_decision(name: object) -> QueueJobNameDecision:
    n, reason = no_hook_text(
        name,
        missing_reason="process_queue_identity_name_missing",
        unsupported_reason="process_queue_identity_name_rejected",
    )
    source_type = no_hook_type_name(name)
    if reason:
        try:
            _raise_process_queue_identity_name_parse_failed(reason)
        except ValueError as exc:
            _record_process_queue_identity_issue(
                "process_queue_identity_name_parse_failed",
                exc,
                extra={"source_type": source_type, "reason": reason},
            )
        return QueueJobNameDecision(accepted=False, normalized_name=n, reason=reason, source_type=source_type)
    if not n.endswith(".json"):
        return QueueJobNameDecision(accepted=False, normalized_name=n, reason="not_json_queue_job_name", source_type=source_type)
    if n.endswith(
        (
            ".tmp",
            ".failure.tmp",
            ".claim.tmp",
            ".reclaim.tmp",
            ".quarantine.tmp",
            ".repair.tmp",
            ".qmeta.json",
        )
    ):
        return QueueJobNameDecision(accepted=False, normalized_name=n, reason="reserved_queue_sidecar_name", source_type=source_type)
    if ".tmp" in n or ".qmeta" in n or ".claim" in n:
        return QueueJobNameDecision(accepted=False, normalized_name=n, reason="embedded_queue_sidecar_marker", source_type=source_type)
    return QueueJobNameDecision(accepted=True, normalized_name=n, reason="accepted_queue_job_json_name", source_type=source_type)


def queue_is_job_json_name(name: object) -> bool:
    return queue_is_job_json_name_decision(name).accepted



def queue_job_identity(job: object, source_name: object = None) -> str:
    items = no_hook_mapping_items(job)
    if items is None:
        _record_process_queue_identity_issue(
            "process_queue_identity_source_parse_failed",
            ValueError("process_queue_identity_job_mapping_rejected"),
            extra={"job_type": no_hook_type_name(job)},
        )
    snapshot = QueueJobIdentitySnapshot.from_job(job, source_name)
    for reason in snapshot.rejections:
        _record_process_queue_identity_issue(
            "process_queue_identity_source_parse_failed",
            ValueError(reason),
            extra={"reason": reason},
        )
    if snapshot.queue_file_id:
        return snapshot.queue_file_id
    if snapshot.job_type == "raw_stage" or snapshot.file_id or snapshot.collector:
        if not snapshot.file_id or not snapshot.collector or snapshot.seq == "":
            return "raw_incomplete:%s:%s:%s:%s" % (
                snapshot.file_id,
                snapshot.collector,
                snapshot.seq,
                snapshot.source_name,
            )
        return "raw:%s:%s:%s:%s" % (
            snapshot.file_id,
            snapshot.collector,
            snapshot.seq,
            snapshot.attempt,
        )
    if snapshot.file:
        try:
            return "file:" + queue_file_identity_for_path(snapshot.file)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            _record_process_queue_identity_issue(
                "process_queue_identity_file_digest_failed",
                exc,
                extra={"source_name": snapshot.source_name},
            )
    if snapshot.source_name != "unknown":
        return "invalid:" + snapshot.source_name
    return "invalid:process_queue_identity_missing"


def invalidate_identity_index_decision(queue_dir: object = None) -> IdentityIndexInvalidationDecision:
    """Invalidate queue-owned identity index files and return replayable state."""
    queue_dir_type = no_hook_type_name(queue_dir)
    if queue_dir is None or (type(queue_dir) is str and queue_dir == ""):
        return IdentityIndexInvalidationDecision(succeeded=True, reason="identity_index_invalidation_not_required", queue_dir_type=queue_dir_type)
    safe_queue_dir, reason = scheduler_filesystem_path(queue_dir)
    if reason:
        _record_process_queue_identity_issue(
            "process_queue_identity_index_invalidate_failed",
            ValueError(reason),
            extra={
                "queue_dir_type": queue_dir_type,
                "reason": reason,
            },
        )
        return IdentityIndexInvalidationDecision(succeeded=False, reason=reason, queue_dir_type=queue_dir_type)
    _invalidate_queue_identity_index(safe_queue_dir)
    return IdentityIndexInvalidationDecision(succeeded=True, reason="identity_index_invalidated", queue_dir_type=queue_dir_type)


def invalidate_identity_index(queue_dir: object = None) -> bool:
    """Invalidate queue-owned identity index files for a queue directory.

    Queue identity ownership lives in this domain.  Callers receive an immutable
    success/failure signal while the durable index mutation is delegated to the
    queue identity index owner.
    """
    return invalidate_identity_index_decision(queue_dir).succeeded


__all__ = (
    "IdentityIndexInvalidationDecision",
    "QueueJobIdentitySnapshot",
    "QueueJobNameDecision",
    "invalidate_identity_index",
    "invalidate_identity_index_decision",
    "queue_is_job_json_name",
    "queue_is_job_json_name_decision",
    "queue_job_identity",
)
