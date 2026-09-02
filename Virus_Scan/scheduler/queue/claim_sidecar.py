"""Process-queue claim sidecar and orphan cleanup ownership.

Owns process-queue claim sidecar publication and cleanup helpers.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_filesystem_path,
)
from Virus_Scan.scheduler.runtime.queue_json import queue_write_json_replace, make_json_safe
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_safe_unlink as _queue_safe_unlink
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_claim_meta_path as _queue_claim_meta_path, safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.queue.identity import queue_job_identity as _queue_job_identity
from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.evidence.process_queue_errors import (
    process_queue_record_suppressed as _process_queue_record_suppressed,
    record_scheduler_suppressed,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names
from Virus_Scan.scheduler.queue.claim_sidecar_support import (
    CLAIM_SIDECAR_FAILED,
    ORPHAN_CLAIM_CLEANUP_FAILED,
    ORPHAN_CLAIM_CLEANUP_NOT_APPLICABLE,
    queue_claim_meta_cleanup_failed,
    queue_claim_sidecar_write_failed,
    queue_orphan_cleanup_limit,
)
from Virus_Scan.scheduler.queue.text_reason_support import queue_text_or_empty_reason


def _queue_claim_sidecar_from_job(dst: object, job: object, **kwargs: object) -> object:
    """Write deterministic claim sidecar for process queue ownership.

    A true return means the active claim is protected by a readable .claim
    record; failures return False so claim callers can move the job back to
    pending or quarantine it.
    """
    safe_dst, path_reason = scheduler_filesystem_path(dst)
    if path_reason:
        record_scheduler_suppressed(
            "process_queue_claim_sidecar_path_rejected",
            ValueError(path_reason),
            extra={
                "claim_path_type": no_hook_type_name(dst),
                "reason": path_reason,
            },
            fatal=True,
        )
        return CLAIM_SIDECAR_FAILED
    job_items = no_hook_mapping_items(job)
    job_data = dict(job_items) if job_items is not None else {}
    worker_id, worker_reason = queue_text_or_empty_reason(
        dict.get(kwargs, "worker_id"),
        missing_reason="queue_claim_worker_id_missing",
        unsupported_reason="queue_claim_worker_id_rejected",
        empty_reason="queue_claim_worker_id_empty",
    )
    progress_marker, progress_reason = queue_text_or_empty_reason(
        dict.get(kwargs, "progress_marker"),
        missing_reason="queue_claim_progress_marker_missing",
        unsupported_reason="queue_claim_progress_marker_rejected",
        empty_reason="queue_claim_progress_marker_empty",
    )
    try:
        p = Path(safe_dst)
        claim = (
            Path(str.__str__(safe_dst) + ".claim")
            if type(safe_dst) is str
            else p.with_name(p.name + ".claim")
        )
        payload = {
            "claim_path": scheduler_evidence_path(p, field_name="claim_path"),
            "worker_id": worker_id,
            "progress_marker": progress_marker,
            "pid": os.getpid(),
            "time": time.time(),
            "job_type": dict.get(job_data, "job_type"),
            "queue_file_id": _queue_job_identity(job, p.name),
        }
        if worker_reason or progress_reason:
            payload["claim_context_rejections"] = tuple(
                reason for reason in (worker_reason, progress_reason) if reason
            )
        return queue_write_json_replace(
            claim,
            make_json_safe(payload),
            tmp_suffix=".claim.tmp",
            verify=True,
            log_context="process_queue_claim_sidecar_write",
        ) is True
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as exc:
        return queue_claim_sidecar_write_failed(dst, exc)


def _queue_safe_remove_claim_meta(claim_path: object) -> object:
    """Process-queue owned claim sidecar cleanup.

    Stage125: finalization depends on process-queue owned claim metadata cleanup.
    for sidecar cleanup.  Missing cleanup helpers previously converted some
    terminal moves into generic finalization failures.
    """
    try:
        return _queue_safe_unlink(_queue_claim_meta_path(claim_path), log_context="process_queue_claim_meta_cleanup")
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return queue_claim_meta_cleanup_failed(claim_path, exc)


def _queue_cleanup_orphan_claim_meta(active_dir: object, *, max_remove: object=8192) -> object:
    """Remove orphan .claim files from an active queue directory deterministically.

    The process queue engine owns terminal cleanup through a local,
    typed cleanup path inside process-queue ownership.
    """
    removed = 0
    remove_limit, limit_reason = queue_orphan_cleanup_limit(max_remove)
    if limit_reason:
        _process_queue_record_suppressed(
            "queue_orphan_claim_cleanup_limit_rejected",
            ValueError(limit_reason),
            extra={"limit_type": no_hook_type_name(max_remove)},
            fatal=True,
        )
        return ORPHAN_CLAIM_CLEANUP_FAILED
    safe_active_dir, active_dir_reason = scheduler_filesystem_path(active_dir)
    if active_dir_reason:
        _process_queue_record_suppressed(
            "queue_orphan_claim_active_dir_rejected",
            ValueError(active_dir_reason),
            extra={"active_dir_type": no_hook_type_name(active_dir)},
            fatal=True,
        )
        return ORPHAN_CLAIM_CLEANUP_FAILED
    active_path = Path(safe_active_dir)
    try:
        names = sorted(
            queue_listdir_names(
                _safe_queue_listdir(active_path),
                context=active_path,
            ),
            key=str.__str__,
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        _process_queue_record_suppressed(
            "queue_orphan_claim_list_missing",
            exc,
            extra={"active_dir": scheduler_evidence_path(active_path, field_name="active_dir")},
        )
        return ORPHAN_CLAIM_CLEANUP_NOT_APPLICABLE
    except (OSError, RuntimeError, ValueError) as exc:
        _process_queue_record_suppressed(
            "queue_orphan_claim_list_failed",
            exc,
            extra={"active_dir_type": no_hook_type_name(active_dir)},
        )
        return ORPHAN_CLAIM_CLEANUP_FAILED
    for name in names:
        if removed >= remove_limit:
            break
        name_text, name_reason = queue_text_or_empty_reason(
            name,
            missing_reason="queue_orphan_claim_name_missing",
            unsupported_reason="queue_orphan_claim_name_rejected",
            empty_reason="queue_orphan_claim_name_empty",
        )
        if name_reason or not name_text.endswith(".claim"):
            continue
        claim = active_path / name_text
        base = claim.with_name(name_text[:-6])
        try:
            if base.exists():
                continue
            if _queue_safe_unlink(claim, log_context="process_queue_orphan_claim_cleanup"):
                removed += 1
        except (OSError, RuntimeError, ValueError) as exc:
            _process_queue_record_suppressed(
                "queue_orphan_claim_cleanup_failed",
                exc,
                extra={
                    "claim_meta": scheduler_evidence_path(claim, field_name="claim_meta"),
                    "base_claim": scheduler_evidence_path(base, field_name="base_claim"),
                },
            )
    return removed
