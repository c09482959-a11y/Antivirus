"""Canonical scheduler queue authority ownership.

Owns durable queue directory authority and repair before execution/replay owners
consume queue state.  This module does not execute scans, enforce timeouts, or
serialize evidence.
"""

from typing import NoReturn

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_job_dirs as _queue_job_dirs, safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace as _queue_atomic_replace
from Virus_Scan.scheduler.runtime.queue_json import read_json_file
from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as _process_queue_record_suppressed
from Virus_Scan.scheduler.queue.claim_protection import (
    process_queue_active_claim_is_protected,
    process_queue_merge_claim_meta_into_job,
    process_queue_read_claim_meta,
)
from Virus_Scan.scheduler.queue.duplicate_guard import queue_duplicate_live_guard as _queue_duplicate_live_guard_impl
from Virus_Scan.scheduler.queue.identity import (
    invalidate_identity_index,
    queue_is_job_json_name,
    queue_job_identity,
)
from Virus_Scan.scheduler.queue.file_job_predicate import process_queue_is_file_job as _process_queue_is_file_job
from Virus_Scan.scheduler.queue.raw_queue_directory import enqueue_guard, raw_queue_dirs
from Virus_Scan.scheduler.queue.identity_lock import (
    acquire_identity_lock_decision,
    queue_identity_lock_dir,
    release_identity_lock_decision,
)
from Virus_Scan.scheduler.queue.admission_guard import process_queue_enqueue_guard
from Virus_Scan.scheduler.queue.time import queue_now, queue_path_mtime_age
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text

from Virus_Scan.scheduler.queue.dirs import (
    _ensure_process_queue_dirs,
    cleanup_diagnostic_tmp_files,
    process_queue_quarantine_invalid_claim,
    process_queue_quarantine_job,
)


def _active_claim_return_failed_closed_extra(active_path: object, pending_path: object, exc: BaseException) -> dict[str, object]:
    active_path_text, active_path_reason = scheduler_path_text(active_path)
    pending_path_text, pending_path_reason = scheduler_path_text(pending_path)
    evidence = materialize_scheduler_mapping(
        immutable_mapping(
            {
                "active_returned_to_pending": False,
                "process_queue_return_active_failed_closed": True,
                "failure_reason": "return_active_claim_to_pending_failed",
                "error_type": no_hook_type_name(exc),
                "active_path_evidence": {
                    "active_path": active_path_text if active_path_reason == "" else "",
                    "active_path_available": active_path_reason == "",
                    "active_path_reason": active_path_reason,
                    "active_path_type": no_hook_type_name(active_path),
                },
                "pending_path_evidence": {
                    "pending_path": pending_path_text if pending_path_reason == "" else "",
                    "pending_path_available": pending_path_reason == "",
                    "pending_path_reason": pending_path_reason,
                    "pending_path_type": no_hook_type_name(pending_path),
                },
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_record": True,
            }
        )
    )
    if type(evidence) is dict:
        return evidence
    return {
        "active_returned_to_pending": False,
        "process_queue_return_active_failed_closed": True,
        "failure_reason": "return_active_claim_to_pending_evidence_unavailable",
    }

_QUEUE_ACTIVE_RETURN_TO_PENDING_FALSE = "queue active claim return-to-pending returned false"


def _raise_queue_active_return_to_pending_false() -> NoReturn:
    raise RuntimeError(_QUEUE_ACTIVE_RETURN_TO_PENDING_FALSE)


def return_active_claim_to_pending(active_path: object, pending_path: object, *, log_context: object, telemetry_stage: object) -> object:
    """Move a just-claimed active artifact back to pending through queue authority.

    Queue authority owns the active->pending ownership transition.  If the
    transition cannot be completed, the active artifact is quarantined so stale
    active ownership cannot be resurrected or processed twice.
    """
    active_returned = False
    try:
        if _queue_atomic_replace(active_path, pending_path, log_context=log_context):
            return True
        _raise_queue_active_return_to_pending_false()
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, ValueError) as exc:
        _process_queue_record_suppressed(
            telemetry_stage,
            exc,
            extra=_active_claim_return_failed_closed_extra(active_path, pending_path, exc),
            fatal=True,
        )
        try:
            process_queue_quarantine_job(
                active_path,
                reason=telemetry_stage,
                job={"queue_failure": True, "claim_return_failed": True},
                identity=None,
            )
        except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as qexc:
            _process_queue_record_suppressed(
                telemetry_stage + "_quarantine_failed",
                qexc,
                extra=_active_claim_return_failed_closed_extra(active_path, pending_path, qexc),
                fatal=True,
            )
        active_returned = False
    return active_returned



def queue_duplicate_live_guard(queue_dir: object, claim_path: object, job: object, *, queue_job_dirs: object=None, safe_listdir: object=None, report: object=None, read_json: object=None) -> object:
    """Fail-closed duplicate live-claim guard owned by queue authority."""
    return _queue_duplicate_live_guard_impl(
        queue_dir,
        claim_path,
        job,
        queue_job_dirs=_queue_job_dirs if queue_job_dirs is None else queue_job_dirs,
        safe_listdir=_safe_queue_listdir if safe_listdir is None else safe_listdir,
        is_job_name=queue_is_job_json_name,
        job_identity=queue_job_identity,
        read_json=read_json_file if read_json is None else read_json,
        report=_process_queue_record_suppressed if report is None else report,
    )


# Public queue directory authority contract used outside the queue subdomain.
ensure_process_queue_dirs = _ensure_process_queue_dirs

__all__ = (
    "_ensure_process_queue_dirs",
    "_process_queue_is_file_job",
    "acquire_identity_lock_decision",
    "cleanup_diagnostic_tmp_files",
    "enqueue_guard",
    "invalidate_identity_index",
    "process_queue_active_claim_is_protected",
    "process_queue_enqueue_guard",
    "process_queue_merge_claim_meta_into_job",
    "process_queue_quarantine_invalid_claim",
    "process_queue_quarantine_job",
    "process_queue_read_claim_meta",
    "queue_identity_lock_dir",
    "queue_is_job_json_name",
    "queue_job_identity",
    "queue_now",
    "queue_path_mtime_age",
    "raw_queue_dirs",
    "release_identity_lock_decision",
)
