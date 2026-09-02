"""Process-queue directory and diagnostic cleanup ownership."""

from pathlib import Path


from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_job_dirs as _queue_job_dirs
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace as _queue_atomic_replace
from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as _process_queue_record_suppressed
from Virus_Scan.scheduler.internal.scheduler_config import process_queue_env_int as _process_queue_env_int_value
from Virus_Scan.scheduler.runtime.queue_json import queue_write_json_replace, make_json_safe
from Virus_Scan.scheduler.queue.claim_sidecar import _queue_cleanup_orphan_claim_meta, _queue_safe_remove_claim_meta
from Virus_Scan.scheduler.queue.dirs_support import (
    QUEUE_DIRS_FAILED,
    QUEUE_QUARANTINE_FAILED,
    cleanup_diagnostic_tmp_files as _cleanup_diagnostic_tmp_files_impl,
    negative_count,
    queue_reason_text,
)
from Virus_Scan.scheduler.queue.raw_queue_path_support import materialize_raw_queue_path

_QUEUE_QUARANTINE_RETURNED_FALSE = "queue quarantine returned false"


def cleanup_diagnostic_tmp_files(queue_dir: object, max_age_sec: float = 60.0, *, record_suppressed: object) -> int:
    """Remove stale process-queue diagnostic temporary files through queue authority.

    Ownership token: process_queue_diagnostic_tmp_cleanup.
    """
    return _cleanup_diagnostic_tmp_files_impl(queue_dir, max_age_sec=max_age_sec, record_suppressed=record_suppressed)


def process_queue_quarantine_job(path: object, *, reason: str = "process_queue_quarantine", job: object = None, identity: object = None) -> bool:
    """Move or materialize a process-queue artifact into quarantine through queue authority.

    Quarantine is a durable queue-state transition, not reconciliation policy.
    Reconciliation may decide that quarantine is required, but queue authority
    owns the filesystem mutation and fail-closed diagnostics.
    """
    try:
        p = materialize_raw_queue_path(path, reason="process_queue_quarantine_path_rejected")
        reason_text, _reason_issue = queue_reason_text(
            reason,
            missing_reason="process_queue_quarantine_reason_missing",
            unsupported_reason="process_queue_quarantine_reason_rejected",
            empty_reason="process_queue_quarantine_reason_empty",
        )
        qdir = p.parent.parent / "quarantine"
        qdir.mkdir(parents=True, exist_ok=True)
        dest = qdir / (p.name + ".quarantine")
        if p.exists():
            return _queue_atomic_replace(p, dest, log_context=reason_text) is True
        if type(job) is dict:
            return queue_write_json_replace(
                dest,
                {"queue_failure": True, "reason": reason_text, "job": make_json_safe(job), "identity": identity},
                tmp_suffix=".tmp",
                verify=True,
                log_context=reason_text,
            ) is True
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        reason_text, _reason_issue = queue_reason_text(
            reason,
            missing_reason="process_queue_quarantine_reason_missing",
            unsupported_reason="process_queue_quarantine_reason_rejected",
            empty_reason="process_queue_quarantine_reason_empty",
        )
        _process_queue_record_suppressed(
            "process_queue_quarantine_failed",
            exc,
            extra={"path": scheduler_evidence_path(path, field_name="path"), "reason": reason_text},
        )
    return QUEUE_QUARANTINE_FAILED


def process_queue_quarantine_invalid_claim(path: object, *, reason: object, job: object, identity: object=None) -> object:
    """Quarantine invalid claimed process-queue work through queue authority.

    Claiming code decides that an artifact cannot be executed; queue authority
    owns the durable active/pending/quarantine transition and claim-sidecar
    cleanup needed to prevent stale worker ownership leakage.  This helper does
    not execute scans, enforce timeout policy, or serialize scheduler evidence.
    """
    try:
        p = materialize_raw_queue_path(path, reason="process_queue_claim_quarantine_path_rejected")
        reason_text, _reason_issue = queue_reason_text(
            reason,
            missing_reason="process_queue_claim_quarantine_reason_missing",
            unsupported_reason="process_queue_claim_quarantine_reason_rejected",
            empty_reason="process_queue_claim_quarantine_reason_empty",
        )
        if process_queue_quarantine_job(p, reason=reason_text, job=job, identity=identity):
            return True
        if p.parent.name == "active":
            try:
                _queue_safe_remove_claim_meta(p)
            except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as meta_exc:
                _process_queue_record_suppressed(
                    "process_queue_claim_quarantine_meta_cleanup_failed",
                    meta_exc,
                    extra={"path": scheduler_evidence_path(p, field_name="path"), "reason": reason_text},
                    fatal=True,
                )
            if process_queue_quarantine_job(p, reason=reason_text, job=job, identity=identity):
                return True
        if p.exists():
            qdir = p.parent.parent / "quarantine"
            qdir.mkdir(parents=True, exist_ok=True)
            dest = qdir / (p.parent.name + "__" + p.name)
            n = 1
            while dest.exists():
                dest = qdir / (p.parent.name + "__" + p.stem + "__pq%03d.json" % n)
                n += 1
            if _queue_atomic_replace(p, dest, log_context=reason_text):
                try:
                    _queue_safe_remove_claim_meta(p)
                except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as meta_exc:
                    _process_queue_record_suppressed(
                        "process_queue_claim_quarantine_post_meta_cleanup_failed",
                        meta_exc,
                        extra={"path": scheduler_evidence_path(p, field_name="path"), "reason": reason_text},
                        fatal=False,
                    )
                return True
        raise RuntimeError(_QUEUE_QUARANTINE_RETURNED_FALSE)
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as exc:
        _process_queue_record_suppressed(
            "process_queue_claim_quarantine_failed",
            exc,
            extra={
                "path": scheduler_evidence_path(path, field_name="path"),
                "reason": queue_reason_text(
                    reason,
                    missing_reason="process_queue_claim_quarantine_reason_missing",
                    unsupported_reason="process_queue_claim_quarantine_reason_rejected",
                    empty_reason="process_queue_claim_quarantine_reason_empty",
                )[0],
            },
            fatal=True,
        )
        return QUEUE_QUARANTINE_FAILED




def _ensure_process_queue_dirs(
    queue_dir: object,
    *,
    diagnostic_cleanup: object=cleanup_diagnostic_tmp_files,
    record_suppressed: object=_process_queue_record_suppressed,
    orphan_cleanup: object=_queue_cleanup_orphan_claim_meta,
    process_queue_env_int: object=_process_queue_env_int_value,
) -> object:
    """Create and repair process-queue authority directories deterministically."""
    try:
        pending, active, done, failed = _queue_job_dirs(queue_dir)
        for d in (pending, active, done, failed):
            try:
                Path(d).mkdir(parents=True, exist_ok=True)
            except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as exc:
                record_suppressed(
                    "queue_ensure_dir_create_failed",
                    exc,
                    fatal=True,
                    extra={
                        "dir": scheduler_evidence_path(d, field_name="dir"),
                        "queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_dir"),
                    },
                )
                return QUEUE_DIRS_FAILED
        diag_cleanup = diagnostic_cleanup(queue_dir, max_age_sec=60.0, record_suppressed=record_suppressed)
        if negative_count(diag_cleanup):
            record_suppressed(
                "queue_ensure_dirs_diagnostic_cleanup_incomplete",
                RuntimeError("diagnostic tmp cleanup failed"),
                extra={"queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_dir")},
            )
        orphan_removed = orphan_cleanup(active, max_remove=process_queue_env_int("UMIGE_QUEUE_ORPHAN_CLAIM_CLEAN_MAX", 8192, minimum=0, record_suppressed=record_suppressed))
        if negative_count(orphan_removed):
            record_suppressed(
                "queue_ensure_dirs_orphan_claim_cleanup_failed",
                RuntimeError("orphan claim cleanup failed"),
                extra={
                    "queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_dir"),
                    "active_dir": scheduler_evidence_path(active, field_name="active_dir"),
                },
            )
        return True
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        record_suppressed("queue_ensure_dirs_failed", exc, fatal=True, extra={"queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_dir")})
        return QUEUE_DIRS_FAILED



__all__ = ("_ensure_process_queue_dirs", "cleanup_diagnostic_tmp_files", "process_queue_quarantine_invalid_claim", "process_queue_quarantine_job")
