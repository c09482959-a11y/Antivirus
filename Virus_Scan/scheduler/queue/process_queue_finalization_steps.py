"""Bounded process-queue finalization side-effect steps."""
from __future__ import annotations

from pathlib import Path
import os
import time

from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace

_FAILURE_INFO_PERSISTENCE_VERIFICATION_FAILED = "queue failure_info persistence verification failed"
_FINALIZATION_MOVE_BUSY_OR_FAILED = "queue finalization move busy/failed; leaving claim for retry"


def queue_finish_missing_failure_info(*, job: object, finish_job_attempt: object) -> dict[str, object]:
    """Build explicit failure_info for a failed finalization with no diagnostics."""

    return {
        "stage": "queue_finalize_without_success",
        "exception_type": "UnknownQueueFinalizationFailure",
        "error": "queue job finalized as failed without an exception; treating as infrastructure failure",
        "worker_pid": int(os.getpid()),
        "attempt": finish_job_attempt(job),
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def queue_finish_persist_failure_diagnostics(
    *,
    queue_dir: object,
    claim_path: object,
    ok_flag: bool,
    error_info: object,
    job: object,
    record_failure: object,
    error_info_missing: object,
    finish_job_attempt: object,
) -> object:
    """Persist required failure diagnostics before moving a terminal queue claim."""

    if (not ok_flag) and error_info_missing(error_info):
        error_info = queue_finish_missing_failure_info(job=job, finish_job_attempt=finish_job_attempt)
    if not ok_flag:
        if record_failure(queue_dir, claim_path, job=job, error_info=error_info) is not True:
            raise RuntimeError(_FAILURE_INFO_PERSISTENCE_VERIFICATION_FAILED)
    elif not error_info_missing(error_info):
        record_failure(queue_dir, claim_path, job=job, error_info=error_info)
    return error_info


def queue_finish_claim_already_terminal(
    *,
    claim_path: object,
    target_dir: Path,
    done: Path,
    failed: Path,
    ok_flag: bool,
    record_suppressed: object,
) -> bool:
    """Return whether a previously moved claim is already in a terminal directory."""

    try:
        claim_p = Path(claim_path)
        terminal = target_dir / claim_p.name
        opposite = (failed if ok_flag else done) / claim_p.name
        return claim_p.exists() is False and (terminal.exists() is True or opposite.exists() is True)
    except (OSError, RuntimeError, ValueError) as exc:
        record_suppressed(
            "queue_finish_terminal_idempotency_check_failed",
            exc,
            extra={
                "claim_path": scheduler_evidence_path(claim_path, field_name="queue_finish_claim_path"),
                "ok": ok_flag,
            },
        )
    return False


def queue_finish_remove_claim_meta_before_move(
    *,
    claim_path: object,
    target_dir: Path,
    remove_claim_meta: object,
    record_suppressed: object,
) -> None:
    """Remove stale claim sidecar state before a terminal move without failing the move."""

    try:
        remove_claim_meta(claim_path)
    except (OSError, RuntimeError, ValueError) as suppressed_exc:
        record_suppressed(
            "queue_finish_pre_move_claim_meta_cleanup_failed",
            suppressed_exc,
            extra={
                "claim_path": scheduler_evidence_path(claim_path, field_name="queue_finish_claim_path"),
                "target_dir": scheduler_evidence_path(target_dir, field_name="queue_finish_target_dir"),
            },
        )


def queue_finish_move_claim_to_terminal(
    *,
    claim_path: object,
    target_dir: Path,
    done: Path,
    failed: Path,
    ok_flag: bool,
    remove_claim_meta: object,
    record_suppressed: object,
) -> bool:
    """Move a claim to its terminal directory and report whether it was already moved."""

    target_dir.mkdir(parents=True, exist_ok=True)
    if queue_finish_claim_already_terminal(
        claim_path=claim_path,
        target_dir=target_dir,
        done=done,
        failed=failed,
        ok_flag=ok_flag,
        record_suppressed=record_suppressed,
    ):
        return True
    queue_finish_remove_claim_meta_before_move(
        claim_path=claim_path,
        target_dir=target_dir,
        remove_claim_meta=remove_claim_meta,
        record_suppressed=record_suppressed,
    )
    if queue_atomic_replace(claim_path, target_dir / Path(claim_path).name, log_context="queue_finish_move") is not True:
        raise RuntimeError(_FINALIZATION_MOVE_BUSY_OR_FAILED)
    return False


def queue_finish_cleanup_after_terminal_move(
    *,
    queue_dir: object,
    claim_path: object,
    remove_claim_meta: object,
    invalidate_identity_index: object,
    cleanup_orphan_claim_meta: object,
    process_queue_env_int: object,
    record_suppressed: object,
) -> None:
    """Clean sidecar/index residue after a successful terminal claim move."""

    try:
        remove_claim_meta(claim_path)
        invalidate_identity_index(queue_dir)
    except (OSError, RuntimeError, ValueError) as suppressed_exc:
        record_suppressed(
            "queue_finish_post_move_claim_meta_or_index_cleanup_failed",
            suppressed_exc,
            extra={
                "claim_path": scheduler_evidence_path(claim_path, field_name="queue_finish_claim_path"),
                "queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_finish_queue_dir"),
            },
        )
    try:
        cleanup_orphan_claim_meta(
            Path(claim_path).parent,
            max_remove=process_queue_env_int(
                "UMIGE_QUEUE_ORPHAN_CLAIM_CLEAN_MAX",
                8192,
                minimum=0,
                record_suppressed=record_suppressed,
            ),
        )
    except (OSError, RuntimeError, ValueError) as suppressed_exc:
        record_suppressed(
            "queue_finish_orphan_claim_cleanup_failed",
            suppressed_exc,
            extra={
                "claim_path": scheduler_evidence_path(claim_path, field_name="queue_finish_claim_path"),
                "queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_finish_queue_dir"),
            },
        )


__all__ = (
    "queue_finish_cleanup_after_terminal_move",
    "queue_finish_move_claim_to_terminal",
    "queue_finish_persist_failure_diagnostics",
)
