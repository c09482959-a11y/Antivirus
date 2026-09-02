"""Process-queue job finalization ownership.

Batch 2 scheduler decomposition: completed/failed job reconciliation and
accepted-result finalization are reconciliation ownership, not process-queue
engine ownership.
"""
import json

from Virus_Scan.scheduler.runtime.queue_filesystem import queue_job_dirs as _queue_job_dirs
from Virus_Scan.scheduler.runtime.queue_json import record_process_queue_failure
from Virus_Scan.scheduler.queue.identity import invalidate_identity_index as _queue_identity_index_invalidate
from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as _process_queue_record_suppressed
from Virus_Scan.scheduler.queue.claim_sidecar import _queue_safe_remove_claim_meta, _queue_cleanup_orphan_claim_meta
from Virus_Scan.scheduler.internal.scheduler_config import process_queue_env_int as _process_queue_env_int_value
from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_log_error as _process_queue_log_error
from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.queue.process_queue_finalization_decisions import (
    queue_finish_claim_path_decision,
    queue_finish_job_attempt_decision,
)
from Virus_Scan.scheduler.queue.process_queue_finalization_steps import (
    queue_finish_cleanup_after_terminal_move,
    queue_finish_move_claim_to_terminal,
    queue_finish_persist_failure_diagnostics,
)


def _queue_finish_job_attempt(job: object) -> object:
    return queue_finish_job_attempt_decision(job).as_value()


def _finish_process_queue_job(
    queue_dir: object,
    claim_path: object,
    *,
    ok: object=True,
    error_info: object=None,
    job: object=None,
    record_suppressed: object=_process_queue_record_suppressed,
    remove_claim_meta: object=_queue_safe_remove_claim_meta,
    invalidate_identity_index: object=_queue_identity_index_invalidate,
    cleanup_orphan_claim_meta: object=_queue_cleanup_orphan_claim_meta,
    process_queue_env_int: object=_process_queue_env_int_value,
    record_failure: object=record_process_queue_failure,
    log_error: object=_process_queue_log_error,
) -> object:
    claim_path_decision = queue_finish_claim_path_decision(claim_path)
    if not claim_path_decision.as_bool():
        return False
    ok_flag = ok is True
    finished = False
    _pending, _active, done, failed = _queue_job_dirs(queue_dir)
    target_dir = done if ok_flag else failed
    try:
        queue_finish_persist_failure_diagnostics(
            queue_dir=queue_dir,
            claim_path=claim_path,
            ok_flag=ok_flag,
            error_info=error_info,
            job=job,
            record_failure=record_failure,
            error_info_missing=lambda error_info: error_info is None or (type(error_info) is dict and len(error_info) == 0),
            finish_job_attempt=_queue_finish_job_attempt,
        )
        if queue_finish_move_claim_to_terminal(
            claim_path=claim_path,
            target_dir=target_dir,
            done=done,
            failed=failed,
            ok_flag=ok_flag,
            remove_claim_meta=remove_claim_meta,
            record_suppressed=record_suppressed,
        ):
            return True
        queue_finish_cleanup_after_terminal_move(
            queue_dir=queue_dir,
            claim_path=claim_path,
            remove_claim_meta=remove_claim_meta,
            invalidate_identity_index=invalidate_identity_index,
            cleanup_orphan_claim_meta=cleanup_orphan_claim_meta,
            process_queue_env_int=process_queue_env_int,
            record_suppressed=record_suppressed,
        )
        finished = True
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as e:
        record_suppressed(
            "queue_finish_failed",
            e,
            fatal=True,
            extra={
                "claim_path": scheduler_evidence_path(claim_path, field_name="queue_finish_claim_path"),
                "queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_finish_queue_dir"),
                "ok": ok_flag,
            },
        )
        log_error(
            "process queue job finalization failed for "
            + scheduler_evidence_path(claim_path, field_name="queue_finish_claim_path")
            + ": "
            + scheduler_exception_text(e)
        )
    return finished


# Process-queue feed completion is owned by scheduler.queue.authority.

__all__ = ("_finish_process_queue_job",)
