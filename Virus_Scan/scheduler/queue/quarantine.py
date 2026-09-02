"""Queue-owned quarantine transitions for process queue artifacts."""
from __future__ import annotations



from Virus_Scan.scheduler.runtime.queue_json import read_json_file as _queue_read_json_file, queue_write_quarantine_sidecar
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_claim_meta_path as _queue_claim_meta_path, queue_safe_unlink as _queue_safe_unlink
from Virus_Scan.scheduler.queue.authority import process_queue_active_claim_is_protected, queue_now
from Virus_Scan.scheduler.queue.claim_meta import remove_claim_meta
from Virus_Scan.scheduler.queue.raw_queue_cleanup import cleanup_orphan_claim_meta
from Virus_Scan.scheduler.queue.raw_queue_quarantine import (
    cleanup_orphan_claim_sidecars,
    quarantine_destination,
    quarantine_dir,
    quarantine_job_decision,
    quarantine_sidecar_payload,
    remove_claim_sidecar_for_terminal_move,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.queue.identity import queue_job_identity as _queue_job_identity
from Virus_Scan.scheduler.queue.issue_reporting import record_raw_queue_issue, _stage113_record_process_queue_suppressed


def _queue_safe_remove_claim_meta(claim_path: object) -> object:
    return remove_claim_meta(
        claim_path,
        claim_meta_path=_queue_claim_meta_path,
        safe_unlink=_queue_safe_unlink,
        report=_stage113_record_process_queue_suppressed,
    )


def _queue_quarantine_job(
    path: object,
    reason: str = "duplicate_queue_job",
    job: object = None,
    identity: object = None,
    *,
    active_claim_pid_is_alive: object | None = None,
) -> object:
    return quarantine_job_decision(
        path,
        reason=reason,
        job=job,
        identity=identity,
        active_claim_is_protected=lambda claim_path, job=None: process_queue_active_claim_is_protected(
            claim_path,
            job=job,
            pid_is_alive=active_claim_pid_is_alive,
        ),
        quarantine_dir=lambda queue_dir: quarantine_dir(queue_dir, report=record_raw_queue_issue),
        read_json_file=_queue_read_json_file,
        job_identity=_queue_job_identity,
        quarantine_destination=quarantine_destination,
        remove_claim_sidecar_for_terminal_move=remove_claim_sidecar_for_terminal_move,
        remove_claim_meta=_queue_safe_remove_claim_meta,
        cleanup_orphan_claim_sidecars=cleanup_orphan_claim_sidecars,
        cleanup_orphans=lambda active_dir, max_remove=512: cleanup_orphan_claim_meta(
            active_dir,
            safe_listdir=_safe_queue_listdir,
            safe_unlink=_queue_safe_unlink,
            queue_now=queue_now,
            report=record_raw_queue_issue,
            max_remove=max_remove,
            min_age_sec=0.0,
        ),
        orphan_cleanup_max=512,
        write_quarantine_sidecar=queue_write_quarantine_sidecar,
        quarantine_sidecar_payload=quarantine_sidecar_payload,
        report=record_raw_queue_issue,
        report_issue=record_raw_queue_issue,
        log_error=lambda msg: record_raw_queue_issue("queue_quarantine_log", RuntimeError(str(msg))),
    ).quarantined


__all__ = ("_queue_safe_remove_claim_meta", "_queue_quarantine_job")
