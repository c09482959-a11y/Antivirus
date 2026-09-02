"""Queue-owned integrity verification pipeline."""
from __future__ import annotations



from Virus_Scan.scheduler.queue.authority import _ensure_process_queue_dirs, process_queue_active_claim_is_protected, process_queue_merge_claim_meta_into_job, queue_now
from Virus_Scan.scheduler.queue.diagnostics import queue_cleanup_diagnostic_tmp_files
from Virus_Scan.scheduler.queue.identity import (
    queue_is_job_json_name as _queue_is_job_json_name,
    queue_job_identity as _queue_job_identity,
)
from Virus_Scan.scheduler.queue.integrity import (
    QueueIntegrityVerificationRequest,
    collect_jobs_by_identity,
    verify_and_repair_queue_integrity,
)
from Virus_Scan.scheduler.queue.issue_reporting import record_raw_queue_issue
from Virus_Scan.scheduler.queue.quarantine import _queue_quarantine_job
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_job_dirs as _queue_job_dirs, safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.runtime.queue_json import read_json_file as _queue_read_json_file


def queue_collect_jobs_by_identity(queue_dir: object) -> object:
    return collect_jobs_by_identity(
        queue_dir,
        job_dirs=_queue_job_dirs,
        safe_listdir=_safe_queue_listdir,
        is_job_json_name=_queue_is_job_json_name,
        read_json=_queue_read_json_file,
        job_identity=_queue_job_identity,
        merge_claim_meta=process_queue_merge_claim_meta_into_job,
        report=record_raw_queue_issue,
    )


def queue_integrity_verify_and_repair(
    queue_dir: object,
    *,
    all_files: object = None,
    phase: str = "startup",
    repair: bool = True,
    active_claim_pid_is_alive: object | None = None,
) -> object:
    return verify_and_repair_queue_integrity(
        QueueIntegrityVerificationRequest(
            queue_dir=queue_dir,
            all_files=all_files,
            phase=phase,
            repair=repair,
            ensure_dirs=_ensure_process_queue_dirs,
            cleanup_diagnostic_tmp_files=queue_cleanup_diagnostic_tmp_files,
            identity_collector=queue_collect_jobs_by_identity,
            active_claim_is_protected=lambda path, job=None, now=None: process_queue_active_claim_is_protected(
                path,
                job=job,
                now=now,
                pid_is_alive=active_claim_pid_is_alive,
            ),
            quarantine_job=_queue_quarantine_job,
            queue_now=queue_now,
            report=record_raw_queue_issue,
        )
    )


__all__ = ("queue_collect_jobs_by_identity", "queue_integrity_verify_and_repair")
