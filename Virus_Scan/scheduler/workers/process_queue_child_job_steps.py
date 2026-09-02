"""Bounded process-queue child job execution steps."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_error_detail, scheduler_path_text
from Virus_Scan.scheduler.workers.process_queue_child_result_commit import (
    ProcessQueueChildResultCommitRequest,
    commit_process_queue_child_result,
)
from Virus_Scan.scheduler.workers.process_queue_child_failure_contracts import (
    ChildWorkerFailureResultRequest,
)
from Virus_Scan.scheduler.workers.process_queue_child_failure import (
    attach_child_worker_metadata,
    build_child_failure_result,
    record_child_worker_failure_result,
    scheduler_failure_reporter,
)
from Virus_Scan.scheduler.workers.result_contracts import (
    make_scheduler_worker_error_result,
    normalize_scheduler_worker_result,
)


_USE_SIGNAL_TIMEOUT = True


@dataclass(frozen=True)
class ProcessQueueChildJobStepResult:
    """Immutable evidence from one child-job body execution."""

    done_count: int
    ok: bool
    failure_info: dict[str, object] | None = None




def run_process_queue_child_job_body(
    request: object,
    *,
    job: object,
    done_count: int,
) -> ProcessQueueChildJobStepResult:
    """Run the raw-stage or file-worker child job body."""

    if job.get("job_type") == "raw_stage":
        try:
            raw_result = request.execute_raw_stage_job(job)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            raw_result = {
                "ok": False,
                "error": scheduler_error_detail(exc),
                "infra_error": True,
                "collector": job.get("collector"),
                "file_id": job.get("file_id"),
                "seq": job.get("seq"),
                "attempt": job.get("attempt", 0),
                "failure_info": {"error": scheduler_error_detail(exc)},
            }
        request.append_raw_stage_result(job, raw_result)
        return ProcessQueueChildJobStepResult(done_count=done_count, ok=True)
    file_path, file_path_reason = scheduler_path_text(job.get("file"))
    if file_path == "":
        reason = file_path_reason or "missing_scheduler_worker_path"
        return ProcessQueueChildJobStepResult(
            done_count=done_count,
            ok=False,
            failure_info={
                "error": "process_queue_child_file_unavailable",
                "file_path_unavailable_reason": reason,
            },
        )
    try:
        finished_path, result = request.worker(file_path, "unknown", _USE_SIGNAL_TIMEOUT)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        result, failure_info = build_child_failure_result(
            file_path,
            exc,
            stage="process_queue_child_worker",
            job=job,
        )
        next_done_count = record_child_worker_failure_result(
            ChildWorkerFailureResultRequest(
                job=job,
                child_results=request.child_results,
                worker_output_path=request.worker_output_path,
                queue_dir=request.work_queue_dir,
                claim_path=request.claim_path,
                write_result=request.write_queue_file_result,
                log_error=request.log_error,
                result=result,
                failure_info=failure_info,
                done_count=done_count,
            )
        )
        return ProcessQueueChildJobStepResult(
            done_count=next_done_count,
            ok=False,
            failure_info=failure_info,
        )
    result = normalize_scheduler_worker_result(
        finished_path,
        result,
        worker_error_result=make_scheduler_worker_error_result,
        recoverable_exceptions=RECOVERABLE_RUNTIME_ERRORS,
    )
    result = attach_child_worker_metadata(result, job=job)
    next_done_count = done_count + 1
    if not commit_process_queue_child_result(
        ProcessQueueChildResultCommitRequest(
            queue_dir=request.work_queue_dir,
            claim_path=request.claim_path,
            file_path=finished_path,
            result=result,
            child_results=request.child_results,
            worker_output_path=request.worker_output_path,
            write_result=request.write_queue_file_result,
            report=scheduler_failure_reporter,
            log_error=request.log_error,
            recoverable_exceptions=RECOVERABLE_RUNTIME_ERRORS,
            context="process_queue_child.result",
        )
    ):
        return ProcessQueueChildJobStepResult(
            done_count=next_done_count,
            ok=False,
            failure_info={
                "error": "process_queue_child_result_persist_failed",
                "stage": "process_queue_child_result_commit",
            },
        )
    request.bulk_scan_maintenance(next_done_count)
    request.log_bulk_progress(
        next_done_count,
        request.total_files,
        file_path=finished_path,
        started_at=request.scan_started_at,
        progress_every=request.progress_every,
    )
    if request.throttle_sec > 0.0:
        request.sleep(max(0.0, request.throttle_sec))
    return ProcessQueueChildJobStepResult(done_count=next_done_count, ok=True)


__all__ = ("ProcessQueueChildJobStepResult", "run_process_queue_child_job_body")
