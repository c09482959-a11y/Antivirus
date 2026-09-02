"""Worker-owned process-queue child failure evidence helpers."""
from __future__ import annotations

import os
from collections.abc import Callable, Mapping, MutableMapping

from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.workers.metadata import attach_worker_metadata
from Virus_Scan.scheduler.workers.child_failure_metadata import build_safe_exception_info
from Virus_Scan.scheduler.workers.child_failure_metadata import worker_error_result
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.immutable_output_support import FrozenSchedulerMapping
from Virus_Scan.scheduler.internal.mapping_item_lookup import (
    scheduler_mapping_item_value,
    scheduler_str_key_mapping_from_items,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_error_detail, scheduler_path_text, scheduler_text
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_int
from Virus_Scan.scheduler.workers.process_queue_child_result_commit import (
    ProcessQueueChildResultCommitRequest,
    commit_process_queue_child_result,
)
from Virus_Scan.scheduler.workers.process_queue_child_failure_contracts import (
    ChildLoopFailureRequest,
    ChildWorkerFailureResultRequest,
)
ChildJob = Mapping[str, object] | None
ChildResults = MutableMapping[str, object]
FailureInfo = dict[str, object]
SchedulerFailureReport = Callable[[str, BaseException], object]
_DONE_COUNT_REASON = "process_queue_child_done_count_rejected"

def scheduler_failure_reporter(label: str, failure: BaseException) -> object:
    return record_suppressed_failure(label, failure, domain="scheduler")


def _job_field(job: ChildJob, key: str, default: object | None = None) -> object | None:
    if type(job) is FrozenSchedulerMapping:
        try:
            return job[key]
        except KeyError:
            return default
    return scheduler_mapping_item_value(no_hook_mapping_items(job), key, default)


def _safe_failure_info(value: object) -> FailureInfo:
    if value is None:
        return {
            "failure_info_unavailable": True,
            "failure_info_reason": "process_queue_child_failure_info_missing",
        }
    items = no_hook_mapping_items(value)
    if items is None:
        return {
            "failure_info_unavailable": True,
            "failure_info_reason": "process_queue_child_failure_info_rejected",
        }
    return scheduler_str_key_mapping_from_items(items)


def attach_child_worker_metadata(result: FailureInfo, *, job: ChildJob) -> FailureInfo:
    worker_id, worker_id_reason = scheduler_text(
        _job_field(job, "worker_id", "umige"),
        replacement_text="umige",
        unsupported_reason="process_queue_child_worker_id_rejected",
    )
    safe_worker_id = worker_id[:200] if worker_id_reason == "" and worker_id else "umige"
    annotated = attach_worker_metadata(
        result,
        scheduler_mode="process-queue-child",
        worker_id=safe_worker_id,
        worker_pid=os.getpid(),
    )
    if type(annotated) is not dict:
        return dict(result)
    return scheduler_str_key_mapping_from_items(tuple(annotated.items()))


def build_child_failure_result(file_path: object, exc: BaseException, *, stage: str, job: ChildJob) -> tuple[FailureInfo, FailureInfo]:
    result, failure_info = worker_error_result(
        file_path,
        exc,
        stage=stage,
        job=job,
        make_error_result=make_scheduler_worker_error_result,
        exception_info_builder=build_safe_exception_info,
        report=scheduler_failure_reporter,
        recoverable_exceptions=RECOVERABLE_RUNTIME_ERRORS,
    )
    return attach_child_worker_metadata(result, job=job), failure_info


def record_child_worker_failure_result(request: ChildWorkerFailureResultRequest) -> int:
    """Record an invoked worker failure as durable worker-result evidence."""
    failure_info = request.failure_info
    try:
        file_path, file_path_reason = scheduler_path_text(_job_field(request.job, "file"))
        if file_path == "":
            return worker_int(request.done_count, reason=_DONE_COUNT_REASON, minimum=0)[0]
        if file_path_reason:
            failure_info = _safe_failure_info(failure_info)
            failure_info["file_path_unavailable_reason"] = file_path_reason
        persisted = commit_process_queue_child_result(
            ProcessQueueChildResultCommitRequest(
                queue_dir=request.queue_dir,
                claim_path=request.claim_path,
                file_path=file_path,
                result=request.result,
                child_results=request.child_results,
                worker_output_path=request.worker_output_path,
                write_result=request.write_result,
                report=scheduler_failure_reporter,
                log_error=request.log_error,
                recoverable_exceptions=RECOVERABLE_RUNTIME_ERRORS,
                context="process_queue_child.worker_result_failure",
            )
        )
        if not persisted and type(failure_info) is dict:
            failure_info["result_persistence_failed"] = True
        return worker_int(request.done_count, reason=_DONE_COUNT_REASON, minimum=0)[0] + 1
    except RECOVERABLE_RUNTIME_ERRORS as suppressed_exc:
        try:
            record_suppressed_failure(
                "process_queue_child_worker_failure_result_record_failed",
                suppressed_exc,
                domain="scheduler",
                context={
                    "failure_info": _safe_failure_info(failure_info),
                    "job_file": scheduler_path_text(_job_field(request.job, "file"))[0],
                },
            )
        except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
            _ = reporting_exc
    return worker_int(request.done_count, reason=_DONE_COUNT_REASON, minimum=0)[0]


def record_child_loop_failure(request: ChildLoopFailureRequest) -> tuple[int, FailureInfo | None]:
    """Record a child-loop failure as explicit worker evidence."""
    failure_info: FailureInfo | None = {"error": scheduler_error_detail(request.exc)}
    done_count = request.done_count
    try:
        file_path, file_path_reason = scheduler_path_text(_job_field(request.job, "file"))
        if file_path:
            if file_path_reason:
                failure_info = _safe_failure_info(failure_info)
                failure_info["file_path_unavailable_reason"] = file_path_reason
            result, failure_info = build_child_failure_result(
                file_path,
                request.exc,
                stage="process_queue_child_loop",
                job=request.job,
            )
            done_count = record_child_worker_failure_result(
                ChildWorkerFailureResultRequest(
                    job=request.job,
                    child_results=request.child_results,
                    worker_output_path=request.worker_output_path,
                    queue_dir=request.queue_dir,
                    claim_path=request.claim_path,
                    write_result=request.write_result,
                    log_error=request.log_error,
                    result=result,
                    failure_info=failure_info,
                    done_count=done_count,
                )
            )
    except RECOVERABLE_RUNTIME_ERRORS as suppressed_exc:
        try:
            record_suppressed_failure("suppressed_exception", suppressed_exc, domain="runtime")
        except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
            _ = reporting_exc
    return (
        worker_int(done_count, reason=_DONE_COUNT_REASON, minimum=0)[0],
        failure_info,
    )


__all__ = (
    "attach_child_worker_metadata",
    "build_child_failure_result",
    "record_child_loop_failure",
    "record_child_worker_failure_result",
    "scheduler_failure_reporter",
)
