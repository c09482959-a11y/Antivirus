"""Bounded progress/heartbeat publication steps for process-queue monitors."""
from __future__ import annotations

from Virus_Scan.scheduler.evidence.process_queue_monitor_progress_support import (
    progress_cpu_text,
    progress_int_text,
)
from Virus_Scan.scheduler.evidence.process_queue_partial_output import (
    ProcessQueuePartialOutputDependencies,
    ProcessQueuePartialOutputRequest,
    publish_process_queue_partial_output,
)


def should_log_progress(request: object) -> bool:
    if request.file_done_count != request.last_done_count and (
        request.file_done_count in {request.total_files, 0}
        or request.file_done_count % max(1, request.progress_every) == 0
    ):
        return True
    return bool(request.live_workers and request.now - request.last_progress_time >= request.progress_interval_sec)


def should_log_heartbeat(request: object) -> bool:
    return bool(
        request.live_workers
        and (request.now - request.last_monitor_heartbeat_time) >= request.monitor_heartbeat_sec
    )


def progress_log_message(request: object) -> str:
    return (
        "bulk scan progress: files_done="
        + progress_int_text(request.file_done_count)
        + "/"
        + progress_int_text(request.total_files)
        + " files_active="
        + progress_int_text(request.file_active_count)
        + " files_pending="
        + progress_int_text(request.file_pending_count)
        + " files_failed="
        + progress_int_text(request.file_failed_count)
        + " raw_live="
        + progress_int_text(request.raw_live)
        + " raw_done="
        + progress_int_text(request.raw_done)
        + " raw_failed="
        + progress_int_text(request.raw_failed)
        + " live_workers="
        + progress_int_text(request.live_workers)
    )


def heartbeat_log_message(request: object) -> str:
    return (
        "bulk scan monitor: alive=1 files_done="
        + progress_int_text(request.file_done_count)
        + "/"
        + progress_int_text(request.total_files)
        + " files_active="
        + progress_int_text(request.file_active_count)
        + " files_pending="
        + progress_int_text(request.file_pending_count)
        + " files_failed="
        + progress_int_text(request.file_failed_count)
        + " raw_live="
        + progress_int_text(request.raw_live)
        + " raw_done="
        + progress_int_text(request.raw_done)
        + " raw_failed="
        + progress_int_text(request.raw_failed)
        + " live_workers="
        + progress_int_text(request.live_workers)
        + " accounted_total="
        + progress_int_text(request.accounted_total)
        + " cpu="
        + progress_cpu_text(request.elastic_cpu_sample)
    )


def publish_monitor_partial_output(request: object, dependencies: object) -> tuple[object, ...]:
    partial_publication = publish_process_queue_partial_output(
        ProcessQueuePartialOutputRequest(
            outputs=request.outputs,
            partial_output_path=request.partial_output_path,
            context="partial_monitor",
        ),
        ProcessQueuePartialOutputDependencies(
            read_json_file=dependencies.read_json_file,
            log_error=dependencies.log_error,
            recoverable_exceptions=dependencies.recoverable_exceptions,
        ),
    )
    return partial_publication.evidence


__all__ = (
    "heartbeat_log_message",
    "progress_log_message",
    "publish_monitor_partial_output",
    "should_log_heartbeat",
    "should_log_progress",
)
