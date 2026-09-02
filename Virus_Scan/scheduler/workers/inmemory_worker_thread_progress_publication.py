"""Worker thread progress heartbeat publication helper."""
from __future__ import annotations

import os
import threading
from collections.abc import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_int
from Virus_Scan.scheduler.workers.inmemory_scan_progress import _exception_type_tuple
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import worker_lifecycle_exception_reason


def publish_shared_worker_thread_heartbeat(
    progress: object,
    *,
    stage_name: str,
    flags: int,
    rss_mb: float,
    record_task_meta_rejection: Callable[[object, str], None],
    record_heartbeat_failure: Callable[..., None],
) -> tuple[bool, bool]:
    """Publish one worker-thread heartbeat without owning progress state mutation."""
    try:
        heartbeat_published_raw = progress.update_shared_heartbeat(
            progress.heartbeat_table,
            progress.job_id,
            progress.generation,
            pid=os.getpid(),
            thread_id=threading.get_ident(),
            stage=stage_name,
            progress_counter=int(progress.progress_counter),
            bytes_processed=int(progress.bytes_processed),
            last_progress_ns=int(progress.last_progress_ns),
            flags=flags,
            rss_mb=float(rss_mb),
            completed_jobs=scheduler_int(progress.completed_jobs, minimum=0, reason="worker_thread_progress_completed_jobs_rejected")[0],
        )
        heartbeat_published, heartbeat_reason = scheduler_bool(
            heartbeat_published_raw,
            reason="worker_thread_progress_publish_flag_rejected",
        )
        record_task_meta_rejection(progress.task_meta, heartbeat_reason)
        return heartbeat_published, False
    except _exception_type_tuple(progress.recoverable_exceptions) as exc:
        record_heartbeat_failure(
            stage_name=stage_name,
            reason=str.__add__("shared heartbeat update raised ", worker_lifecycle_exception_reason(exc)),
            exc=exc,
        )
        return False, True


__all__ = ("publish_shared_worker_thread_heartbeat",)
