"""Shared heartbeat row writer."""
from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.workers.heartbeat_support import heartbeat_rejection
from Virus_Scan.scheduler.workers.heartbeat_write_steps import (
    heartbeat_write_values,
    write_heartbeat_row,
)
from Virus_Scan.scheduler.workers.shared_heartbeat_evidence import record_shared_heartbeat_failure

HEARTBEAT_WRITE_REJECTED = False


def update_shared_heartbeat(
    heartbeat_table: object,
    job_id: object,
    generation: object,
    *,
    pid: object = None,
    thread_id: object = None,
    stage: object = "scan",
    progress_counter: object = 0,
    bytes_processed: object = 0,
    last_progress_ns: object = 0,
    flags: object = 0,
    rss_mb: object = 0.0,
    completed_jobs: object = 0,
) -> bool:
    parsed = heartbeat_write_values(
        job_id=job_id,
        generation=generation,
        pid=pid,
        thread_id=thread_id,
        stage=stage,
        progress_counter=progress_counter,
        bytes_processed=bytes_processed,
        last_progress_ns=last_progress_ns,
        flags=flags,
        rss_mb=rss_mb,
        completed_jobs=completed_jobs,
    )
    if type(heartbeat_table) is not dict or type(parsed) is str:
        heartbeat_rejection(
            "heartbeat_write",
            job_id,
            generation,
            parsed if type(parsed) is str else "heartbeat_table_rejected",
        )
        return HEARTBEAT_WRITE_REJECTED
    try:
        write_heartbeat_row(heartbeat_table, parsed)
        return True
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_shared_heartbeat_failure(
            operation="heartbeat_write", job_id=job_id, generation=generation, exc=exc
        )
        return HEARTBEAT_WRITE_REJECTED


__all__ = ("update_shared_heartbeat",)
