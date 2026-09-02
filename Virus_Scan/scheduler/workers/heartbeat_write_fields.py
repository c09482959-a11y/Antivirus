"""Shared heartbeat field parsing helpers."""
from __future__ import annotations

import os
import threading

from Virus_Scan.scheduler.workers.heartbeat_support import safe_heartbeat_int

HEARTBEAT_ARRAY_KEYS = (
    "monotonic_ns",
    "generation",
    "pid",
    "thread_id",
    "stage",
    "progress_counter",
    "bytes_processed",
    "last_progress_ns",
    "flags",
    "completed_jobs",
)


def current_progress_time_requested(last_progress_ns: object) -> bool:
    return last_progress_ns is None or (
        type(last_progress_ns) is int
        and type(last_progress_ns) is not bool
        and last_progress_ns == 0
    )


def heartbeat_int_fields(
    *,
    now_ns: int,
    pid: object,
    thread_id: object,
    progress_counter: object,
    bytes_processed: object,
    last_progress_ns: object,
    flags: object,
    completed_jobs: object,
) -> tuple[tuple[str, object, str, str], ...]:
    progress_time = now_ns if current_progress_time_requested(last_progress_ns) else last_progress_ns
    return (
        ("pid", os.getpid() if pid is None else pid, "heartbeat_pid_rejected", "heartbeat_pid_non_finite"),
        (
            "thread_id",
            threading.get_ident() if thread_id is None else thread_id,
            "heartbeat_thread_id_rejected",
            "heartbeat_thread_id_non_finite",
        ),
        (
            "progress_counter",
            progress_counter,
            "heartbeat_progress_counter_rejected",
            "heartbeat_progress_counter_non_finite",
        ),
        (
            "bytes_processed",
            bytes_processed,
            "heartbeat_bytes_processed_rejected",
            "heartbeat_bytes_processed_non_finite",
        ),
        (
            "last_progress_ns",
            progress_time,
            "heartbeat_last_progress_ns_rejected",
            "heartbeat_last_progress_ns_non_finite",
        ),
        ("flags", flags, "heartbeat_flags_rejected", "heartbeat_flags_non_finite"),
        (
            "completed_jobs",
            completed_jobs,
            "heartbeat_completed_jobs_rejected",
            "heartbeat_completed_jobs_non_finite",
        ),
    )


def parsed_heartbeat_ints(
    fields: tuple[tuple[str, object, str, str], ...],
) -> tuple[dict[str, int] | None, str]:
    parsed: dict[str, int] = {}
    for key, value, rejected, non_finite in fields:
        parsed_value, reason = safe_heartbeat_int(
            value,
            rejection_reason=rejected,
            non_finite_reason=non_finite,
        )
        if reason:
            return None, reason
        parsed[key] = parsed_value
    return parsed, ""


__all__ = (
    "HEARTBEAT_ARRAY_KEYS",
    "heartbeat_int_fields",
    "parsed_heartbeat_ints",
)
