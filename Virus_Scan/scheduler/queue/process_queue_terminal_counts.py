"""Terminal process-queue count projection with explicit listdir failure."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names


def _job_count(
    directory: object,
    *,
    safe_listdir: Callable[[object], object],
    is_job_name: Callable[[object], bool],
) -> int:
    path_value, reason = scheduler_filesystem_path(directory)
    if reason or path_value == "":
        raise TypeError("process_queue_terminal_count_directory_rejected")
    safe_directory = path_value if isinstance(path_value, Path) else Path(path_value)
    if safe_directory.exists() is False:
        return 0
    return sum(
        1
        for name in queue_listdir_names(
            safe_listdir(safe_directory),
            context=safe_directory,
        )
        if is_job_name(name)
    )


def terminal_queue_counts(
    pending: object,
    active: object,
    failed: object,
    *,
    safe_listdir: Callable[[object], object],
    is_job_name: Callable[[object], bool],
) -> tuple[int, int, int]:
    """Return pending, active, and failed job counts or raise explicit evidence."""
    return (
        _job_count(pending, safe_listdir=safe_listdir, is_job_name=is_job_name),
        _job_count(active, safe_listdir=safe_listdir, is_job_name=is_job_name),
        _job_count(failed, safe_listdir=safe_listdir, is_job_name=is_job_name),
    )


__all__ = ("terminal_queue_counts",)
