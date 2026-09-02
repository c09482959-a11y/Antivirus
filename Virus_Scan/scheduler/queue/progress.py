"""Queue-owned raw/process queue progress probes."""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.runtime.api import runtime_value
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.evidence.raw_queue_monitor import queue_progress_counts_global as _raw_queue_monitor_progress_counts
from Virus_Scan.scheduler.queue.authority import _ensure_process_queue_dirs, queue_now
from Virus_Scan.scheduler.queue.identity import queue_is_job_json_name as _queue_is_job_json_name
from Virus_Scan.scheduler.queue.issue_reporting import record_raw_queue_issue, _stage113_record_process_queue_suppressed
from Virus_Scan.scheduler.queue.raw_accumulator_store import RawAccumulatorStore
from Virus_Scan.scheduler.queue.raw_queue_progress import file_has_recent_raw_owner_progress
from Virus_Scan.scheduler.queue.raw_queue_recovery import raw_stage_progress_recent as _raw_stage_progress_recent_impl
from Virus_Scan.scheduler.runtime.queue_filesystem import global_raw_file_id as _global_raw_file_id, queue_job_dirs as _queue_job_dirs, safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.runtime.queue_json import read_json_file as _queue_read_json_file

if TYPE_CHECKING:
    from collections.abc import MutableMapping


def queue_progress_counts_global(queue_dir: object) -> object:
    return _raw_queue_monitor_progress_counts(
        queue_dir,
        ensure_dirs=_ensure_process_queue_dirs,
        queue_job_dirs=_queue_job_dirs,
        safe_queue_listdir=_safe_queue_listdir,
        is_job_json_name=_queue_is_job_json_name,
        read_json_file=_queue_read_json_file,
        report=_stage113_record_process_queue_suppressed,
        now_fn=queue_now,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )


def queue_raw_stage_progress_recent(
    queue_dir: object,
    quiet_sec: float | None = None,
    *,
    state: MutableMapping[str, tuple[int | None, float]],
) -> object:
    return _raw_stage_progress_recent_impl(
        queue_dir,
        quiet_sec=quiet_sec,
        progress_counts=queue_progress_counts_global,
        queue_now=queue_now,
        state=state,
        report=record_raw_queue_issue,
        default_quiet_sec=lambda: runtime_value("UMIGE_RAW_RECOVERY_QUIET_SEC", 120.0),
    )


def queue_file_has_recent_raw_owner_progress(
    queue_dir: object,
    file_path: object,
    quiet_sec: float | None = None,
    *,
    progress_state: MutableMapping[str, tuple[int | None, float]] | None = None,
) -> object:
    state = progress_state if progress_state is not None else {}
    return file_has_recent_raw_owner_progress(
        queue_dir,
        file_path,
        quiet_sec=quiet_sec,
        global_raw_file_id=_global_raw_file_id,
        accumulator_store_cls=RawAccumulatorStore,
        queue_now=queue_now,
        raw_stage_progress_recent=lambda q, quiet_sec=None: queue_raw_stage_progress_recent(
            q,
            quiet_sec=quiet_sec,
            state=state,
        ),
        report=record_raw_queue_issue,
    )

__all__ = (
    "queue_file_has_recent_raw_owner_progress",
    "queue_progress_counts_global",
    "queue_raw_stage_progress_recent",
)
