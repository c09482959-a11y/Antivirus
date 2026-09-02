"""Queue counting helpers for raw queue scheduling decisions."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_nonnegative_int
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names
from Virus_Scan.scheduler.queue.raw_queue_path_support import raw_queue_path_extra

_RAW_QUEUE_PROGRESS_COUNTS_REJECTED = "raw queue progress counts rejected"


def _queue_name_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_raw_queue_name",
        unsupported_reason="unsafe_raw_queue_name_rejected",
    )
    if reason or text == "":
        return ""
    return text


def pending_file_jobs(
    queue_dir: object,
    *,
    queue_job_dirs: Callable[[object], tuple[object, object, object, object]],
    safe_listdir: Callable[[object], list[str]],
    read_json_file: Callable[..., object],
    report: Callable[..., object],
) -> int:
    """Count pending non-raw file jobs, returning -1 when the count is unknown."""
    try:
        pending, _active, _done, _failed = queue_job_dirs(queue_dir)
        count = 0
        for raw_name in queue_listdir_names(safe_listdir(pending), context=pending):
            name = _queue_name_text(raw_name)
            if not name.endswith(".json"):
                continue
            job = read_json_file(pending / name, default={})
            items = no_hook_mapping_items(job, allow_dict_subclass=True)
            if items is None:
                continue
            data = scheduler_str_key_mapping_from_items(items)
            job_type = dict.get(data, "job_type")
            if type(job_type) is str and job_type == "raw_stage":
                continue
            count += 1
        return count
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        report("raw_pending_file_jobs_unknown", exc, fatal=False, extra=raw_queue_path_extra("queue_dir", queue_dir))
        return -1


def raw_queue_live_count(
    queue_dir: object,
    *,
    queue_progress_counts: Callable[[object], Mapping[str, object]],
    report: Callable[[str, BaseException], object],
    live_hard_cap: int,
) -> int:
    """Return raw pending+active count; fail closed to hard cap when unknown."""
    parsed_hard_cap, hard_cap_reason = scheduler_int(
        live_hard_cap,
        default=900,
        minimum=0,
        reason="raw_live_hard_cap_rejected",
    )
    hard_cap = parsed_hard_cap if not hard_cap_reason else 900
    try:
        qc = queue_progress_counts(queue_dir)
        items = no_hook_mapping_items(qc, allow_dict_subclass=True)
        if items is None:
            raise TypeError(_RAW_QUEUE_PROGRESS_COUNTS_REJECTED)
        data = scheduler_str_key_mapping_from_items(items)
        return scheduler_nonnegative_int(
            dict.get(data, "raw_pending"),
            reason="raw_queue_count_rejected",
        ) + scheduler_nonnegative_int(
            dict.get(data, "raw_active"),
            reason="raw_queue_count_rejected",
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        report("raw_live_count_failed_closed", exc)
        return hard_cap
