"""Canonical raw queue progress ownership helpers.

Stage184: owns raw-owner progress checks inside canonical scheduler owners so reclaim logic can
reason about accumulator activity without carrying that policy in the monolith.
"""
from __future__ import annotations

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text
from Virus_Scan.scheduler.queue.raw_queue_progress_evidence import raw_progress_extra
from Virus_Scan.scheduler.queue.raw_queue_progress_steps import (
    apply_raw_owner_completion,
    apply_raw_owner_recent,
    load_raw_owner_progress_data,
    raw_owner_progress_info,
    raw_owner_quiet_seconds,
    raw_owner_updated_timestamp,
)

RAW_QUEUE_PROGRESS_SOURCE_GUARD_MARKERS = (
    "queue_raw_owner_progress_mapping_unavailable",
    "queue_raw_owner_progress_complete_unavailable",
    "queue_raw_owner_progress_recent_global_unavailable",
)


def file_has_recent_raw_owner_progress(
    queue_dir: object,
    file_path: object,
    quiet_sec: object = None,
    *,
    global_raw_file_id: object,
    accumulator_store_cls: object,
    queue_now: object,
    raw_stage_progress_recent: object,
    report: object,
) -> object:
    """Return raw-owner activity for an active original file job."""
    info = raw_owner_progress_info()
    try:
        queue_text, queue_reason = scheduler_path_text(queue_dir)
        file_text, file_reason = scheduler_path_text(file_path)
        if queue_reason != "" or file_reason != "" or queue_text == "" or file_text == "":
            return info
        fid = global_raw_file_id(file_path)
        info["file_id"] = fid
        store = accumulator_store_cls(queue_dir, fid)
        data = load_raw_owner_progress_data(
            info=info,
            data=store.load(),
            fid=fid,
            queue_dir=queue_dir,
            file_path=file_path,
            report=report,
        )
        if data is None:
            return info
        complete = apply_raw_owner_completion(
            info=info,
            complete=accumulator_store_cls.is_complete(data),
            queue_dir=queue_dir,
            file_path=file_path,
            report=report,
        )
        if complete:
            return info
        updated = raw_owner_updated_timestamp(
            info=info,
            data=data,
            store_path=store.path,
            report=report,
        )
        age = queue_now() - updated if updated > 0.0 else None
        info["age"] = age
        apply_raw_owner_recent(
            info=info,
            age=age,
            quiet=raw_owner_quiet_seconds(quiet_sec),
            queue_dir=queue_dir,
            file_path=file_path,
            raw_stage_progress_recent=raw_stage_progress_recent,
            report=report,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        report(
            "queue_raw_owner_progress_check_failed",
            exc,
            fatal=False,
            extra=raw_progress_extra(queue_dir, file_path),
        )
    return info
