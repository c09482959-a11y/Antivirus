"""Bounded steps for failed queue diagnostic repair."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.runtime.api import flush_open_writable_file
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.queue.raw_queue_path_support import materialize_raw_queue_path as queue_path
from Virus_Scan.scheduler.queue.raw_queue_failed_diagnostics_evidence import (
    failed_queue_mapping_decision,
    failed_queue_name_decision,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import (
    QueueListdirFailure,
    queue_listdir_names,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping



def mapping(value: object) -> dict[str, object]:
    """Materialize a diagnostic mapping without caller-owned mapping hooks."""
    return dict(failed_queue_mapping_decision(value).mapping)


def failed_queue_job_names(
    failed_path: Path,
    *,
    safe_queue_listdir: Callable[[object], list[str] | QueueListdirFailure],
) -> tuple[str, ...]:
    """Return sorted failed-job names from a queue directory listing."""
    names: list[str] = []
    for raw_name in queue_listdir_names(safe_queue_listdir(failed_path), context=failed_path):
        name = failed_queue_name_decision(raw_name).text
        if name:
            names.append(name)
    return tuple(sorted(names))


def failed_queue_reclaim_info(item: dict[str, object]) -> dict[str, object]:
    """Build failure info from the latest reclaim history record when present."""
    hist = no_hook_sequence_items(dict.get(item, "queue_reclaim_history"))
    last = mapping(hist[-1]) if hist else {}
    if not last:
        return {}
    reclaim_info = dict(last)
    return {
        **reclaim_info,
        "stage": dict.get(reclaim_info, "stage", "queue_failed_after_reclaim"),
        "exception_type": dict.get(reclaim_info, "exception_type", "QueueReclaimFailure"),
        "error": dict.get(
            reclaim_info,
            "error",
            "queue job failed after reclaim/retry; diagnostics recovered from reclaim history",
        ),
        "time": dict.get(
            reclaim_info,
            "time",
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        ),
    }


def synthesize_failed_queue_info(
    item: dict[str, object],
    *,
    name: str,
    default_failure_info: Callable[..., Mapping[str, object]],
) -> dict[str, object]:
    """Return replayable failure info for a failed queue job lacking diagnostics."""
    del name
    reclaim_info = failed_queue_reclaim_info(item)
    if reclaim_info:
        return reclaim_info
    qi = mapping(dict.get(item, "queue_info"))
    return mapping(default_failure_info(
        stage="queue_failed_without_original_diagnostics",
        exception_type="QueueFailureDiagnosticsSynthesized",
        error="failed queue job lacked failure_info; synthesized during failed-job audit",
        worker_pid=dict.get(qi, "worker_pid", dict.get(item, "worker_pid")),
        attempt=dict.get(item, "attempt"),
    ))


def safe_remove_tmp(
    tmp: str | Path,
    queue_safe_unlink: Callable[..., bool],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    context: str,
) -> None:
    """Remove a failed repair temp file while recording cleanup failure."""
    try:
        queue_safe_unlink(tmp, log_context=context)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        record_scheduler_suppressed("queue_repair_cleanup_failed", exc)


def publish_failed_queue_repair(
    *,
    path: Path,
    item: dict[str, object],
    make_json_safe: Callable[[object], object],
    queue_safe_unlink: Callable[..., bool],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
) -> bool:
    """Durably publish repaired failed-job metadata."""
    tmp = path.with_name(path.name + ".repair.tmp")
    sync_ok = True
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(make_json_safe(item), fh, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        try:
            fh.flush()
            flush_open_writable_file(fh.fileno())
        except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
            sync_ok = False
            record_scheduler_suppressed("queue_repair_failed_job_sync_failed", exc)
    if sync_ok is not True:
        safe_remove_tmp(tmp, queue_safe_unlink, record_scheduler_suppressed, "queue_repair_failed_job_sync_failed")
        return False
    if queue_atomic_replace(tmp, path, log_context="queue_repair_failed_job") is not True:
        safe_remove_tmp(tmp, queue_safe_unlink, record_scheduler_suppressed, "queue_repair_failed_job_replace_failed")
        return False
    return True


def repair_one_failed_queue_job(
    *,
    path: Path,
    name: str,
    read_json_file: Callable[..., object],
    default_failure_info: Callable[..., Mapping[str, object]],
    make_json_safe: Callable[[object], object],
    queue_safe_unlink: Callable[..., bool],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
) -> bool:
    """Repair one failed queue job when failure diagnostics are missing."""
    item = mapping(read_json_file(path, default={}))
    if not item:
        item = {"queue_job": name, "queue_unreadable": True}
    failure_info = mapping(dict.get(item, "failure_info"))
    if failure_info:
        return False
    item["queue_failure"] = True
    item["failure_info"] = make_json_safe(
        synthesize_failed_queue_info(
            item,
            name=name,
            default_failure_info=default_failure_info,
        )
    )
    return publish_failed_queue_repair(
        path=path,
        item=item,
        make_json_safe=make_json_safe,
        queue_safe_unlink=queue_safe_unlink,
        record_scheduler_suppressed=record_scheduler_suppressed,
    )


__all__ = (
    "failed_queue_job_names",
    "mapping",
    "publish_failed_queue_repair",
    "queue_path",
    "repair_one_failed_queue_job",
    "safe_remove_tmp",
    "synthesize_failed_queue_info",
)
