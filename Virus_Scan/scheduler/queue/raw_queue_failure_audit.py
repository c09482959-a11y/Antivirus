"""Canonical failed queue audit/report helpers.

Stage193 moves terminal failed-job report construction out of the deleted monolithic scheduler queue module.
The helper is metadata-only: it reads failed queue artifacts and constructs
forensic diagnostics without requeueing, deleting, or mutating jobs.
"""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import QueueListdirFailure, queue_listdir_names
from Virus_Scan.scheduler.queue.raw_queue_failure_audit_decisions import (
    failed_queue_mapping_decision,
    failed_queue_name_decision,
)
from Virus_Scan.scheduler.queue.raw_queue_path_support import materialize_raw_queue_path


def _text(value: object, *, default: str = "") -> str:
    text, reason = no_hook_text(value, unsupported_reason="failed_queue_report_text_rejected")
    if reason or text == "":
        return default
    return text



def collect_failed_queue_report(
    queue_dir: object,
    *,
    queue_job_dirs: Callable[[object], tuple[object, object, object, object]],
    safe_queue_listdir: Callable[[object], list[str] | QueueListdirFailure],
    is_job_json_name: Callable[[str], bool],
    read_json_file: Callable[..., object],
    recoverable_exceptions: tuple[type[BaseException], ...],
    log_error: Callable[[str], object],
) -> list[dict[str, object]]:
    """Build durable failed-job report entries from failed/*.json.

    The caller owns whether incomplete queue state is fatal. This helper only
    normalizes failed job metadata so terminal reporting is deterministic and
    not duplicated inside the raw queue orchestration loop.
    """
    failure_report: list[dict[str, object]] = []
    try:
        _pending, _active, _done, failed = queue_job_dirs(queue_dir)
        failed_path = materialize_raw_queue_path(failed, reason="failed_queue_report_path_rejected")
        if not failed_path.exists():
            return failure_report
        names = []
        for raw_name in queue_listdir_names(safe_queue_listdir(failed_path), context=failed_path):
            name = failed_queue_name_decision(raw_name).text
            if name:
                names.append(name)
        for name in sorted(names)[:5000]:
            if not is_job_json_name(name):
                continue
            item = failed_queue_mapping_decision(read_json_file(failed_path / name, default={})).as_mapping()
            if not item:
                item = {"queue_job": name, "failure_info": {"error": "failed job JSON unreadable"}}
            info = failed_queue_mapping_decision(dict.get(item, "failure_info")).as_mapping()
            if not info:
                info = {
                    "stage": "failed_without_diagnostics",
                    "exception_type": "MissingFailureInfo",
                    "error": "job was in failed/ without failure_info; likely orphaned active job or finalization path before diagnostics",
                    "worker_pid": None,
                    "time": None,
                }
            qi = failed_queue_mapping_decision(dict.get(item, "queue_info")).as_mapping()
            failure_report.append({
                "queue_job": name,
                "job_type": dict.get(item, "job_type", "file"),
                "file": dict.get(item, "file"),
                "collector": dict.get(item, "collector"),
                "seq": dict.get(item, "seq"),
                "attempt": dict.get(item, "attempt"),
                "stage": dict.get(info, "stage"),
                "exception_type": dict.get(info, "exception_type"),
                "error": dict.get(info, "error"),
                "worker_pid": (
                    dict.get(info, "worker_pid")
                    if dict.get(info, "worker_pid") is not None
                    else dict.get(qi, "worker_pid")
                ),
                "time": (
                    dict.get(info, "time")
                    if dict.get(info, "time") is not None
                    else (
                        dict.get(qi, "heartbeat_iso")
                        if dict.get(qi, "heartbeat_iso") is not None
                        else dict.get(qi, "claimed_iso")
                    )
                ),
                "queue_info": qi,
                "queue_reclaim_history": list(no_hook_sequence_items(dict.get(item, "queue_reclaim_history"))),
            })
    except recoverable_exceptions as exc:
        log_error("process queue failed-job report collection failed: " + scheduler_exception_text(exc))
    return failure_report


def summarize_failed_queue_report(failure_report: list[dict[str, object]], *, limit: int = 10) -> list[tuple[tuple[str, str, str, str], int]]:
    """Return deterministic aggregate reason counts for terminal logging."""
    summary: dict[tuple[str, str, str, str], int] = {}
    for fr_raw in failure_report:
        fr = failed_queue_mapping_decision(fr_raw).as_mapping()
        key = (
            _text(dict.get(fr, "job_type"), default="file"),
            _text(dict.get(fr, "stage"), default="unknown"),
            _text(dict.get(fr, "exception_type"), default="unknown"),
            _text(dict.get(fr, "error"))[:160],
        )
        summary[key] = dict.get(summary, key, 0) + 1
    safe_limit, _reason = scheduler_int(limit, default=10, minimum=0, reason="failed_queue_report_limit_rejected")
    return sorted(dict.items(summary), key=lambda kv: kv[1], reverse=True)[:safe_limit]
