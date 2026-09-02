"""Canonical raw-queue telemetry monitor helpers.

Evidence owns queue pressure, progress counters, and operator-facing queue health
snapshots.  These helpers do not mutate queue state; they emit caller-owned
immutable dict snapshots that reconciliation/execution may consume.
"""
from __future__ import annotations

from typing import Callable, Mapping, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scheduler.internal.raw_queue_monitor_no_hook import (
    exact_reason_text,
    plain_scheduler_mapping,
)
from Virus_Scan.scheduler.evidence.raw_queue_monitor_io import queue_io_pressure_sample
from Virus_Scan.scheduler.evidence.raw_queue_monitor_support import (
    QUEUE_JOB_KIND_FILE,
    QUEUE_JOB_KIND_RAW,
    raw_queue_job_kind,
    safe_queue_names,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import QueueListdirFailure


def queue_pressure_flags(io_sample: Mapping[str, object] | None) -> dict[str, object]:
    """Normalize queue pressure metadata without treating metadata latency as disk pressure."""
    sample = plain_scheduler_mapping(io_sample, field_name="queue_pressure_sample")
    reason = exact_reason_text(dict.get(sample, "reason"), default="")
    reasons = {r for r in reason.split("+") if r}
    metadata_latency = "queue_latency" in reasons
    actual_disk = any(r in reasons for r in ("disk_busy", "queue_file_count"))
    sample["metadata_latency"] = bool(metadata_latency)
    sample["actual_disk_io_pressure"] = bool(actual_disk)
    sample["pressure"] = bool(actual_disk)
    if metadata_latency and not actual_disk:
        sample["reason"] = "queue_metadata_latency"
    elif actual_disk and metadata_latency:
        sample["reason"] = reason.replace("queue_latency", "queue_metadata_latency")
    return sample


def _classify_queue_progress_job(
    *,
    counts: dict[str, int],
    key_file: str,
    key_raw: str,
    directory: object,
    name: object,
    is_job_json_name: Callable[[str], bool],
    read_json_file: Callable[..., object],
    report: Callable[..., object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    job_name, job_name_reason = no_hook_text(
        name,
        missing_reason="missing_queue_job_name",
        unsupported_reason="unsafe_queue_job_name_rejected",
    )
    if job_name_reason:
        report("queue_progress_job_name_rejected", None, fatal=False)
        return
    if not is_job_json_name(job_name):
        return
    job_kind = raw_queue_job_kind(
        directory,
        job_name,
        read_json_file=read_json_file,
        report=report,
        recoverable_exceptions=recoverable_exceptions,
    )
    if job_kind == QUEUE_JOB_KIND_RAW:
        counts[key_raw] += 1
    elif job_kind == QUEUE_JOB_KIND_FILE:
        counts[key_file] += 1


def _count_queue_progress_directory(
    *,
    counts: dict[str, int],
    key_file: str,
    key_raw: str,
    directory: object,
    safe_queue_listdir: Callable[[object], list[str] | QueueListdirFailure],
    is_job_json_name: Callable[[str], bool],
    read_json_file: Callable[..., object],
    report: Callable[..., object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    for name in safe_queue_names(
        directory,
        safe_queue_listdir=safe_queue_listdir,
        report=report,
        failure_stage="queue_progress_counts_failed",
        recoverable_exceptions=recoverable_exceptions,
    ):
        try:
            _classify_queue_progress_job(
                counts=counts,
                key_file=key_file,
                key_raw=key_raw,
                directory=directory,
                name=name,
                is_job_json_name=is_job_json_name,
                read_json_file=read_json_file,
                report=report,
                recoverable_exceptions=recoverable_exceptions,
            )
        except recoverable_exceptions as exc:
            report("queue_progress_count_entry_failed", exc)


def queue_progress_counts_global(
    queue_dir: object,
    *,
    ensure_dirs: Callable[[object], object],
    queue_job_dirs: Callable[[object], tuple[object, object, object, object]],
    safe_queue_listdir: Callable[[object], list[str] | QueueListdirFailure],
    is_job_json_name: Callable[[str], bool],
    read_json_file: Callable[..., object],
    report: Callable[..., object],
    now_fn: Callable[[], float] | None = None,
    recoverable_exceptions: tuple[type[BaseException], ...] = (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ),
) -> dict[str, int]:
    """Count file/raw queue states using deterministic queue-owned semantics."""
    del now_fn
    counts = {
        "file_pending": 0,
        "file_active": 0,
        "file_done": 0,
        "file_failed": 0,
        "raw_pending": 0,
        "raw_active": 0,
        "raw_done": 0,
        "raw_failed": 0,
    }
    try:
        ensure_dirs(queue_dir)
        pending, active, done, failed = queue_job_dirs(queue_dir)
        for key_file, key_raw, directory in (
            ("file_pending", "raw_pending", pending),
            ("file_active", "raw_active", active),
            ("file_done", "raw_done", done),
            ("file_failed", "raw_failed", failed),
        ):
            _count_queue_progress_directory(
                counts=counts,
                key_file=key_file,
                key_raw=key_raw,
                directory=directory,
                safe_queue_listdir=safe_queue_listdir,
                is_job_json_name=is_job_json_name,
                read_json_file=read_json_file,
                report=report,
                recoverable_exceptions=recoverable_exceptions,
            )
    except recoverable_exceptions as exc:
        report("queue_progress_counts_failed", exc)
    return counts


__all__ = (
    "queue_io_pressure_sample",
    "queue_pressure_flags",
    "queue_progress_counts_global",
)
