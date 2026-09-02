"""Process-queue progress count evidence ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.evidence.process_queue_monitor_progress_support import monitor_progress_int


@dataclass(frozen=True)
class ProcessQueueProgressCounts:
    counts: Mapping[str, int]
    file_done_count: int
    file_failed_count: int
    file_active_count: int
    file_pending_count: int
    raw_total: int
    raw_live: int
    accounted_total: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "counts", immutable_mapping(self.counts))


def snapshot_process_queue_progress_counts(
    queue_dir: object,
    *,
    progress_counts: Callable[[object], Mapping[str, int]],
) -> ProcessQueueProgressCounts:
    """Read queue progress counters and expose immutable derived evidence."""

    count_items = no_hook_mapping_items(progress_counts(queue_dir))
    if count_items is None:
        raise ValueError("scheduler_progress_counts_mapping_rejected")
    counts = dict(count_items)
    normalized: dict[str, int] = {}
    progress_keys = (
        "file_done",
        "file_failed",
        "file_active",
        "file_pending",
        "raw_pending",
        "raw_active",
        "raw_done",
        "raw_failed",
    )
    rejection_reasons = {
        "file_done": "scheduler_progress_count_file_done_rejected",
        "file_failed": "scheduler_progress_count_file_failed_rejected",
        "file_active": "scheduler_progress_count_file_active_rejected",
        "file_pending": "scheduler_progress_count_file_pending_rejected",
        "raw_pending": "scheduler_progress_count_raw_pending_rejected",
        "raw_active": "scheduler_progress_count_raw_active_rejected",
        "raw_done": "scheduler_progress_count_raw_done_rejected",
        "raw_failed": "scheduler_progress_count_raw_failed_rejected",
    }
    for key in progress_keys:
        if key not in counts:
            normalized[key] = 0
            continue
        normalized[key] = monitor_progress_int(counts[key], rejection_reasons[key])
    file_done_count = normalized["file_done"]
    file_failed_count = normalized["file_failed"]
    file_active_count = normalized["file_active"]
    file_pending_count = normalized["file_pending"]
    raw_total = sum(normalized[key] for key in ("raw_pending", "raw_active", "raw_done", "raw_failed"))
    raw_live = normalized["raw_pending"] + normalized["raw_active"]
    accounted_total = file_done_count + file_failed_count + normalized["raw_done"] + normalized["raw_failed"]
    return ProcessQueueProgressCounts(
        counts=immutable_mapping(normalized),
        file_done_count=file_done_count,
        file_failed_count=file_failed_count,
        file_active_count=file_active_count,
        file_pending_count=file_pending_count,
        raw_total=raw_total,
        raw_live=raw_live,
        accounted_total=accounted_total,
    )


__all__ = ("ProcessQueueProgressCounts", "snapshot_process_queue_progress_counts")
