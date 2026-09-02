"""Immutable process-queue dynamic feed contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_sequence_items
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int


@dataclass(frozen=True)
class ProcessQueueDynamicFeedRequest:
    enabled: bool
    queue_dir: object
    ordered_queue_items: tuple[object, ...]
    queue_feed_cursor: int
    queue_total_enqueued: int
    queue_enqueued_identities: tuple[object, ...]
    target_workers: int
    file_active_count: int
    file_pending_count: int
    io_pressure: bool
    cpu_sample: float | None
    elastic_io_sample: Mapping[str, object]
    all_files_count: int
    raw_live: int
    current_time: float
    queue_last_feed_log: float
    env: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "elastic_io_sample", immutable_mapping(self.elastic_io_sample)
        )
        object.__setattr__(self, "env", immutable_mapping(self.env))


@dataclass(frozen=True)
class ProcessQueueDynamicFeedDependencies:
    build_feed_policy: Callable[..., object]
    decide_feed: Callable[..., object]
    write_jobs_slice: Callable[..., tuple[int, int, int]]
    mark_feed_complete: Callable[[object], bool]
    progress_counts: Callable[[object], dict[str, int]]
    record_issue: Callable[..., None]
    log_error: Callable[[str], None]
    log_info: Callable[[str], None]
    recoverable_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        safe_recoverable_exceptions = (
            tuple(
                item
                for item in self.recoverable_exceptions
                if type(item) is type and issubclass(item, BaseException)
            )
            if type(self.recoverable_exceptions) is tuple
            else ()
        )
        object.__setattr__(
            self,
            "recoverable_exceptions",
            safe_recoverable_exceptions or (OSError, RuntimeError, TypeError, ValueError),
        )


@dataclass(frozen=True)
class ProcessQueueDynamicFeedOutput:
    queue_feed_cursor: int
    queue_total_enqueued: int
    queue_enqueued_identities: tuple[object, ...]
    queue_last_feed_log: float
    counts: Mapping[str, int]

    def __post_init__(self) -> None:
        cursor, _ = scheduler_int(self.queue_feed_cursor, default=0, minimum=0)
        total, _ = scheduler_int(self.queue_total_enqueued, default=0, minimum=0)
        last_log, _ = scheduler_float(
            self.queue_last_feed_log, default=0.0, minimum=0.0
        )
        identities = tuple(sorted(scheduler_str_sequence_items(self.queue_enqueued_identities)))
        object.__setattr__(self, "queue_feed_cursor", cursor)
        object.__setattr__(self, "queue_total_enqueued", total)
        object.__setattr__(self, "queue_enqueued_identities", identities)
        object.__setattr__(self, "queue_last_feed_log", last_log)
        object.__setattr__(self, "counts", immutable_mapping(self.counts))


@dataclass
class ProcessQueueDynamicFeedState:
    enabled: bool
    ordered_queue_items: tuple[object, ...]
    queue_feed_cursor: int
    queue_total_enqueued: int
    queue_enqueued_identities: set[str]
    queue_last_feed_log: float
    target_workers: int
    file_active_count: int
    file_pending_count: int
    io_pressure: bool
    cpu_sample: float | None
    all_files_count: int
    raw_live: int
    current_time: float
    counts: dict[str, object]

    def output(self) -> ProcessQueueDynamicFeedOutput:
        return ProcessQueueDynamicFeedOutput(
            self.queue_feed_cursor,
            self.queue_total_enqueued,
            tuple(self.queue_enqueued_identities),
            self.queue_last_feed_log,
            self.counts,
        )


__all__ = (
    "ProcessQueueDynamicFeedDependencies",
    "ProcessQueueDynamicFeedOutput",
    "ProcessQueueDynamicFeedRequest",
    "ProcessQueueDynamicFeedState",
)
