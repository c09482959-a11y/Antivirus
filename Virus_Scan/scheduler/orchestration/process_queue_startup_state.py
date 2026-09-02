"""Immutable process-queue startup runtime state."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.orchestration.process_queue_startup_state_steps import (
    freeze_startup_progress_state,
    normalize_startup_identity_set,
    normalize_startup_int_fields,
    normalize_startup_ordered_items,
    normalize_startup_scalar_fields,
)

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class ProcessQueueStartupState:
    """Startup snapshot consumed by the execution loop."""

    queue_dir: Path
    outputs_dir: Path
    runtime_dir: Path
    worker_pool: object
    ordered_queue_items: tuple[object, ...]
    queue_feed_cursor: int
    queue_enqueued_identities: frozenset[str]
    queue_total_enqueued: int
    queue_last_feed_log: float
    raw_stage_progress_state: object
    process_count: int
    requested_process_count: int
    dynamic_queue_feed: bool
    elastic_scheduler: bool
    elastic_min_workers: int
    next_worker_spawn_id: int

    def __post_init__(self) -> None:
        ordered_items = normalize_startup_ordered_items(self.ordered_queue_items)
        identities = normalize_startup_identity_set(self.queue_enqueued_identities)
        normalized_ints, reasons = normalize_startup_int_fields(
            {
                "queue_feed_cursor": (self.queue_feed_cursor, 0),
                "queue_total_enqueued": (self.queue_total_enqueued, 0),
                "process_count": (self.process_count, 1),
                "requested_process_count": (self.requested_process_count, 1),
                "elastic_min_workers": (self.elastic_min_workers, 0),
                "next_worker_spawn_id": (self.next_worker_spawn_id, 0),
            }
        )
        queue_last_feed_log, dynamic_queue_feed, elastic_scheduler, scalar_reasons = normalize_startup_scalar_fields(
            queue_last_feed_log=self.queue_last_feed_log,
            dynamic_queue_feed=self.dynamic_queue_feed,
            elastic_scheduler=self.elastic_scheduler,
        )
        reasons.extend(scalar_reasons)
        if reasons:
            raise ValueError(",".join(reasons))
        object.__setattr__(self, "ordered_queue_items", ordered_items)
        object.__setattr__(self, "queue_feed_cursor", normalized_ints["queue_feed_cursor"])
        object.__setattr__(self, "queue_enqueued_identities", identities)
        object.__setattr__(self, "queue_total_enqueued", normalized_ints["queue_total_enqueued"])
        object.__setattr__(self, "queue_last_feed_log", queue_last_feed_log)
        object.__setattr__(
            self,
            "raw_stage_progress_state",
            freeze_startup_progress_state(self.raw_stage_progress_state),
        )
        for field_name in (
            "process_count",
            "requested_process_count",
            "elastic_min_workers",
            "next_worker_spawn_id",
        ):
            object.__setattr__(self, field_name, normalized_ints[field_name])
        object.__setattr__(self, "dynamic_queue_feed", dynamic_queue_feed)
        object.__setattr__(self, "elastic_scheduler", elastic_scheduler)


__all__ = ("ProcessQueueStartupState",)
