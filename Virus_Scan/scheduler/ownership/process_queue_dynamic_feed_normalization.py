"""Normalize process-queue dynamic feed inputs before execution."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_contracts import (
    ProcessQueueDynamicFeedRequest,
    ProcessQueueDynamicFeedState,
)
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_normalization_steps import (
    normalize_dynamic_feed_counts,
    normalize_dynamic_feed_identities,
    normalize_dynamic_feed_ordered_items,
    normalize_dynamic_feed_scalars,
)


def normalize_dynamic_feed_request(
    request: ProcessQueueDynamicFeedRequest,
) -> tuple[ProcessQueueDynamicFeedState, tuple[Mapping[str, object], ...]]:
    """Normalize dynamic-feed request fields into a replayable state object."""
    values, issues = normalize_dynamic_feed_counts(request)
    scalars, scalar_issues = normalize_dynamic_feed_scalars(request)
    ordered_items, ordered_issues = normalize_dynamic_feed_ordered_items(request)
    identities, identity_issues = normalize_dynamic_feed_identities(request)
    issues += scalar_issues + ordered_issues + identity_issues
    return ProcessQueueDynamicFeedState(
        enabled=scalars["enabled"],
        ordered_queue_items=ordered_items,
        queue_feed_cursor=values["cursor"],
        queue_total_enqueued=values["total_enqueued"],
        queue_enqueued_identities=identities,
        queue_last_feed_log=scalars["last_log"],
        target_workers=values["target_workers"],
        file_active_count=values["file_active_count"],
        file_pending_count=values["file_pending_count"],
        io_pressure=scalars["io_pressure"],
        cpu_sample=scalars["cpu_sample"],
        all_files_count=values["all_files_count"],
        raw_live=values["raw_live"],
        current_time=scalars["current_time"],
        counts={},
    ), issues


__all__ = ("normalize_dynamic_feed_request",)
