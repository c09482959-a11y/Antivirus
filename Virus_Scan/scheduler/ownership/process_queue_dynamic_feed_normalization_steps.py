"""Bounded no-hook normalization steps for process-queue dynamic feed input."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_contracts import (
    ProcessQueueDynamicFeedRequest,
)
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_support import (
    feed_bool,
    feed_float,
    feed_int,
    feed_issue,
)


def normalize_dynamic_feed_counts(
    request: ProcessQueueDynamicFeedRequest,
) -> tuple[dict[str, int], tuple[Mapping[str, object], ...]]:
    """Normalize integer count fields for the dynamic-feed contract."""
    issues: tuple[Mapping[str, object], ...] = ()
    values: dict[str, int] = {}
    for field_name, raw_value in (
        ("cursor", request.queue_feed_cursor),
        ("total_enqueued", request.queue_total_enqueued),
        ("target_workers", request.target_workers),
        ("file_active_count", request.file_active_count),
        ("file_pending_count", request.file_pending_count),
        ("all_files_count", request.all_files_count),
        ("raw_live", request.raw_live),
    ):
        value, issue = feed_int(raw_value, field_name=field_name)
        values[field_name] = value
        issues += issue
    return values, issues


def normalize_dynamic_feed_scalars(
    request: ProcessQueueDynamicFeedRequest,
) -> tuple[dict[str, object], tuple[Mapping[str, object], ...]]:
    """Normalize boolean/float scalar fields for the dynamic-feed contract."""
    issues: tuple[Mapping[str, object], ...] = ()
    enabled, issue = feed_bool(request.enabled, field_name="enabled")
    issues += issue
    io_pressure, issue = feed_bool(request.io_pressure, field_name="io_pressure")
    issues += issue
    last_log, issue = feed_float(
        request.queue_last_feed_log,
        field_name="last_feed_log",
    )
    issues += issue
    current_time, issue = feed_float(
        request.current_time,
        field_name="current_time",
    )
    issues += issue
    cpu_sample = None
    if request.cpu_sample is not None:
        cpu_sample, issue = feed_float(request.cpu_sample, field_name="cpu_sample")
        issues += issue
    return {
        "enabled": enabled,
        "io_pressure": io_pressure,
        "last_log": last_log,
        "current_time": current_time,
        "cpu_sample": cpu_sample,
    }, issues


def normalize_dynamic_feed_ordered_items(
    request: ProcessQueueDynamicFeedRequest,
) -> tuple[tuple[object, ...], tuple[Mapping[str, object], ...]]:
    """Normalize ordered queue items without calling caller-owned iterators."""
    if type(request.ordered_queue_items) in (tuple, list):
        return no_hook_sequence_items(request.ordered_queue_items), ()
    return (), (
        feed_issue(
            "ordered_queue_items",
            request.ordered_queue_items,
            "process_queue_feed_ordered_items_rejected",
        ),
    )


def normalize_dynamic_feed_identities(
    request: ProcessQueueDynamicFeedRequest,
) -> tuple[set[str], tuple[Mapping[str, object], ...]]:
    """Normalize already-enqueued identities to exact strings only."""
    issues: tuple[Mapping[str, object], ...] = ()
    if type(request.queue_enqueued_identities) in (tuple, list, set, frozenset):
        identity_values = no_hook_sequence_items(request.queue_enqueued_identities)
    else:
        identity_values = ()
        issues += (
            feed_issue(
                "queue_enqueued_identities",
                request.queue_enqueued_identities,
                "process_queue_feed_identities_rejected",
            ),
        )
    identities: set[str] = set()
    for index, identity in enumerate(identity_values):
        if type(identity) is str and identity:
            identities.add(str.__str__(identity))
        else:
            issues += (
                feed_issue(
                    "queue_enqueued_identities[" + int.__str__(index) + "]",
                    identity,
                    "process_queue_feed_identity_rejected",
                ),
            )
    return identities, issues


__all__ = (
    "normalize_dynamic_feed_counts",
    "normalize_dynamic_feed_identities",
    "normalize_dynamic_feed_ordered_items",
    "normalize_dynamic_feed_scalars",
)
