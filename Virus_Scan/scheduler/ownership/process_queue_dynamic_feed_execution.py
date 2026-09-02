"""Execute one normalized process-queue dynamic feed step."""
from __future__ import annotations


from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_support import (
    feed_bool,
    feed_int,
)
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_execution_steps import (
    feed_decision_capacity,
    mark_dynamic_feed_complete_if_needed,
    publish_dynamic_feed_capacity,
    publish_dynamic_feed_remainder,
    record_dynamic_feed_failure,
    record_dynamic_feed_recovery_failure,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_contracts import (
        ProcessQueueDynamicFeedDependencies,
        ProcessQueueDynamicFeedRequest,
        ProcessQueueDynamicFeedState,
    )


def _log_feed(
    request: ProcessQueueDynamicFeedRequest,
    deps: ProcessQueueDynamicFeedDependencies,
    state: ProcessQueueDynamicFeedState,
    fed_now: int,
) -> None:
    file_active, _ = feed_int(
        dict.get(state.counts, "file_active", state.file_active_count),
        field_name="reported_file_active",
        default=state.file_active_count,
    )
    file_pending, _ = feed_int(
        dict.get(state.counts, "file_pending", state.file_pending_count),
        field_name="reported_file_pending",
        default=state.file_pending_count,
    )
    raw_pending, _ = feed_int(
        dict.get(state.counts, "raw_pending", 0),
        field_name="reported_raw_pending",
    )
    raw_active, _ = feed_int(
        dict.get(state.counts, "raw_active", 0),
        field_name="reported_raw_active",
    )
    sample_pressure, _ = feed_bool(
        scheduler_mapping_value(request.elastic_io_sample, "pressure"),
        field_name="sample_pressure",
    )
    metadata_latency, _ = feed_bool(
        scheduler_mapping_value(request.elastic_io_sample, "metadata_latency"),
        field_name="sample_metadata_latency",
    )
    disk_pressure, _ = feed_bool(
        scheduler_mapping_value(
            request.elastic_io_sample, "actual_disk_io_pressure"
        ),
        field_name="sample_actual_disk_pressure",
    )
    reason = scheduler_mapping_value(
        request.elastic_io_sample, "reason", default="n/a"
    )
    reason_text = reason if type(reason) is str else "n/a"
    cpu_text = "n/a" if state.cpu_sample is None else float.__format__(state.cpu_sample, ".1f") + "%"
    raw_count = raw_pending + raw_active if state.counts else state.raw_live
    deps.log_info(
        "bulk scan dynamic queue feed: added="
        + int.__str__(fed_now)
        + " enqueued="
        + int.__str__(state.queue_total_enqueued)
        + "/"
        + int.__str__(state.all_files_count)
        + " target_workers="
        + int.__str__(state.target_workers)
        + " files_active="
        + int.__str__(file_active)
        + " files_pending="
        + int.__str__(file_pending)
        + " raw_live="
        + int.__str__(raw_count)
        + " cpu="
        + str.__str__(cpu_text)
        + " io_pressure="
        + ("True" if sample_pressure else "False")
        + " io_reason="
        + str.__str__(reason_text)
        + " queue_metadata_latency="
        + ("True" if metadata_latency else "False")
        + " actual_disk_io_pressure="
        + ("True" if disk_pressure else "False")
    )


def execute_dynamic_feed(
    request: ProcessQueueDynamicFeedRequest,
    deps: ProcessQueueDynamicFeedDependencies,
    state: ProcessQueueDynamicFeedState,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    try:
        capacity = feed_decision_capacity(
            request,
            deps,
            state,
            recoverable_exceptions,
        )
        fed_now = publish_dynamic_feed_capacity(request, deps, state, capacity)
        if fed_now > 0 and state.current_time - state.queue_last_feed_log >= 15.0:
            _log_feed(request, deps, state, fed_now)
            state.queue_last_feed_log = state.current_time
        mark_dynamic_feed_complete_if_needed(request, deps, state)
    except recoverable_exceptions as exc:
        record_dynamic_feed_failure(request, deps, state, exc)
        try:
            remaining = publish_dynamic_feed_remainder(request, deps, state)
        except recoverable_exceptions as publish_exc:
            remaining = max(0, len(state.ordered_queue_items) - state.queue_feed_cursor)
            record_dynamic_feed_recovery_failure(
                request,
                deps,
                remaining,
                publish_exc,
            )


__all__ = ("execute_dynamic_feed",)
