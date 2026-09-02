"""Bounded execution steps for process-queue dynamic feed publication."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_exception_text,
    scheduler_int,
)
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_support import (
    record_feed_issue,
    safe_counts,
    safe_write_result,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_contracts import (
        ProcessQueueDynamicFeedDependencies,
        ProcessQueueDynamicFeedRequest,
        ProcessQueueDynamicFeedState,
    )


def feed_decision_capacity(
    request: ProcessQueueDynamicFeedRequest,
    deps: ProcessQueueDynamicFeedDependencies,
    state: ProcessQueueDynamicFeedState,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> int:
    policy = deps.build_feed_policy(
        materialize_scheduler_mapping(request.env),
        target_workers=state.target_workers,
        recoverable_exceptions=recoverable_exceptions,
    )
    decision = deps.decide_feed(
        target_workers=state.target_workers,
        file_active_count=state.file_active_count,
        file_pending_count=state.file_pending_count,
        io_pressure=state.io_pressure,
        policy=policy,
    )
    decision_state = no_hook_plain_instance_dict(decision)
    if decision_state is None:
        raise ValueError("process_queue_feed_decision_rejected")
    capacity, reason = scheduler_int(
        dict.get(decision_state, "feed_capacity"),
        default=0,
        minimum=0,
        reason="process_queue_feed_capacity_rejected",
    )
    if reason:
        raise ValueError(reason)
    return capacity


def publish_dynamic_feed_capacity(
    request: ProcessQueueDynamicFeedRequest,
    deps: ProcessQueueDynamicFeedDependencies,
    state: ProcessQueueDynamicFeedState,
    capacity: int,
) -> int:
    if capacity <= 0:
        return 0
    state.queue_feed_cursor, fed_now, _ = safe_write_result(
        deps.write_jobs_slice(
            request.queue_dir,
            state.ordered_queue_items,
            state.queue_feed_cursor,
            capacity,
            state.queue_enqueued_identities,
        )
    )
    state.queue_total_enqueued += fed_now
    if fed_now > 0:
        state.counts = safe_counts(deps.progress_counts(request.queue_dir))
    return fed_now


def mark_dynamic_feed_complete_if_needed(
    request: ProcessQueueDynamicFeedRequest,
    deps: ProcessQueueDynamicFeedDependencies,
    state: ProcessQueueDynamicFeedState,
) -> None:
    if state.queue_feed_cursor >= len(state.ordered_queue_items):
        deps.mark_feed_complete(request.queue_dir)


def record_dynamic_feed_failure(
    request: ProcessQueueDynamicFeedRequest,
    deps: ProcessQueueDynamicFeedDependencies,
    state: ProcessQueueDynamicFeedState,
    exc: BaseException,
) -> None:
    deps.log_error(
        "dynamic process queue feed failed: " + scheduler_exception_text(exc)
    )
    record_feed_issue(
        deps,
        "process_queue_dynamic_feed_failed",
        "dynamic process queue feed failed",
        queue_dir=request.queue_dir,
        extra={
            "cursor": state.queue_feed_cursor,
            "error": scheduler_exception_text(exc),
        },
    )


def publish_dynamic_feed_remainder(
    request: ProcessQueueDynamicFeedRequest,
    deps: ProcessQueueDynamicFeedDependencies,
    state: ProcessQueueDynamicFeedState,
) -> int:
    remaining = max(0, len(state.ordered_queue_items) - state.queue_feed_cursor)
    if remaining > 0:
        state.queue_feed_cursor, fed_now, _ = safe_write_result(
            deps.write_jobs_slice(
                request.queue_dir,
                state.ordered_queue_items,
                state.queue_feed_cursor,
                remaining,
                state.queue_enqueued_identities,
            )
        )
        state.queue_total_enqueued += fed_now
    deps.mark_feed_complete(request.queue_dir)
    return remaining


def record_dynamic_feed_recovery_failure(
    request: ProcessQueueDynamicFeedRequest,
    deps: ProcessQueueDynamicFeedDependencies,
    remaining: int,
    publish_exc: BaseException,
) -> None:
    record_feed_issue(
        deps,
        "process_queue_dynamic_feed_publish_failed",
        "dynamic feed recovery publication failed",
        queue_dir=request.queue_dir,
        extra={
            "remaining": remaining,
            "error": scheduler_exception_text(publish_exc),
        },
    )


__all__ = (
    "feed_decision_capacity",
    "mark_dynamic_feed_complete_if_needed",
    "publish_dynamic_feed_capacity",
    "publish_dynamic_feed_remainder",
    "record_dynamic_feed_failure",
    "record_dynamic_feed_recovery_failure",
)
