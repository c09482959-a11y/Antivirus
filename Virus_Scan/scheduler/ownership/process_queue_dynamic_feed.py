"""Canonical bounded process-queue dynamic feed entrypoint."""
from __future__ import annotations

from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_contracts import (
    ProcessQueueDynamicFeedDependencies,
    ProcessQueueDynamicFeedOutput,
    ProcessQueueDynamicFeedRequest,
)
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_execution import (
    execute_dynamic_feed,
)
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_normalization import (
    normalize_dynamic_feed_request,
)
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed_support import (
    record_feed_issue,
)


def advance_process_queue_dynamic_feed(
    request: ProcessQueueDynamicFeedRequest,
    deps: ProcessQueueDynamicFeedDependencies,
) -> ProcessQueueDynamicFeedOutput:
    """Validate, advance, and return immutable queue ownership state."""
    if type(request) is not ProcessQueueDynamicFeedRequest:
        exception_message = "process queue dynamic feed request must use the canonical contract"
        raise TypeError(exception_message)
    if type(deps) is not ProcessQueueDynamicFeedDependencies:
        exception_message = "process queue dynamic feed dependencies must use the canonical contract"
        raise TypeError(exception_message)
    state, issues = normalize_dynamic_feed_request(request)
    if issues:
        record_feed_issue(
            deps,
            "process_queue_dynamic_feed_input_rejected",
            "dynamic feed request contained rejected values",
            queue_dir=request.queue_dir,
            extra={"issues": issues},
        )
    if not state.enabled or state.queue_feed_cursor >= len(state.ordered_queue_items):
        return state.output()
    execute_dynamic_feed(
        request,
        deps,
        state,
        deps.recoverable_exceptions,
    )
    return state.output()


__all__ = (
    "ProcessQueueDynamicFeedDependencies",
    "ProcessQueueDynamicFeedOutput",
    "ProcessQueueDynamicFeedRequest",
    "advance_process_queue_dynamic_feed",
)
