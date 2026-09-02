"""Bounded publication/throttle driver for in-memory result completion."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_result_completion_contracts import (
    InMemoryCompletedResultDriverRequest,
)
from Virus_Scan.scheduler.queue.inmemory_result_completion_publication import (
    store_publish_and_maintain_completed_result,
)
from Virus_Scan.scheduler.queue.inmemory_result_completion_state import sleep_for_throttle


def publish_completed_result_and_apply_throttle(
    request: InMemoryCompletedResultDriverRequest,
) -> bool:
    """Publish one completed result and return whether throttle sleep ran."""
    store_publish_and_maintain_completed_result(request.publication)
    return sleep_for_throttle(
        throttle_sec=request.throttle_sec,
        sleep=request.sleep,
    )


__all__ = ("publish_completed_result_and_apply_throttle",)
