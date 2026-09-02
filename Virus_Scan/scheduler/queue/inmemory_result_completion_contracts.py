"""Immutable contracts for one completed in-memory worker result."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, MutableMapping

from Virus_Scan.scheduler.queue.inmemory_result_completion_state import InMemoryResultMessageParts


@dataclass(frozen=True, slots=True)
class InMemoryCompletedResultPublicationRequest:
    """Canonical inputs for storing and publishing one completed result."""

    parts: InMemoryResultMessageParts
    record: dict[str, object]
    results: MutableMapping[object, object]
    recovery: object
    container_root: object
    routing_evidence_context: object
    routing_evidence_attacher: Callable[..., object]
    attach_result_evidence: Callable[..., object]
    publish_partial_results: Callable[..., object]
    partial_output_path: object
    partial_output_every: int
    partial_writer: Callable[..., object]
    partial_checkpoint_cache: object
    log_error: Callable[[str], object]
    bulk_scan_maintenance: Callable[[int], object]
    log_bulk_progress: Callable[..., object]
    started_at: float
    progress_every: int
    wall_time: Callable[[], float]
    job_records: MutableMapping[int, MutableMapping[str, object]]
    recoverable_exceptions: tuple[type[BaseException], ...]
    suppressed_recorder: Callable[[str, BaseException], object]
    result_retainer: Callable[[object, object], object]
    derived_cache_writer: Callable[[object], object]


@dataclass(frozen=True, slots=True)
class InMemoryCompletedResultDriverRequest:
    """Publication request plus the bounded parent throttle contract."""

    publication: InMemoryCompletedResultPublicationRequest
    throttle_sec: float
    sleep: Callable[[float], object]


__all__ = (
    "InMemoryCompletedResultDriverRequest",
    "InMemoryCompletedResultPublicationRequest",
)
