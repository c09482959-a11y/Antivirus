"""Immutable parent-side in-memory worker message contracts."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import monitor_recoverable_exceptions


@dataclass(frozen=True)
class InMemoryParentMessageRequest:
    message: object
    job_records: object
    active: object
    terminal: object
    failed: object
    done: object
    results: object
    recovery: object
    state_index: object
    root: object
    routing_evidence_context: object
    worker_heartbeats: object
    worker_metrics: object
    heartbeat_flags: object
    partial_output_path: object
    partial_output_every: int
    partial_writer: object
    started_at: float
    progress_every: int
    throttle_sec: float
    result_retainer: object
    derived_cache_writer: object
    wall_time: object
    sleep: object
    recoverable_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "recoverable_exceptions", monitor_recoverable_exceptions(self.recoverable_exceptions))


@dataclass(frozen=True)
class InMemoryParentMessageResult:
    handled: bool
    should_continue: bool
