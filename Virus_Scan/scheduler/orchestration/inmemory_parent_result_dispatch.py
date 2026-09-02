"""Dispatch a validated in-memory parent result message."""
from __future__ import annotations

import time
from typing import Callable

from Virus_Scan.scheduler.orchestration.inmemory_parent_message import (
    InMemoryParentMessageRequest,
    InMemoryParentMessageResult,
    handle_inmemory_parent_message,
)
from Virus_Scan.publication.api import write_partial_scan_results


def dispatch_inmemory_parent_result_message(
    *,
    msg: object,
    job_records: object,
    active: object,
    terminal: object,
    failed: object,
    done: object,
    results: object,
    recovery: object,
    state_index: object,
    root: object,
    routing_evidence_context: object,
    worker_heartbeats: object,
    worker_metrics: object,
    heartbeat_flags: object,
    partial_output_path: object,
    partial_output_every: int,
    started_at: float,
    progress_every: int,
    throttle_sec: float,
    result_retainer: object,
    derived_cache_writer: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
    parent_message_handler: Callable[
        [InMemoryParentMessageRequest],
        InMemoryParentMessageResult,
    ] = handle_inmemory_parent_message,
) -> object:
    return parent_message_handler(
        InMemoryParentMessageRequest(
            message=msg,
            job_records=job_records,
            active=active,
            terminal=terminal,
            failed=failed,
            done=done,
            results=results,
            recovery=recovery,
            state_index=state_index,
            root=root,
            routing_evidence_context=routing_evidence_context,
            worker_heartbeats=worker_heartbeats,
            worker_metrics=worker_metrics,
            heartbeat_flags=heartbeat_flags,
            partial_output_path=partial_output_path,
            partial_output_every=partial_output_every,
            partial_writer=write_partial_scan_results,
            started_at=started_at,
            progress_every=progress_every,
            throttle_sec=throttle_sec,
            result_retainer=result_retainer,
            derived_cache_writer=derived_cache_writer,
            wall_time=time.time,
            sleep=time.sleep,
            recoverable_exceptions=recoverable_exceptions,
        )
    )


__all__ = ("dispatch_inmemory_parent_result_message",)
