"""Result-message ownership for the in-memory parent scheduler loop."""
from __future__ import annotations

import queue as _queue

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.orchestration.inmemory_parent_message import (
    handle_inmemory_parent_message,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_result_dispatch import (
    dispatch_inmemory_parent_result_message,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_result_evidence import (
    parent_result_continue_decision,
    parent_result_message_decision,
)
from Virus_Scan.scheduler.workers.inmemory_parent_message_evidence import (
    record_parent_worker_message_failure,
)


def _is_parent_result_message(message: object) -> bool:
    return parent_result_message_decision(message).is_parent_result


def _malformed_parent_result_log_message(message: object) -> str:
    return str.__add__(
        "in-memory scheduler ignored malformed result message type: ",
        no_hook_type_name(message),
    )


def _parent_result_message_validation_failed(
    *,
    msg: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> bool:
    try:
        message_decision = parent_result_message_decision(msg)
        if message_decision.is_parent_result:
            return bool(0)
        malformed_exc = RuntimeError("malformed parent worker result message")
        record_parent_worker_message_failure(
            operation="parent_result_malformed",
            message=msg,
            exc=malformed_exc,
        )
        log_error(_malformed_parent_result_log_message(msg))
        return True
    except recoverable_exceptions as exc:
        record_parent_worker_message_failure(
            operation="parent_result_validation",
            message=msg,
            exc=exc,
        )
        return True


def handle_next_inmemory_parent_result(
    *,
    result_queue: object,
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
) -> bool:
    """Handle at most one parent result message and return whether to continue."""
    try:
        msg = result_queue.get(timeout=0.25)
        queue_empty = False
    except _queue.Empty:
        msg = None
        queue_empty = True
    if queue_empty:
        return parent_result_continue_decision(
            should_continue=False,
            accepted=True,
            reason="parent_result_queue_empty",
        ).should_continue
    if _parent_result_message_validation_failed(
        msg=msg,
        recoverable_exceptions=recoverable_exceptions,
    ):
        return parent_result_continue_decision(
            should_continue=False,
            accepted=False,
            reason="parent_result_validation_failed",
        ).should_continue
    message_output = dispatch_inmemory_parent_result_message(
        msg=msg,
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
        started_at=started_at,
        progress_every=progress_every,
        throttle_sec=throttle_sec,
        result_retainer=result_retainer,
        derived_cache_writer=derived_cache_writer,
        recoverable_exceptions=recoverable_exceptions,
        parent_message_handler=handle_inmemory_parent_message,
    )
    return bool(message_output.should_continue)
