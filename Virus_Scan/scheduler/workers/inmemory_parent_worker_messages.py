"""Worker-owned handlers for parent-side in-memory worker messages."""
from __future__ import annotations



from Virus_Scan.runtime.api import log_error
from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.orchestration.inmemory_parent_message_contracts import (
    InMemoryParentMessageRequest,
    InMemoryParentMessageResult,
)
from Virus_Scan.scheduler.queue.inmemory_lifecycle_decisions import mark_retry_admitted_decision as _im_mark_retry_admitted_decision
from Virus_Scan.scheduler.workers.inmemory_parent_message_evidence import record_parent_worker_message_failure
from Virus_Scan.scheduler.workers.inmemory_parent_state import mark_worker_assigned_from_message, mark_worker_running_from_message
from Virus_Scan.scheduler.workers.inmemory_worker_exit import reconcile_inmemory_worker_exit
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_message import ingest_worker_heartbeat_message
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import (
    safe_parent_worker_message_identity,
    worker_lifecycle_exception_reason,
)


def handle_inmemory_assigned_worker_message(request: InMemoryParentMessageRequest) -> InMemoryParentMessageResult:
    msg = request.message
    try:
        assigned_applied = mark_worker_assigned_from_message(
            message=msg,
            job_records=request.job_records,
            active=request.active,
            terminal=request.terminal,
            mark_retry_admitted=_im_mark_retry_admitted_decision,
            lifecycle_recorder=request.recovery.record_lifecycle_request,
            state_index=request.state_index,
        )
        if not assigned_applied:
            record_parent_worker_message_failure(
                operation="assigned_rejected",
                message=msg,
                exc=RuntimeError("assigned worker message did not match active job state"),
            )
    except request.recoverable_exceptions as exc:
        record_parent_worker_message_failure(operation="assigned", message=msg, exc=exc)
        log_error("in-memory scheduler ignored bad assigned message: " + worker_lifecycle_exception_reason(exc))
        return InMemoryParentMessageResult(handled=True, should_continue=True)
    return InMemoryParentMessageResult(handled=True, should_continue=False)


def handle_inmemory_running_worker_message(request: InMemoryParentMessageRequest) -> InMemoryParentMessageResult:
    msg = request.message
    try:
        running_applied = mark_worker_running_from_message(
            message=msg,
            job_records=request.job_records,
            active=request.active,
            terminal=request.terminal,
            worker_heartbeats=request.worker_heartbeats,
            mark_retry_admitted=_im_mark_retry_admitted_decision,
            lifecycle_recorder=request.recovery.record_lifecycle_request,
            state_index=request.state_index,
        )
        if not running_applied:
            record_parent_worker_message_failure(
                operation="running_rejected",
                message=msg,
                exc=RuntimeError("running worker message did not match active job state"),
            )
    except request.recoverable_exceptions as exc:
        record_parent_worker_message_failure(operation="running", message=msg, exc=exc)
        log_error("in-memory scheduler ignored bad running message: " + worker_lifecycle_exception_reason(exc))
        return InMemoryParentMessageResult(handled=True, should_continue=True)
    return InMemoryParentMessageResult(handled=True, should_continue=False)


def handle_inmemory_heartbeat_worker_message(request: InMemoryParentMessageRequest) -> InMemoryParentMessageResult:
    msg = request.message
    try:
        heartbeat_applied = ingest_worker_heartbeat_message(
            message=msg,
            job_records=request.job_records,
            active=request.active,
            terminal=request.terminal,
            worker_heartbeats=request.worker_heartbeats,
            worker_metrics=request.worker_metrics,
            heartbeat_flags=request.heartbeat_flags,
            history_transition=request.recovery.replace_with_history_transition,
            cancel_job=request.recovery.request_cancel_only,
            lifecycle_recorder=request.recovery.record_lifecycle_request,
            wall_time=request.wall_time,
        )
        if not heartbeat_applied:
            record_parent_worker_message_failure(
                operation="heartbeat_rejected",
                message=msg,
                exc=RuntimeError("heartbeat worker message did not match active job state"),
            )
    except request.recoverable_exceptions as exc:
        record_parent_worker_message_failure(operation="heartbeat", message=msg, exc=exc)
        log_error("in-memory scheduler ignored bad heartbeat message: " + worker_lifecycle_exception_reason(exc))
        return InMemoryParentMessageResult(handled=True, should_continue=True)
    return InMemoryParentMessageResult(handled=True, should_continue=False)


def handle_inmemory_worker_exit_message(request: InMemoryParentMessageRequest) -> InMemoryParentMessageResult:
    msg = request.message
    try:
        exit_evidence = reconcile_inmemory_worker_exit(
            message=msg,
            active=request.active,
            terminal=request.terminal,
            retry_or_fail=request.recovery.retry_or_fail,
        )
        if exit_evidence.had_active_work:
            record_scheduler_suppressed(
                "inmemory_worker_exit_active_work",
                "inmemory worker exit had active work evidence",
            )
    except request.recoverable_exceptions as exc:
        record_parent_worker_message_failure(operation="worker_exit", message=msg, exc=exc)
        log_error("in-memory scheduler worker-exit reconciliation failed: " + worker_lifecycle_exception_reason(exc))
        return InMemoryParentMessageResult(handled=True, should_continue=True)
    return InMemoryParentMessageResult(handled=True, should_continue=False)


def record_unknown_inmemory_worker_message(message: object) -> InMemoryParentMessageResult:
    kind, preview = safe_parent_worker_message_identity(message)
    record_parent_worker_message_failure(
        operation="unknown_kind",
        message=message,
        exc=RuntimeError("unknown in-memory parent worker message kind=" + kind),
    )
    log_error("in-memory scheduler ignored unknown message kind=" + kind + " preview=" + preview)
    return InMemoryParentMessageResult(handled=False, should_continue=False)
