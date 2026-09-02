"""No-hook process-queue child heartbeat shutdown boundary."""
from __future__ import annotations


from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.workers.claim_heartbeat import WorkerClaimHeartbeatHandle
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import worker_lifecycle_exception_reason
from Virus_Scan.scheduler.workers.ipc_lifecycle import stop_worker_heartbeat



def process_queue_child_heartbeat_parts(handle: object) -> tuple[object, object, str]:
    """Return exact child heartbeat resources without caller-owned attribute hooks."""
    if handle is None:
        return None, None, ""
    if type(handle) is not WorkerClaimHeartbeatHandle:
        return None, None, "process_queue_child_heartbeat_handle_rejected"
    stop_event = scheduler_exact_attr(handle, "stop_event", owner_type=WorkerClaimHeartbeatHandle)
    thread = scheduler_exact_attr(handle, "thread", owner_type=WorkerClaimHeartbeatHandle)
    if stop_event is None or thread is None:
        return None, None, "process_queue_child_heartbeat_handle_unavailable"
    return stop_event, thread, ""


def stop_process_queue_child_heartbeat(
    handle: object, *, join_timeout: float = 1.0, failure_recorder: object = None
) -> dict[str, object]:
    """Stop a child-job heartbeat handle without traversing hostile handle objects."""
    status: dict[str, object] = {"signalled": False, "joined": False, "alive": False, "error": ""}
    stop_event, thread, reason = process_queue_child_heartbeat_parts(handle)
    if reason:
        status["error"] = reason
        if callable(failure_recorder):
            try:
                failure_recorder("process_queue_child_heartbeat_handle_rejected", RuntimeError(reason))
            except RECOVERABLE_RUNTIME_ERRORS as recorder_exc:
                status["recorder_error"] = worker_lifecycle_exception_reason(recorder_exc)
        return status
    return stop_worker_heartbeat(
        stop_event,
        thread,
        join_timeout=join_timeout,
        failure_recorder=failure_recorder,
    )


__all__ = (
    "process_queue_child_heartbeat_parts",
    "stop_process_queue_child_heartbeat",
)
