"""Worker-owned claim heartbeat thread lifecycle.

Queue ownership writes claim heartbeat sidecar metadata; worker ownership starts
and stops the bounded heartbeat thread for a claimed worker job.  The update
operation is supplied explicitly so this module does not mutate queue state or
own queue metadata persistence.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Event, Thread
from typing import Callable

from Virus_Scan.contracts.env_config import float_env
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_text


WORKER_CLAIM_HEARTBEAT_STOP_FAILED = False
_CLAIM_HEARTBEAT_REQUIRES_UPDATE_CALLBACK_OWNER = "claim heartbeat requires explicit update_callback owner"


@dataclass(frozen=True, slots=True)
class WorkerClaimHeartbeatHandle:
    """Immutable handle for a worker-owned claim heartbeat thread."""

    stop_event: Event
    thread: Thread
    interval_sec: float
    worker_id: str



def start_worker_claim_heartbeat(
    claim_path: object,
    *,
    job: object = None,
    worker_id: str = "worker",
    interval_sec: float | None = None,
    update_callback: Callable[..., bool] | None = None,
) -> WorkerClaimHeartbeatHandle:
    """Start a worker-owned heartbeat thread for a claimed queue job."""
    replacement_interval = float_env("UMIGE_QUEUE_HEARTBEAT_SEC", 5.0, 0.0, None)
    parsed_interval, _interval_reason = scheduler_float(
        interval_sec if interval_sec is not None else replacement_interval,
        default=replacement_interval,
        minimum=1.0,
        reason="worker_claim_heartbeat_interval_rejected",
        non_finite_reason="worker_claim_heartbeat_interval_non_finite",
    )
    interval = max(1.0, parsed_interval)
    safe_worker_id, _worker_id_reason = scheduler_text(
        worker_id,
        replacement_text="worker",
        unsupported_reason="worker_claim_heartbeat_worker_id_rejected",
    )
    safe_worker_id = safe_worker_id or "worker"
    if update_callback is None:
        raise RuntimeError(_CLAIM_HEARTBEAT_REQUIRES_UPDATE_CALLBACK_OWNER)
    stop = Event()
    update_callback(claim_path, job=job, worker_id=safe_worker_id)

    def _beat() -> None:
        while not stop.wait(interval):
            if not update_callback(claim_path, job=job, worker_id=safe_worker_id):
                break

    thread = Thread(target=_beat, name="umige_queue_job_heartbeat", daemon=True)
    thread.start()
    return WorkerClaimHeartbeatHandle(stop_event=stop, thread=thread, interval_sec=interval, worker_id=safe_worker_id)


def stop_worker_claim_heartbeat(handle: WorkerClaimHeartbeatHandle | None, *, timeout_sec: float = 2.0) -> bool:
    """Request heartbeat shutdown and perform a bounded worker-owned join."""
    if handle is None:
        return True
    if type(handle) is not WorkerClaimHeartbeatHandle:
        return WORKER_CLAIM_HEARTBEAT_STOP_FAILED
    stop_event = scheduler_exact_attr(handle, "stop_event", owner_type=WorkerClaimHeartbeatHandle)
    thread = scheduler_exact_attr(handle, "thread", owner_type=WorkerClaimHeartbeatHandle)
    if type(stop_event) is not Event or type(thread) is not Thread:
        return WORKER_CLAIM_HEARTBEAT_STOP_FAILED
    replacement_timeout = 2.0
    timeout, _reason = scheduler_float(
        timeout_sec,
        default=replacement_timeout,
        minimum=0.0,
        reason="worker_claim_heartbeat_timeout_rejected",
        non_finite_reason="worker_claim_heartbeat_timeout_non_finite",
    )
    stop_event.set()
    thread.join(timeout=timeout)
    return thread.is_alive() is False


__all__ = ("WorkerClaimHeartbeatHandle", "start_worker_claim_heartbeat", "stop_worker_claim_heartbeat")
