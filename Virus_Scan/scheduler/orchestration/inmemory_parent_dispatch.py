"""Dispatch-cycle ownership for the in-memory parent scheduler loop."""
from __future__ import annotations

import queue as _queue


from Virus_Scan.contracts.env_config import int_env
from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.evidence.inmemory_ewma import update_ewma
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.workers.inmemory_dispatch_backpressure import decide_inmemory_dispatch_backpressure
from Virus_Scan.scheduler.workers.inmemory_job_dispatch import InMemoryDispatchBatch, dispatch_ready_inmemory_jobs
from Virus_Scan.scheduler.queue.inmemory_lifecycle_decisions import mark_retry_admitted_decision as _im_mark_retry_admitted_decision


def _submitted_count(dispatch_batch: object) -> int:
    if type(dispatch_batch) is not InMemoryDispatchBatch:
        return 0
    submitted_value = scheduler_exact_attr(dispatch_batch, "submitted", owner_type=InMemoryDispatchBatch, default=0)
    submitted, _reason = scheduler_int(
        submitted_value,
        default=0,
        reason="inmemory_parent_dispatch_submitted_rejected",
    )
    return submitted


def dispatch_inmemory_parent_jobs(
    *,
    pending: object,
    job_records: object,
    terminal: object,
    task_queue: object,
    active: object,
    state_index: object,
    max_inflight: int,
    max_queued_unstarted: int,
    logical_slots: int,
    workers: int,
    recovery: object,
    ewma_state: object,
    now: object,
) -> int:
    """Dispatch ready jobs and return the number of newly submitted jobs."""
    heavy_cap = int_env('UMIGE_INMEMORY_HEAVY_INFLIGHT_WEIGHT', max(logical_slots * 3, workers * 8), 1, None)
    dispatch_batch = dispatch_ready_inmemory_jobs(
        pending=pending,
        job_records=job_records,
        terminal=terminal,
        task_queue=task_queue,
        state_index=state_index,
        max_inflight=max_inflight,
        max_queued_unstarted=max_queued_unstarted,
        logical_slots=logical_slots,
        workers=workers,
        heavy_cap=heavy_cap,
        decide_backpressure=lambda **kwargs: decide_inmemory_dispatch_backpressure(
                **kwargs,
                suppressed_recorder=lambda where, exc: record_scheduler_suppressed(where, exc),
            ),
        mark_retry_admitted=_im_mark_retry_admitted_decision,
        lifecycle_recorder=recovery.record_lifecycle_request,
        backpressure_recorder=lambda _reason: update_ewma('dispatch_backpressure', 1.0, state=ewma_state),
        queue_full_exception=_queue.Full,
        now=now,
    )
    return _submitted_count(dispatch_batch)
