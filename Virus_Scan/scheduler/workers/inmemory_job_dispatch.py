"""Worker-owned in-memory parent-to-worker dispatch boundary."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest, LifecycleRequestRecorder

from dataclasses import dataclass
from typing import Callable, MutableMapping, MutableSet

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_int, scheduler_text


@dataclass(frozen=True, slots=True)
class InMemoryDispatchBatch:
    submitted: int
    blocked: bool
    block_reason: str


@dataclass(frozen=True, slots=True)
class InMemoryDispatchRecordAttemptDecision:
    attempt: int
    reason: str
    accepted: bool

    def as_attempt(self) -> int:
        return self.attempt


@dataclass(frozen=True, slots=True)
class InMemoryDispatchRecordCostDecision:
    cost: dict[object, object] | None
    reason: str
    accepted: bool

    def as_cost(self) -> dict[object, object] | None:
        return self.cost


def _record_attempt_decision(record: object) -> InMemoryDispatchRecordAttemptDecision:
    if type(record) is not dict:
        return InMemoryDispatchRecordAttemptDecision(0, "inmemory_dispatch_record_missing", accepted=False)
    parsed, reason = scheduler_int(dict.get(record, "attempt", 0), default=0, minimum=0, reason="inmemory_dispatch_attempt_rejected")
    return InMemoryDispatchRecordAttemptDecision(parsed, reason, reason == "")



def _record_attempt(record: object) -> int:
    return _record_attempt_decision(record).as_attempt()


def _record_cost_decision(record: object) -> InMemoryDispatchRecordCostDecision:
    if type(record) is not dict:
        return InMemoryDispatchRecordCostDecision(None, "inmemory_dispatch_record_missing", accepted=False)
    cost = dict.get(record, "cost")
    if type(cost) is dict:
        return InMemoryDispatchRecordCostDecision(cost, "", accepted=True)
    reason = "inmemory_dispatch_cost_missing" if cost is None else "inmemory_dispatch_cost_rejected"
    return InMemoryDispatchRecordCostDecision(None, reason, accepted=False)



def _record_cost(record: object) -> dict[object, object] | None:
    return _record_cost_decision(record).as_cost()


def dispatch_ready_inmemory_jobs(*, pending: object, job_records: MutableMapping[int, MutableMapping[str, object]], terminal: MutableSet[int], task_queue: object, state_index: object, max_inflight: int, max_queued_unstarted: int, logical_slots: int, workers: int, heavy_cap: int, decide_backpressure: Callable[..., tuple[bool, str]], mark_retry_admitted: Callable[..., object], lifecycle_recorder: LifecycleRequestRecorder, backpressure_recorder: Callable[[str], object], queue_full_exception: type[BaseException], now: Callable[[], float]) -> InMemoryDispatchBatch:
    """Submit eligible pending jobs to worker IPC while preserving limits.

    Worker ownership controls parent-to-worker IPC submission while the caller
    retains queue state objects and lifecycle journal authority through explicit
    arguments.
    """
    submitted = 0
    blocked = False
    block_reason = ''
    while pending and state_index.logical_inflight_count() < max_inflight and state_index.queued_unstarted_count() < max_queued_unstarted:
        blocked, block_reason = decide_backpressure(active_heavy_weight=state_index.active_heavy_weight(), logical_slots=logical_slots, workers=workers, pressure_snapshot=())
        if blocked:
            block_reason_text, block_reason_issue = scheduler_text(block_reason, replacement_text='dispatch_backpressure')
            if block_reason_issue != '' or block_reason_text == '':
                block_reason = 'dispatch_backpressure'
            else:
                block_reason = block_reason_text
            backpressure_recorder(block_reason)
            break
        job_id, path, attempt = pending[0]
        safe_attempt, _ = scheduler_int(
            attempt,
            default=0,
            minimum=0,
            reason="inmemory_dispatch_attempt_rejected",
        )
        if job_id in terminal:
            pending.popleft()
            continue
        rec = job_records.get(job_id)
        if rec is not None and _record_attempt(rec) != safe_attempt:
            pending.popleft()
            continue
        cost = _record_cost(rec)
        if cost is not None:
            heavy, _heavy_reason = scheduler_bool(
                dict.get(cost, 'heavy'),
                default=False,
                reason="inmemory_dispatch_bool_rejected",
            )
        if cost is not None and heavy is True:
            weight, _ = scheduler_int(
                dict.get(cost, 'weight', 1),
                default=0,
                minimum=0,
                reason="inmemory_dispatch_attempt_rejected",
            )
            weight = weight or 1
            heavy_limit, _ = scheduler_int(
                heavy_cap,
                default=0,
                minimum=0,
                reason="inmemory_dispatch_attempt_rejected",
            )
            if state_index.active_heavy_weight() + weight > heavy_limit:
                blocked = True
                block_reason = 'heavy_inflight_cap'
                break
        try:
            task_queue.put((job_id, path, safe_attempt), timeout=0.05)
        except queue_full_exception:
            blocked = True
            block_reason = 'task_queue_full'
            break
        pending.popleft()
        if rec is not None:
            queued_at = now()
            rec['state'] = 'queued'
            rec['generation'] = safe_attempt
            rec['queued_at'] = queued_at
            rec['queued_timeout_armed_at'] = 0.0
            rec['pid'] = None
            mark_retry_admitted(rec, attempt=safe_attempt, now=queued_at)
            lifecycle_recorder(
                InMemoryLifecycleRecordRequest(
                    job_id=job_id,
                    attempt=safe_attempt,
                    transition="queued",
                    state="queued",
                )
            )
            state_index.sync_record(job_id, rec, due_at=queued_at)
        submitted += 1
    block_reason_text, block_reason_issue = scheduler_text(block_reason, replacement_text='')
    if block_reason_issue != '' or block_reason_text == '':
        block_reason_text = ''
    return InMemoryDispatchBatch(submitted, blocked, block_reason_text)
