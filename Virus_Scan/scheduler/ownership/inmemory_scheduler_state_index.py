"""Transition-owned counters and deadline index for one in-memory scheduler run."""
from __future__ import annotations

from dataclasses import dataclass, field
import heapq
import math

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int

_LIVE_STATES = frozenset(("queued", "assigned", "running"))
_ACTIVE_STATES = frozenset(("assigned", "running"))
_MISSING = object()


def _record_state(record: object) -> str:
    items = no_hook_mapping_items(record)
    value = scheduler_mapping_item_value(items, "state", _MISSING)
    return str.__str__(value) if type(value) is str else ""


def _record_heavy_weight(record: object) -> int:
    items = no_hook_mapping_items(record)
    cost = scheduler_mapping_item_value(items, "cost", _MISSING)
    cost_items = no_hook_mapping_items(cost)
    if cost_items is None:
        return 0
    heavy = scheduler_mapping_item_value(cost_items, "heavy", False)
    if type(heavy) is bool:
        is_heavy = heavy
    elif type(heavy) is int and type(heavy) is not bool:
        is_heavy = heavy != 0
    else:
        is_heavy = False
    if not is_heavy:
        return 0
    raw_weight = scheduler_mapping_item_value(cost_items, "weight", 1)
    weight, reason = scheduler_int(
        raw_weight,
        default=0,
        minimum=0,
        reason="inmemory_state_index_heavy_weight_rejected",
    )
    if reason != "":
        return 0
    return weight or 1


def _deadline_value(value: object) -> float | None:
    parsed, reason = scheduler_float(
        value,
        default=0.0,
        minimum=0.0,
        reason="inmemory_state_index_deadline_rejected",
        non_finite_reason="inmemory_state_index_deadline_non_finite",
    )
    if reason != "" or not math.isfinite(parsed):
        return None
    return parsed


@dataclass(slots=True)
class InMemorySchedulerStateIndex:
    """Own O(1) live-state counters and O(log N + due) timeout deadlines."""

    _state_by_job: dict[int, str] = field(default_factory=dict)
    _heavy_weight_by_job: dict[int, int] = field(default_factory=dict)
    _active_job_ids: set[int] = field(default_factory=set)
    _deadline_token_by_job: dict[int, int] = field(default_factory=dict)
    _deadline_heap: list[tuple[float, int, int]] = field(default_factory=list)
    _queued_unstarted: int = 0
    _active: int = 0
    _active_heavy_weight: int = 0
    _token_sequence: int = 0

    def queued_unstarted_count(self) -> int:
        return self._queued_unstarted

    def logical_inflight_count(self) -> int:
        return self._active

    def queued_or_active_count(self) -> int:
        return self._queued_unstarted + self._active

    def active_heavy_weight(self) -> int:
        return self._active_heavy_weight

    def active_job_ids(self) -> tuple[int, ...]:
        return tuple(sorted(self._active_job_ids))

    def indexed_job_count(self) -> int:
        return len(self._state_by_job)

    def pending_deadline_count(self) -> int:
        return len(self._deadline_token_by_job)

    def _apply_counter_delta(self, job_id: int, old_state: str, new_state: str, new_heavy_weight: int) -> None:
        old_heavy_weight = self._heavy_weight_by_job.get(job_id, 0)
        if old_state == "queued":
            self._queued_unstarted -= 1
        elif old_state in _ACTIVE_STATES:
            self._active -= 1
            self._active_heavy_weight -= old_heavy_weight
            self._active_job_ids.discard(job_id)
        if new_state == "queued":
            self._queued_unstarted += 1
        elif new_state in _ACTIVE_STATES:
            self._active += 1
            self._active_heavy_weight += new_heavy_weight
            self._active_job_ids.add(job_id)
        if self._queued_unstarted < 0 or self._active < 0 or self._active_heavy_weight < 0:
            raise RuntimeError("inmemory_scheduler_state_index_counter_underflow")

    def sync_record(self, job_id: object, record: object, *, due_at: object | None = None) -> None:
        safe_job_id, reason = scheduler_int(
            job_id,
            default=-1,
            minimum=0,
            reason="inmemory_state_index_job_id_rejected",
        )
        if reason != "":
            raise ValueError(reason)
        new_state = _record_state(record)
        old_state = self._state_by_job.get(safe_job_id, "")
        new_heavy_weight = _record_heavy_weight(record) if new_state in _ACTIVE_STATES else 0
        self._apply_counter_delta(safe_job_id, old_state, new_state, new_heavy_weight)
        if new_state in _LIVE_STATES:
            self._state_by_job[safe_job_id] = new_state
            if new_state in _ACTIVE_STATES:
                self._heavy_weight_by_job[safe_job_id] = new_heavy_weight
            else:
                self._heavy_weight_by_job.pop(safe_job_id, None)
            if due_at is not None:
                self.schedule_at(safe_job_id, due_at)
        else:
            self._state_by_job.pop(safe_job_id, None)
            self._heavy_weight_by_job.pop(safe_job_id, None)
            self._active_job_ids.discard(safe_job_id)
            self.invalidate_deadline(safe_job_id)

    def schedule_at(self, job_id: object, due_at: object) -> None:
        safe_job_id, reason = scheduler_int(
            job_id,
            default=-1,
            minimum=0,
            reason="inmemory_state_index_job_id_rejected",
        )
        if reason != "":
            raise ValueError(reason)
        deadline = _deadline_value(due_at)
        if deadline is None:
            raise ValueError("inmemory_state_index_deadline_rejected")
        if safe_job_id not in self._state_by_job:
            return
        self._token_sequence += 1
        token = self._token_sequence
        self._deadline_token_by_job[safe_job_id] = token
        heapq.heappush(self._deadline_heap, (deadline, safe_job_id, token))

    def invalidate_deadline(self, job_id: object) -> None:
        safe_job_id, reason = scheduler_int(
            job_id,
            default=-1,
            minimum=0,
            reason="inmemory_state_index_job_id_rejected",
        )
        if reason != "":
            return
        self._deadline_token_by_job.pop(safe_job_id, None)

    def pop_due(self, now: object) -> tuple[int, ...]:
        safe_now = _deadline_value(now)
        if safe_now is None:
            raise ValueError("inmemory_state_index_now_rejected")
        due: list[int] = []
        while self._deadline_heap and self._deadline_heap[0][0] <= safe_now:
            _deadline, job_id, token = heapq.heappop(self._deadline_heap)
            if self._deadline_token_by_job.get(job_id) != token:
                continue
            if job_id not in self._state_by_job:
                self._deadline_token_by_job.pop(job_id, None)
                continue
            self._deadline_token_by_job.pop(job_id, None)
            due.append(job_id)
        return tuple(due)


__all__ = ("InMemorySchedulerStateIndex",)
