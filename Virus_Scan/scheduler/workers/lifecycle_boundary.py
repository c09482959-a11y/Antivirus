"""Immutable worker lifecycle transition boundary."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping
import threading

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.runtime.api import RuntimeStateReducer, RuntimeTransition, append_provenance_event, stable_digest
from Virus_Scan.scheduler.internal.immutable_materialization import materialize_scheduler_mapping_decision
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_int

_VALID_WORKER_LIFECYCLE_TRANSITIONS = MappingProxyType({
    "new": frozenset({"queued", "failed"}),
    "queued": frozenset({"claimed", "cancelled", "failed"}),
    "claimed": frozenset({"running", "cancelled", "failed"}),
    "running": frozenset({"completed", "cancelled", "failed"}),
    "cancelled": frozenset(),
    "completed": frozenset(),
    "failed": frozenset(),
})

def _lifecycle_text(value: object, *, field_name: str, replacement_text: str = "") -> tuple[str, tuple[tuple[str, object], ...]]:
    safe_field_name = str.__str__(field_name) if type(field_name) is str and field_name else "field"
    safe_replacement = str.__str__(replacement_text) if type(replacement_text) is str else ""
    text, reason = scheduler_text(
        value,
        replacement_text=safe_replacement,
        unsupported_reason=str.__add__(str.__add__("worker_lifecycle_", safe_field_name), "_rejected"),
    )
    if reason == "":
        return text, ()
    return safe_replacement, ((safe_field_name, unsupported_scheduler_value_evidence(value, field_name=safe_field_name)),)

def _lifecycle_int(value: object, *, field_name: str, replacement_value: int = 0) -> tuple[int, tuple[tuple[str, object], ...]]:
    safe_field_name = str.__str__(field_name) if type(field_name) is str and field_name else "field"
    number, reason = worker_int(value, replacement=replacement_value, reason='rejected', minimum=0)
    if reason == "":
        return number, ()
    return number, ((safe_field_name, unsupported_scheduler_value_evidence(value, field_name=safe_field_name)),)

def _canonical_input_rejections(event: Mapping[str, object]) -> tuple[object, ...]:
    frozen_decision = frozen_scheduler_items_decision(event)
    items = frozen_decision.items if frozen_decision.accepted else None
    if items is None:
        items = no_hook_mapping_items(event)
    if items is None:
        return (unsupported_scheduler_value_evidence(event, field_name="worker_lifecycle_event"),)
    matches = tuple(value for key, value in items if key == "input_rejections")
    if not matches:
        return ()
    raw_rejections = matches[0]
    if type(raw_rejections) is tuple:
        return raw_rejections
    if type(raw_rejections) is list:
        return tuple(raw_rejections)
    return (unsupported_scheduler_value_evidence(raw_rejections, field_name="input_rejections"),)
def _event_from_mapping(event: Mapping[str, object]) -> tuple["WorkerLifecycleEvent", tuple[tuple[str, object], ...]]:
    items = no_hook_mapping_items(event)
    if items is None:
        evidence = unsupported_scheduler_value_evidence(event, field_name="worker_lifecycle_event")
        return WorkerLifecycleEvent("", "", "new", "new", "", 0), (("event", evidence),)
    data = scheduler_str_key_mapping_from_items(items)
    ignored = tuple(
        (str.__add__("unsupported_key_", int.__str__(index)), unsupported_scheduler_value_evidence(key, field_name=str.__add__("worker_lifecycle_key_", int.__str__(index))))
        for index, (key, _value) in enumerate(items)
        if type(key) is not str
    )
    return WorkerLifecycleEvent(
        dict.get(data, "worker_id", ""),
        dict.get(data, "queue_id", ""),
        dict.get(data, "from_state", "new"),
        dict.get(data, "to_state", "new"),
        dict.get(data, "reason", ""),
        dict.get(data, "retry_generation", 0),
    ), ignored

@dataclass(frozen=True)
class WorkerLifecycleEvent:
    worker_id: str
    queue_id: str
    from_state: str
    to_state: str
    reason: str = ""
    retry_generation: int = 0

    def canonical(self) -> Mapping[str, object]:
        rejections: list[tuple[str, object]] = []
        worker_id, rejected = _lifecycle_text(self.worker_id, field_name="worker_id")
        rejections.extend(rejected)
        queue_id, rejected = _lifecycle_text(self.queue_id, field_name="queue_id")
        rejections.extend(rejected)
        from_state, rejected = _lifecycle_text(self.from_state, field_name="from_state", replacement_text="new")
        rejections.extend(rejected)
        to_state, rejected = _lifecycle_text(self.to_state, field_name="to_state", replacement_text="new")
        rejections.extend(rejected)
        reason, rejected = _lifecycle_text(self.reason, field_name="reason")
        rejections.extend(rejected)
        retry_generation, rejected = _lifecycle_int(self.retry_generation, field_name="retry_generation")
        rejections.extend(rejected)
        payload: dict[str, object] = {
            "worker_id": worker_id,
            "queue_id": queue_id,
            "from_state": from_state,
            "to_state": to_state,
            "reason": reason,
            "retry_generation": retry_generation,
        }
        if rejections:
            payload["input_rejections"] = tuple(value for _field_name, value in rejections)
        return immutable_mapping(payload)

    @property
    def fingerprint(self) -> str:
        return stable_digest("worker_lifecycle", self.canonical())

class SchedulerIsolationBoundary:
    """Worker-authority lifecycle boundary with immutable transition history."""

    def __init__(self, *, scheduler_id: str = "scheduler") -> None:
        scheduler_text_value, _reason = scheduler_text(
            scheduler_id,
            replacement_text="scheduler",
            unsupported_reason="worker_lifecycle_scheduler_id_rejected",
        )
        self.scheduler_id = scheduler_text_value if scheduler_text_value != "" else "scheduler"
        self._scheduler_id_rejections = (unsupported_scheduler_value_evidence(scheduler_id, field_name="scheduler_id"),) if _reason else ()
        self._lock = threading.RLock()
        self._states: tuple[tuple[str, str], ...] = ()
        self._reducer = RuntimeStateReducer(owner=str.__add__("scheduler:", self.scheduler_id))

    @staticmethod
    def _state_replace(states: tuple[tuple[str, str], ...], queue_id: str, state: str) -> tuple[tuple[str, str], ...]:
        replaced = False
        updated = []
        for qid, old_state in states:
            updated.append((queue_id, state) if qid == queue_id else (qid, old_state))
            replaced = replaced or qid == queue_id
        if not replaced:
            updated.append((queue_id, state))
        return tuple(updated)

    def transition(self, event: WorkerLifecycleEvent | Mapping[str, object]) -> Mapping[str, object]:
        map_rejections: tuple[tuple[str, object], ...] = ()
        if not isinstance(event, WorkerLifecycleEvent):
            event, map_rejections = _event_from_mapping(event)
        ev = event.canonical()
        rejections = self._scheduler_id_rejections + _canonical_input_rejections(ev) + tuple(value for _key, value in map_rejections)
        if rejections:
            return immutable_mapping({"event_type": "worker_lifecycle", "scheduler_id": self.scheduler_id, "status": "rejected", "input_rejections": rejections})
        qid = _lifecycle_text(ev["queue_id"], field_name="queue_id")[0]
        reason = _lifecycle_text(ev["reason"], field_name="reason")[0]
        from_state = _lifecycle_text(ev["from_state"], field_name="from_state", replacement_text="new")[0]
        to_state = _lifecycle_text(ev["to_state"], field_name="to_state", replacement_text="new")[0]
        transition = RuntimeTransition(owner=str.__add__("scheduler:", self.scheduler_id), action="set", key=qid, value=ev, reason=reason)
        fingerprint = event.fingerprint
        with self._lock:
            current = next((state for state_qid, state in self._states if state_qid == qid), "new")
            if from_state != current:
                raise RuntimeError("scheduler state mismatch for " + str.__str__(qid) + ": expected " + str.__str__(current) + ", got " + str.__str__(from_state))
            if to_state not in _VALID_WORKER_LIFECYCLE_TRANSITIONS.get(current, frozenset()):
                raise RuntimeError("invalid scheduler transition " + str.__str__(current) + "->" + str.__str__(to_state) + " for " + str.__str__(qid))
            self._states = self._state_replace(self._states, qid, to_state)
            record = immutable_mapping({"event_type": "worker_lifecycle", "scheduler_id": self.scheduler_id, "event": ev, "fingerprint": fingerprint})
        self._reducer.apply(transition)
        materialized_record = materialize_scheduler_mapping_decision(record).value
        if type(materialized_record) is dict:
            append_provenance_event(scheduler_str_key_mapping_from_items(no_hook_mapping_items(materialized_record)))
        else:
            append_provenance_event({
                "event_type": "worker_lifecycle",
                "scheduler_id": self.scheduler_id,
                "status": "provenance_materialization_rejected",
                "record": unsupported_scheduler_value_evidence(record, field_name="worker_lifecycle_record"),
            })
        return record

    def state_of(self, queue_id: str) -> str:
        qid, reason = scheduler_text(queue_id, replacement_text="", unsupported_reason="worker_lifecycle_queue_id_rejected")
        if reason:
            raise ValueError("worker lifecycle queue_id rejected: " + no_hook_type_name(queue_id))
        with self._lock:
            return next((state for state_qid, state in self._states if state_qid == qid), "new")

    def snapshot(self) -> Mapping[str, object]:
        with self._lock:
            return immutable_mapping({"scheduler_id": self.scheduler_id, "states": immutable_mapping(tuple(sorted(self._states))), "history": self._reducer.canonical_history()})
