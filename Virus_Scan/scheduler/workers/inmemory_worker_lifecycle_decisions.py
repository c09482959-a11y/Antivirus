"""Replayable in-memory worker lifecycle boundary decisions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text, scheduler_value_snapshot
from Virus_Scan.scheduler.internal.immutable_snapshots import immutable_snapshot_mapping

_DECISION_TRUE = bool(1)
_DECISION_FALSE = bool(0)
_PRE_EXECUTION_STAGE_TOKENS = ("start", "assigned", "budget", "cache_lookup", "prefilter", "type_scan")


@dataclass(frozen=True, slots=True)
class WorkerLifecycleBooleanDecision:
    """Typed replayable decision for worker lifecycle boolean projections."""

    value: bool
    reason: str
    evidence: tuple[Mapping[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class WorkerFutureTupleDecision:
    """Typed replayable decision for live worker future tuple projections."""

    items: tuple[object, ...]
    reason: str
    evidence: tuple[Mapping[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class WorkerHeartbeatItemsDecision:
    """Typed replayable decision for active worker heartbeat item projections."""

    items: tuple[tuple[object, object], ...]
    reason: str
    evidence: tuple[Mapping[str, object], ...] = ()


def _worker_evidence(reason: str, *, field: str, value: object = None) -> Mapping[str, object]:
    return immutable_snapshot_mapping(
        {
            "worker_lifecycle_boundary_decision": reason,
            "field": field,
            "value": scheduler_value_snapshot(value, field_name=field),
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        },
        field_name="worker_lifecycle_boundary_decision",
    )


def worker_pre_execution_stage_decision(stage: object) -> WorkerLifecycleBooleanDecision:
    """Classify pre-execution stages while recording unsupported stage input."""

    stage_text, stage_reason = scheduler_text(stage, replacement_text="")
    if stage_reason != "":
        return WorkerLifecycleBooleanDecision(
            value=_DECISION_FALSE,
            reason=stage_reason,
            evidence=(_worker_evidence(stage_reason, field="inmemory_worker_stage", value=stage),),
        )
    stage_l = str.lower(stage_text)
    return WorkerLifecycleBooleanDecision(
        value=any(token in stage_l for token in _PRE_EXECUTION_STAGE_TOKENS),
        reason="",
    )


def worker_heartbeat_record_decision(*, record: object, terminal: object, job_id: int) -> WorkerLifecycleBooleanDecision:
    """Decide whether a heartbeat can apply to the current job record."""

    if type(record) is not dict:
        reason = "inmemory_heartbeat_record_missing"
        return WorkerLifecycleBooleanDecision(
            value=_DECISION_FALSE,
            reason=reason,
            evidence=(_worker_evidence(reason, field="inmemory_heartbeat_record", value=record),),
        )
    if job_id in terminal:
        reason = "inmemory_heartbeat_job_terminal"
        return WorkerLifecycleBooleanDecision(
            value=_DECISION_FALSE,
            reason=reason,
            evidence=(_worker_evidence(reason, field="inmemory_heartbeat_job_id", value=job_id),),
        )
    return WorkerLifecycleBooleanDecision(value=_DECISION_TRUE, reason="")


def worker_heartbeat_attempt_decision(*, record_attempt: object, attempt: int) -> WorkerLifecycleBooleanDecision:
    """Decide whether a heartbeat attempt matches the current record attempt."""

    if record_attempt is None:
        reason = "inmemory_heartbeat_record_attempt_rejected"
        return WorkerLifecycleBooleanDecision(
            value=_DECISION_FALSE,
            reason=reason,
            evidence=(_worker_evidence(reason, field="inmemory_heartbeat_record_attempt", value=record_attempt),),
        )
    if record_attempt != attempt:
        reason = "inmemory_heartbeat_attempt_mismatch"
        return WorkerLifecycleBooleanDecision(
            value=_DECISION_FALSE,
            reason=reason,
            evidence=(_worker_evidence(reason, field="inmemory_heartbeat_attempt", value=attempt),),
        )
    return WorkerLifecycleBooleanDecision(value=_DECISION_TRUE, reason="")


def done_worker_futures_decision(active: object) -> WorkerFutureTupleDecision:
    """Collect completed worker futures and record unsupported active mappings."""

    active_items = no_hook_mapping_items(active)
    if active_items is None:
        reason = "inmemory_worker_active_mapping_rejected"
        return WorkerFutureTupleDecision(
            items=(),
            reason=reason,
            evidence=(_worker_evidence(reason, field="inmemory_worker_active", value=active),),
        )
    done: list[object] = []
    for future, _meta in active_items:
        try:
            if future.done():
                done.append(future)
        except (OSError, RuntimeError, TypeError, ValueError, AttributeError):
            continue
    return WorkerFutureTupleDecision(items=tuple(done), reason="")


def active_worker_heartbeat_items_decision(active_items: object) -> WorkerHeartbeatItemsDecision:
    """Return active worker heartbeat item pairs with replayable rejection evidence."""

    if type(active_items) not in {list, tuple}:
        reason = "active_worker_heartbeat_items_rejected"
        return WorkerHeartbeatItemsDecision(
            items=(),
            reason=reason,
            evidence=(_worker_evidence(reason, field="active_worker_heartbeat_items", value=active_items),),
        )
    out = [
        (item[0], item[1])
        for item in active_items
        if type(item) in {list, tuple} and len(item) >= 2
    ]
    return WorkerHeartbeatItemsDecision(items=tuple(out), reason="")


__all__ = (
    "WorkerFutureTupleDecision",
    "WorkerHeartbeatItemsDecision",
    "WorkerLifecycleBooleanDecision",
    "active_worker_heartbeat_items_decision",
    "done_worker_futures_decision",
    "worker_heartbeat_attempt_decision",
    "worker_heartbeat_record_decision",
    "worker_pre_execution_stage_decision",
)
