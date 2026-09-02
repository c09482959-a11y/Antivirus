"""Bounded steps for in-memory worker heartbeat cycle publication."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, MutableMapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle_decisions import (
    heartbeat_active_items_decision,
    heartbeat_cfg_decision,
)


@dataclass(frozen=True, slots=True)
class HeartbeatCycleValues:
    active_items: tuple[tuple[object, object], ...]
    now: float
    last_emit: float
    interval: float
    seq: int
    should_publish: bool


@dataclass(frozen=True, slots=True)
class HeartbeatPublicationValues:
    now: float
    seq: int
    stop_requested: bool
    heartbeat_failures: tuple[Mapping[str, object], ...]


def heartbeat_active_items(active: object) -> tuple[tuple[object, object], ...]:
    return heartbeat_active_items_decision(active).items


def heartbeat_cfg(cfg: object) -> dict[str, object]:
    return dict(heartbeat_cfg_decision(cfg).config)


def heartbeat_failures(active_items: tuple[tuple[object, object], ...]) -> tuple[Mapping[str, object], ...]:
    failures: list[Mapping[str, object]] = []
    for _future, meta in active_items:
        if type(meta) is not dict:
            continue
        failed, _reason = scheduler_bool(
            dict.get(meta, "heartbeat_publish_failed"),
            default=False,
            reason="inmemory_worker_heartbeat_publish_failed_rejected",
        )
        if not failed:
            continue
        evidence = dict.get(meta, "heartbeat_publish_evidence")
        if no_hook_mapping_items(evidence) is None:
            failures.append({"worker_heartbeat_publish_failed": True})
        else:
            failures.append(immutable_mapping(evidence))
    return tuple(failures)


def normalize_heartbeat_cycle_values(
    *,
    active: object,
    now_hb: float,
    last_heartbeat_emit: float,
    heartbeat_interval: float,
    heartbeat_seq: int,
) -> HeartbeatCycleValues:
    active_items = heartbeat_active_items(active)
    now_value, _now_reason = scheduler_float(
        now_hb,
        minimum=0.0,
        reason="inmemory_worker_heartbeat_now_rejected",
        non_finite_reason="inmemory_worker_heartbeat_now_non_finite",
    )
    last_value, _last_reason = scheduler_float(
        last_heartbeat_emit,
        minimum=0.0,
        reason="inmemory_worker_heartbeat_last_emit_rejected",
        non_finite_reason="inmemory_worker_heartbeat_last_emit_non_finite",
    )
    interval_value, _interval_reason = scheduler_float(
        heartbeat_interval,
        minimum=0.0,
        reason="inmemory_worker_heartbeat_interval_rejected",
        non_finite_reason="inmemory_worker_heartbeat_interval_non_finite",
    )
    seq_value, _seq_reason = scheduler_int(
        heartbeat_seq,
        minimum=0,
        reason="inmemory_worker_heartbeat_seq_rejected",
    )
    should_publish = bool(active_items) and now_value - last_value >= interval_value
    return HeartbeatCycleValues(
        active_items,
        now_value,
        last_value,
        interval_value,
        seq_value,
        should_publish,
    )


def publish_heartbeat_cycle_values(
    *,
    values: HeartbeatCycleValues,
    cfg: Mapping[str, object],
    cancel_table: object,
    heartbeat_table: object,
    heartbeat_flags: MutableMapping[object, object],
    completed_jobs: int,
    cancel_requested: Callable[..., object],
    update_shared_heartbeat: Callable[..., object],
    heartbeat_publisher: Callable[..., object],
    process_id: int,
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
) -> HeartbeatPublicationValues:
    completed_value, _completed_reason = scheduler_int(
        completed_jobs,
        minimum=0,
        reason="inmemory_worker_heartbeat_completed_rejected",
    )
    process_value, _process_reason = scheduler_int(
        process_id,
        minimum=0,
        reason="inmemory_worker_heartbeat_process_rejected",
    )
    stop_requested = heartbeat_publisher(
        active_items=values.active_items,
        cfg=heartbeat_cfg(cfg),
        cancel_table=cancel_table,
        heartbeat_table=heartbeat_table,
        heartbeat_flags=heartbeat_flags,
        completed_jobs=completed_value,
        cancel_requested=cancel_requested,
        update_shared_heartbeat=update_shared_heartbeat,
        process_id=process_value,
        now_hb=values.now,
        recoverable_exceptions=recoverable_exceptions,
        record_suppressed=record_suppressed,
    )
    stop_value, _stop_reason = scheduler_bool(
        stop_requested,
        reason="inmemory_worker_heartbeat_stop_rejected",
    )
    return HeartbeatPublicationValues(
        values.now,
        values.seq,
        stop_value,
        heartbeat_failures(values.active_items),
    )


__all__ = (
    "HeartbeatCycleValues",
    "HeartbeatPublicationValues",
    "heartbeat_active_items",
    "heartbeat_cfg",
    "heartbeat_failures",
    "normalize_heartbeat_cycle_values",
    "publish_heartbeat_cycle_values",
)
