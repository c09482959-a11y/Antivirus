"""Bounded worker heartbeat publication steps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_boundary import (
    safe_bool_result,
    safe_worker_heartbeat_inputs,
)


@dataclass(frozen=True, slots=True)
class HeartbeatPublishInputs:
    """No-hook worker heartbeat inputs materialized for one active task."""

    job_id: str
    attempt: int
    stage: str
    progress: int
    bytes_processed: int
    last_progress_ns: int
    rss_limit: float
    completed_jobs: int
    process_id: int
    running_flag: int
    cancel_flag: int
    poison_flag: int
    meta_dict: dict | None
    input_failure: str


@dataclass(frozen=True, slots=True)
class HeartbeatPublishFlags:
    """Derived heartbeat flags and stop decision for one active task."""

    flags: int
    rss_mb: float
    should_stop: bool


def load_heartbeat_publish_inputs(
    *,
    meta: object,
    cfg: dict,
    heartbeat_flags: object,
    completed_jobs: int,
    process_id: int,
    default_rss_limit: float,
) -> HeartbeatPublishInputs:
    """Materialize validated heartbeat inputs without exposing tuple indexing."""

    (
        job_id,
        attempt,
        stage,
        progress,
        bytes_processed,
        last_progress_ns,
        rss_limit,
        completed_jobs_value,
        process_id_value,
        running_flag,
        cancel_flag,
        poison_flag,
        meta_dict,
        input_failure,
    ) = safe_worker_heartbeat_inputs(
        meta=meta,
        cfg=cfg,
        heartbeat_flags=heartbeat_flags,
        completed_jobs=completed_jobs,
        process_id=process_id,
        default_rss_limit=default_rss_limit,
    )
    return HeartbeatPublishInputs(
        job_id=job_id,
        attempt=attempt,
        stage=stage,
        progress=progress,
        bytes_processed=bytes_processed,
        last_progress_ns=last_progress_ns,
        rss_limit=rss_limit,
        completed_jobs=completed_jobs_value,
        process_id=process_id_value,
        running_flag=running_flag,
        cancel_flag=cancel_flag,
        poison_flag=poison_flag,
        meta_dict=meta_dict,
        input_failure=input_failure,
    )


def derive_heartbeat_publish_flags(
    *,
    inputs: HeartbeatPublishInputs,
    cancel_table: object,
    cancel_requested: Callable[[object, str, int], bool],
) -> HeartbeatPublishFlags:
    """Resolve cancel/poison flags for a materialized heartbeat input set."""

    flags = inputs.running_flag if inputs.progress > 0 else 0
    if safe_bool_result(cancel_requested(cancel_table, inputs.job_id, inputs.attempt)):
        flags |= inputs.cancel_flag
    rss_mb = 0.0
    should_stop = False
    if inputs.rss_limit > 0 and rss_mb > inputs.rss_limit:
        flags |= inputs.poison_flag
        should_stop = True
    return HeartbeatPublishFlags(flags=flags, rss_mb=rss_mb, should_stop=should_stop)


def publish_heartbeat_update(
    *,
    inputs: HeartbeatPublishInputs,
    flags: HeartbeatPublishFlags,
    heartbeat_table: object,
    update_shared_heartbeat: Callable[..., object],
) -> object:
    """Publish one heartbeat update through the injected shared-heartbeat owner."""

    return update_shared_heartbeat(
        heartbeat_table,
        inputs.job_id,
        inputs.attempt,
        pid=inputs.process_id,
        thread_id=0,
        stage=inputs.stage,
        progress_counter=inputs.progress,
        bytes_processed=inputs.bytes_processed,
        last_progress_ns=inputs.last_progress_ns,
        flags=flags.flags,
        rss_mb=flags.rss_mb,
        completed_jobs=inputs.completed_jobs,
    )


def heartbeat_timestamp_value(now_hb: object) -> float:
    """Return the heartbeat timestamp only for primitive numeric values."""

    return now_hb if type(now_hb) in {int, float} else 0.0


__all__ = (
    "HeartbeatPublishFlags",
    "HeartbeatPublishInputs",
    "derive_heartbeat_publish_flags",
    "heartbeat_timestamp_value",
    "load_heartbeat_publish_inputs",
    "publish_heartbeat_update",
)
