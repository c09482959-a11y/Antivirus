"""Bounded active-claim protection decisions for queue claim sidecars."""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.queue.claim_sidecar_policy_support import (
    active_claim_failed_closed,
    active_claim_grace_seconds,
    policy_first_present,
    policy_nonnegative_time,
    report_active_claim_unprotected,
)
from Virus_Scan.scheduler.queue.raw_queue_path_support import materialize_raw_queue_path

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

def active_claim_path(path: object) -> Path | None:
    claim_path = materialize_raw_queue_path(path, reason="queue_active_claim_path_rejected")
    if claim_path.parent.name != "active":
        return None
    return claim_path

def active_claim_current_time(
    now: float | None,
    queue_now: Callable[[], float],
) -> float:
    return policy_nonnegative_time(
        queue_now() if now is None else now,
        reason="queue_active_claim_now_rejected",
    )

def active_claim_grace_value(
    grace: float | None,
    report: Callable[..., object],
) -> float:
    if grace is None:
        return active_claim_grace_seconds(
            None,
            default=60.0,
            minimum=15.0,
            report=report,
        )
    return policy_nonnegative_time(grace, reason="queue_active_claim_grace_rejected")

def active_claim_age_value(
    claim_path: Path,
    current: float,
    path_age: Callable[[Path, float], float | None],
) -> float | None:
    age = path_age(claim_path, current)
    if age is None:
        return None
    return policy_nonnegative_time(age, reason="queue_active_claim_age_rejected")

def active_claim_payload_mapping(
    claim_path: Path,
    job: object | None,
    read_json: Callable[..., object],
    merge_claim_meta: Callable[[Path, object], object],
) -> dict[object, object] | None:
    payload = job if type(job) is dict else read_json(claim_path, default=None)
    if type(payload) is not dict:
        return None
    merged = merge_claim_meta(claim_path, payload)
    if type(merged) is dict:
        return merged
    return {}

def active_claim_queue_info(payload: dict[object, object]) -> dict[object, object]:
    queue_info = dict.get(payload, "queue_info")
    if type(queue_info) is dict:
        return queue_info
    return {}

def active_claim_worker_pid(
    payload: dict[object, object],
    queue_info: dict[object, object],
) -> object:
    pid = dict.get(queue_info, "worker_pid")
    if pid is None:
        return dict.get(payload, "worker_pid")
    return pid

def active_claim_heartbeat_time(
    claim_path: Path,
    queue_info: dict[object, object],
    report: Callable[..., object],
) -> float | None:
    heartbeat = policy_first_present(queue_info, "heartbeat_time", "claimed_time")
    try:
        if heartbeat is None:
            return None
        return policy_nonnegative_time(
            heartbeat,
            reason="queue_active_claim_heartbeat_rejected",
        )
    except ValueError as exc:
        report(
            "queue_active_claim_heartbeat_invalid",
            exc,
            fatal=False,
            extra={"claim": scheduler_evidence_path(claim_path, field_name="claim")},
        )
        return None

def active_claim_worker_liveness_protected(
    *,
    pid_alive: bool,
    heartbeat_time: float | None,
    heartbeat_age: float,
    active_grace: float,
) -> bool:
    return pid_alive and (
        heartbeat_time is None or heartbeat_age < max(active_grace * 6.0, 300.0)
    )

def active_claim_recent_heartbeat_protected(
    heartbeat_time: float | None,
    heartbeat_age: float,
    active_grace: float,
) -> bool:
    return heartbeat_time is not None and heartbeat_age < max(active_grace * 2.0, 120.0)

def active_claim_is_protected_with_dependencies(
    path: object,
    job: object | None = None,
    *,
    now: float | None = None,
    grace: float | None = None,
    path_age: Callable[[Path, float], float | None],
    read_json: Callable[..., object],
    merge_claim_meta: Callable[[Path, object], object],
    pid_is_alive: Callable[[object], bool],
    queue_now: Callable[[], float],
    report: Callable[..., object],
) -> bool:
    try:
        claim_path = active_claim_path(path)
        if claim_path is None:
            return False
        current = active_claim_current_time(now, queue_now)
        active_grace = active_claim_grace_value(grace, report)
        age = active_claim_age_value(claim_path, current, path_age)
        if age is None or age < active_grace:
            return True
        payload = active_claim_payload_mapping(claim_path, job, read_json, merge_claim_meta)
        if payload is None:
            return age < max(active_grace * 4.0, 240.0)
        queue_info = active_claim_queue_info(payload)
        pid = active_claim_worker_pid(payload, queue_info)
        pid_alive = pid_is_alive(pid) is True
        heartbeat_time = active_claim_heartbeat_time(claim_path, queue_info, report)
        heartbeat_age = current - heartbeat_time if heartbeat_time is not None else age
        if active_claim_worker_liveness_protected(
            pid_alive=pid_alive,
            heartbeat_time=heartbeat_time,
            heartbeat_age=heartbeat_age,
            active_grace=active_grace,
        ):
            return True
        if active_claim_recent_heartbeat_protected(
            heartbeat_time,
            heartbeat_age,
            active_grace,
        ):
            return True
        report_active_claim_unprotected(
            report,
            path,
            pid=pid,
            pid_alive=pid_alive,
            heartbeat_time=heartbeat_time,
            heartbeat_age=heartbeat_age,
            active_grace=active_grace,
        )
        return False
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        report(
            "queue_active_claim_protection_failed_closed",
            exc,
            fatal=True,
            extra={
                "claim": scheduler_evidence_path(path, field_name="claim")
                if path is not None
                else "missing_claim"
            },
        )
        return active_claim_failed_closed(path)
