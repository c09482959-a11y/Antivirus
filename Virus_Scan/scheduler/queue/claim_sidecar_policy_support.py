"""No-hook support helpers for claim sidecar policy."""
from __future__ import annotations

from pathlib import Path


from Virus_Scan.contracts.no_hook_materialization import (
    exact_finite_float_or_none,
    exact_int_or_none,
    no_hook_type_name,
)
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path, scheduler_float
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot

CLAIM_SIDECAR_POLICY_WRITE_FAILED = False
ACTIVE_CLAIM_FAILED_CLOSED = True


def policy_nonnegative_time(value: object, *, reason: str) -> float:
    metric = exact_finite_float_or_none(value)
    if metric is None or metric < 0.0:
        raise ValueError(reason)
    return metric


def policy_pid(value: object) -> int:
    pid = exact_int_or_none(value)
    if pid is None or pid < 0:
        raise ValueError("queue_claim_worker_pid_rejected")
    return pid


def policy_first_present(mapping: dict[object, object], *keys: str) -> object:
    for key in keys:
        value = dict.get(mapping, key)
        if value is not None:
            return value
    return None


def active_claim_failed_closed(path: object) -> bool:
    safe_path, reason = scheduler_filesystem_path(path)
    if reason:
        return ACTIVE_CLAIM_FAILED_CLOSED
    try:
        return Path(safe_path).parent.name == "active"
    except (OSError, RuntimeError, TypeError, ValueError):
        return ACTIVE_CLAIM_FAILED_CLOSED


def active_claim_grace_seconds(environ: object=None, *, default: object=60.0, minimum: object=15.0, report: object=None) -> float:
    env = scheduler_environment_snapshot(environ)
    default_value, default_reason = scheduler_float(
        default,
        default=60.0,
        minimum=0.0,
        reason="queue_active_claim_grace_default_rejected",
    )
    minimum_value, minimum_reason = scheduler_float(
        minimum,
        default=15.0,
        minimum=0.0,
        reason="queue_active_claim_grace_minimum_rejected",
    )
    raw_value = scheduler_mapping_value(env, "UMIGE_QUEUE_ACTIVE_CLAIM_GRACE_SEC", default=default_value)
    grace_value, grace_reason = scheduler_float(
        raw_value,
        default=default_value,
        minimum=minimum_value,
        reason="queue_active_claim_grace_rejected",
        non_finite_reason="queue_active_claim_grace_non_finite",
    )
    rejection_reason = default_reason or minimum_reason or grace_reason
    if rejection_reason and report is not None:
        report("queue_active_claim_grace_invalid", ValueError(rejection_reason), fatal=False)
    if grace_reason:
        return max(minimum_value, default_value)
    return max(minimum_value, grace_value)


def report_active_claim_unprotected(report: object, path: object, *, pid: object, pid_alive: bool, heartbeat_time: object, heartbeat_age: float, active_grace: float) -> None:
    report(
        "queue_active_claim_unprotected_stale_worker",
        RuntimeError("active claim is no longer protected by worker liveness or heartbeat"),
        fatal=False,
        extra={
            "claim": scheduler_evidence_path(path, field_name="claim"),
            "pid_alive": pid_alive,
            "pid_type": no_hook_type_name(pid),
            "heartbeat_available": heartbeat_time is not None,
            "heartbeat_age": heartbeat_age,
            "active_grace": active_grace,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        },
    )
