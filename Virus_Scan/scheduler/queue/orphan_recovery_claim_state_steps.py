"""Bounded active-claim state loading steps for orphan recovery."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_plain_instance_dict,
    no_hook_type_name,
)
from Virus_Scan.scheduler.evidence.process_queue_errors import (
    process_queue_record_suppressed as _process_queue_record_suppressed,
)
from Virus_Scan.scheduler.queue.authority import (
    process_queue_merge_claim_meta_into_job as _queue_merge_claim_meta_into_job,
)
from Virus_Scan.scheduler.queue.orphan_recovery_claim_decision import deferred_claim_state_none
from Virus_Scan.scheduler.runtime.queue_json import read_json_file

def _claim_numeric(
    value: object,
    *,
    field: str,
    default: float,
) -> tuple[float, Mapping[str, object] | None]:
    field_name = str.__str__(field) if type(field) is str and field else "claim_numeric"
    if value is None or (type(value) is str and str.__str__(value).strip() == ""):
        return default, None
    metric, reason = no_hook_finite_float(
        value,
        default=default,
        reason=field_name + "_malformed",
        non_finite_reason=field_name + "_non_finite",
    )
    if reason or metric < 0:
        category = reason or field_name + "_negative"
        return default, {
            "stage": "process_queue_orphan_claim_state",
            "state": "degraded",
            "error_category": category,
            "error_source": "scheduler.queue.orphan_recovery_claim_state",
            "message": category,
            "field": field_name,
            "value_type": no_hook_type_name(value),
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }
    return metric, None

def load_claim_payload_or_defer(
    src: object,
    *,
    active_age: float | None,
    claim_grace: float,
    deferred_recovery_evidence: list[Mapping[str, object]] | None,
) -> tuple[dict[str, object] | None, list[Mapping[str, object]] | None]:
    job_read = read_json_file(src, default=None)
    if isinstance(job_read, dict):
        return job_read, []
    if active_age is None or active_age < claim_grace:
        deferred_claim_state_none(
            "orphan_claim_payload_deferred", src=src, value=job_read, sink=deferred_recovery_evidence,
        )
        return None, None
    return {}, [{
        "stage": "process_queue_orphan_claim_state",
        "state": "degraded",
        "error_category": "orphan_claim_payload_unavailable",
        "error_source": "scheduler.queue.orphan_recovery_claim_state",
        "message": "orphan_claim_payload_unavailable",
        "field": "active_claim_payload",
        "value_type": no_hook_type_name(job_read),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }]

def merge_active_claim_job(src: object, job: dict[str, object]) -> dict[str, object]:
    merged_job = _queue_merge_claim_meta_into_job(src, job)
    return scheduler_str_key_mapping_from_items(merged_job.items())

def queue_info_or_defer(
    src: object,
    job: Mapping[str, object],
    *,
    active_age: float | None,
    claim_grace: float,
    recovery_evidence: list[Mapping[str, object]],
    deferred_recovery_evidence: list[Mapping[str, object]] | None,
) -> dict[str, object] | None:
    raw_queue_info = job.get("queue_info")
    qi = raw_queue_info or {}
    if not isinstance(qi, dict):
        recovery_evidence.append(
            {
                "stage": "process_queue_orphan_claim_state",
                "state": "degraded",
                "error_category": "orphan_claim_queue_info_malformed",
                "error_source": "scheduler.queue.orphan_recovery_claim_state",
                "message": "orphan_claim_queue_info_malformed",
                "field": "queue_info",
                "value_type": no_hook_type_name(raw_queue_info),
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_record": True,
            }
        )
        qi = {}
    has_claim_metadata = bool(qi.get("claimed_time") or qi.get("heartbeat_time") or qi.get("progress_time"))
    if not has_claim_metadata and (active_age is None or active_age < claim_grace):
        deferred_claim_state_none(
            "orphan_claim_metadata_deferred", src=src, value=qi, sink=deferred_recovery_evidence,
        )
        return None
    return qi

def mtime_source_age(src: object, *, now: float, active_age: float | None) -> float:
    if active_age is None:
        return 0.0
    try:
        return max(0.0, float(now) - float(active_age))
    except (TypeError, ValueError, OverflowError) as exc:
        _process_queue_record_suppressed(
            "process_queue_mtime_source_age_parse_failed", exc, extra={"source": str(src)}
        )
        return 0.0

def active_claim_metric_times(
    qi: Mapping[str, object],
    *,
    mtime_age: float,
    recovery_evidence: list[Mapping[str, object]],
) -> tuple[float, float, float]:
    claimed, claimed_issue = _claim_numeric(
        qi.get("claimed_time"),
        field="claimed_time",
        default=mtime_age,
    )
    if claimed_issue is not None:
        recovery_evidence.append(claimed_issue)
    hb, heartbeat_issue = _claim_numeric(
        qi.get("heartbeat_time"),
        field="heartbeat_time",
        default=claimed or mtime_age,
    )
    if heartbeat_issue is not None:
        recovery_evidence.append(heartbeat_issue)
    progress_ts, progress_issue = _claim_numeric(
        qi.get("progress_time"),
        field="progress_time",
        default=claimed or hb or mtime_age,
    )
    if progress_issue is not None:
        recovery_evidence.append(progress_issue)
    return claimed, hb, progress_ts

def active_claim_ages(
    *,
    now: float,
    stale: float,
    claimed: float,
    hb: float,
    progress_ts: float,
) -> tuple[float, float, float]:
    hb_age = now - hb if hb else stale + 1.0
    claim_age = now - claimed if claimed else hb_age
    progress_age = now - progress_ts if progress_ts else claim_age
    return hb_age, claim_age, progress_age

def active_claim_liveness(
    *,
    job: Mapping[str, object],
    qi: Mapping[str, object],
    hb: float,
    hb_age: float,
    stale: float,
    worker_liveness_checker: Callable[..., object],
) -> tuple[object, bool, bool]:
    pid = qi.get("worker_pid") or job.get("worker_pid")
    pid_liveness = worker_liveness_checker(pid, record_suppressed=_process_queue_record_suppressed)
    liveness_data = pid_liveness if type(pid_liveness) is dict else no_hook_plain_instance_dict(pid_liveness)
    liveness_alive = dict.get(liveness_data, "alive") if type(liveness_data) is dict else None
    pid_alive = liveness_alive if type(liveness_alive) is bool else False
    heartbeat_fresh = bool(hb and hb_age < stale and pid_alive)
    return pid, pid_alive, heartbeat_fresh

__all__ = (
    "_claim_numeric", "active_claim_ages", "active_claim_liveness", "active_claim_metric_times",
    "load_claim_payload_or_defer", "merge_active_claim_job", "mtime_source_age", "queue_info_or_defer",
)
