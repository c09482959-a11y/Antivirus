"""Policy and raw-progress evidence for orphan reclaim timeout decisions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as _process_queue_record_suppressed
from Virus_Scan.scheduler.internal.scheduler_config import process_queue_env_float as _process_queue_env_float_value
from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget
from Virus_Scan.scheduler.queue.orphan_recovery_timeout_evidence import (
    job_mapping,
    resolve_reclaim_float_value,
    resolve_reclaim_int_value,
)


@dataclass(frozen=True)
class ReclaimTimeoutPolicyState:
    claim_age: float
    progress_age: float
    hb_age: float
    hard_file_timeout: float
    progress_stall: float
    stale: float
    timeout_evidence: dict[str, object]


def first_scheduler_job_value(mapping: Mapping[str, object], *keys: str, default: object = None) -> object:
    for key in keys:
        try:
            value = mapping.get(key, None)
        except (AttributeError, KeyError, TypeError, RuntimeError):
            continue
        if value is not None:
            return value
    return default


def scheduler_job_text(value: object, *, missing_text: str) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_scheduler_reclaim_text",
        unsupported_reason="unsafe_scheduler_reclaim_text_rejected",
    )
    if reason == "" and text:
        return text
    return missing_text


def build_reclaim_timeout_policy_state(
    *,
    job: dict[str, object],
    claim_age: float,
    progress_age: float,
    hb_age: float,
    stale: float,
    file_timeout: float,
    progress_stall: float,
) -> ReclaimTimeoutPolicyState:
    policy_evidence: list[Mapping[str, object]] = []
    job_record = job_mapping(job, policy_evidence)
    resolved_file_timeout = resolve_reclaim_float_value(value=file_timeout, field="file_timeout", default_value=0.0, evidence=policy_evidence)
    resolved_progress_stall = resolve_reclaim_float_value(value=progress_stall, field="progress_stall", default_value=0.0, evidence=policy_evidence)
    resolved_stale = resolve_reclaim_float_value(value=stale, field="stale", default_value=0.0, evidence=policy_evidence)
    resolved_claim_age = resolve_reclaim_float_value(value=claim_age, field="claim_age", default_value=0.0, evidence=policy_evidence)
    resolved_progress_age = resolve_reclaim_float_value(value=progress_age, field="progress_age", default_value=0.0, evidence=policy_evidence)
    resolved_hb_age = resolve_reclaim_float_value(value=hb_age, field="hb_age", default_value=0.0, evidence=policy_evidence)
    recursion_depth = resolve_reclaim_int_value(
        value=first_scheduler_job_value(job_record, "recursion_depth", "depth", default=0),
        field="recursion_depth",
        default_value=0,
        evidence=policy_evidence,
    )
    job_file = scheduler_job_text(job_record.get("file"), missing_text="")
    job_type = scheduler_job_text(job_record.get("job_type"), missing_text="file")
    timeout_budget = compute_timeout_budget(
        job_file,
        configured_timeout_seconds=resolved_file_timeout,
        workload_class=job_type,
        method=job_type if job_type != "file" else "file_scan",
        recursion_depth=recursion_depth,
    )
    hard_file_timeout = _process_queue_env_float_value(
        "UMIGE_QUEUE_HARD_FILE_TIMEOUT_SEC",
        0.0,
        minimum=0.0,
        record_suppressed=_process_queue_record_suppressed,
    )
    if hard_file_timeout <= 0:
        hard_file_timeout = timeout_budget.hard_timeout_seconds
    else:
        hard_file_timeout = max(float(hard_file_timeout), timeout_budget.hard_timeout_seconds)
    timeout_evidence = dict(timeout_budget.as_evidence())
    if policy_evidence:
        timeout_evidence["reclaim_timeout_policy_evidence"] = tuple(policy_evidence)
        timeout_evidence["reclaim_timeout_policy_failed"] = True
        timeout_evidence["final_json_must_record"] = True
        timeout_evidence["checkpoint_must_record"] = True
        timeout_evidence["replay_must_reproduce"] = True
    return ReclaimTimeoutPolicyState(
        claim_age=resolved_claim_age,
        progress_age=resolved_progress_age,
        hb_age=resolved_hb_age,
        hard_file_timeout=hard_file_timeout,
        progress_stall=max(float(resolved_progress_stall), timeout_budget.stall_timeout_seconds),
        stale=max(float(resolved_stale), timeout_budget.heartbeat_stale_seconds),
        timeout_evidence=timeout_evidence,
    )


def probe_reclaim_raw_global_progress(
    *,
    queue_dir: object,
    progress_stall: float,
    raw_stage_progress_recent: Callable[..., bool],
    timeout_evidence: dict[str, object],
) -> bool:
    try:
        return raw_stage_progress_recent(queue_dir, quiet_sec=max(30.0, min(progress_stall, 120.0)))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        _process_queue_record_suppressed(
            "process_queue_raw_global_progress_probe_failed",
            exc,
            extra={"queue_dir_type": no_hook_type_name(queue_dir)},
        )
        timeout_evidence["raw_global_progress_probe_failed"] = True
        timeout_evidence["raw_global_progress_probe_evidence"] = {
            "stage": "process_queue_reclaim_timeout_raw_progress_probe",
            "queue_dir_type": no_hook_type_name(queue_dir),
            "error_category": no_hook_type_name(exc),
            "error_source": "orphan_recovery_timeout.raw_stage_progress_recent",
            "detail": scheduler_job_text(exc, missing_text="raw_progress_probe_failed")[:1000],
            "timeout_failure": True,
            "queue_recovery_failure": True,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_reproduce": True,
        }
        return True
