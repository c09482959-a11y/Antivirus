"""Queue-owned failure-info construction for orphan recovery."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping
from Virus_Scan.scheduler.queue.exact_bool_support import exact_bool



def _owned_mapping(value: object, *, field: str) -> dict[str, object]:
    if value is None:
        return {}
    if type(value) is dict:
        return materialize_scheduler_mapping(immutable_mapping(value))
    return {field + "_unavailable": True, "value_type": no_hook_type_name(value)}



def build_reclaim_failure_info(
    *,
    reason_stage: str,
    timeout_expired: bool,
    hard_file_timeout: float,
    file_timeout: float,
    checkpoint_stalled: bool,
    progress_age: float,
    hb_age: float,
    claim_age: float,
    pid: object,
    pid_alive: bool,
    heartbeat_fresh: bool,
    timeout_evidence: dict[str, object],
    owner_killed: bool,
    termination_evidence: dict[str, object] | None,
    recovered: bool,
    attempt: int,
    now_text: str,
    progress_marker: object,
) -> dict[str, object]:
    timeout_expired_b = exact_bool(timeout_expired)
    checkpoint_stalled_b = exact_bool(checkpoint_stalled)
    hard_file_timeout_metric, _hard_file_timeout_reason = no_hook_finite_float(
        hard_file_timeout, default=0.0, allow_exact_text=False
    )
    file_timeout_metric, _file_timeout_reason = no_hook_finite_float(
        file_timeout, default=0.0, allow_exact_text=False
    )
    progress_age_metric, _progress_age_reason = no_hook_finite_float(
        progress_age, default=0.0, allow_exact_text=False
    )
    heartbeat_age_metric, _heartbeat_age_reason = no_hook_finite_float(
        hb_age, default=0.0, allow_exact_text=False
    )
    claim_age_metric, _claim_age_reason = no_hook_finite_float(
        claim_age, default=0.0, allow_exact_text=False
    )
    worker_termination = _owned_mapping(termination_evidence, field="worker_termination")
    if type(pid) is int and type(pid) is not bool:
        worker_pid: object = pid
        pid_error_text = int.__str__(pid)
    elif type(pid) is str:
        worker_pid_text = str.__str__(pid).strip()
        worker_pid = int(worker_pid_text) if worker_pid_text.isdigit() else worker_pid_text
        pid_error_text = str.__str__(pid)
    else:
        worker_pid = {"worker_pid_unavailable": True, "value_type": no_hook_type_name(pid)}
        pid_error_text = "unsupported_pid_type_" + no_hook_type_name(pid)
    return {
        "stage": reason_stage,
        "exception_type": "HardTimeout" if timeout_expired_b else ("ProgressStalled" if checkpoint_stalled_b else "WorkerOrphaned"),
        "error": (
            "active queue job exceeded timeout/stall guard; timeout_expired="
            + ("True" if exact_bool(timeout_expired_b) else "False")
            + "; hard_timeout="
            + format(hard_file_timeout_metric, ".1f")
            + "s; configured_timeout="
            + format(file_timeout_metric, ".1f")
            + "s; checkpoint_stalled="
            + ("True" if exact_bool(checkpoint_stalled_b) else "False")
            + "; progress_age="
            + format(progress_age_metric, ".1f")
            + "s; heartbeat_age="
            + format(heartbeat_age_metric, ".1f")
            + "s; claim_age="
            + format(claim_age_metric, ".1f")
            + "s; worker_pid="
            + pid_error_text
            + "; pid_alive="
            + ("True" if exact_bool(pid_alive) else "False")
            + "; heartbeat_fresh="
            + ("True" if exact_bool(heartbeat_fresh) else "False")
        ),
        "timeout_evidence": timeout_evidence,
        "heartbeat_age": round(heartbeat_age_metric, 3),
        "progress_age": round(progress_age_metric, 3),
        "worker_state": reason_stage,
        "worker_killed": exact_bool(owner_killed),
        "worker_termination": worker_termination,
        "worker_recovered": exact_bool(recovered),
        "worker_pid": worker_pid,
        "attempt": attempt,
        "time": now_text,
        "progress_marker": progress_marker,
    }


__all__ = ("build_reclaim_failure_info",)
