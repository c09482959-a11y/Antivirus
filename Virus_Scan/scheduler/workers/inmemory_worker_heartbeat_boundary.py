"""No-hook boundary helpers for worker heartbeat publication evidence."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import InMemoryHeartbeatFlags
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_decisions import active_worker_heartbeat_items_decision
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value

_ZERO_INT = 0
_ZERO_FLOAT = 0.0
_MISSING = object()



def _heartbeat_text(value: object, *, default: str, missing_reason: str, unsupported_reason: str) -> tuple[str, str]:
    text, reason = no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)
    if reason != "":
        return default, reason
    stripped = str.strip(text)
    if stripped == "":
        return default, "blank_worker_heartbeat_text"
    return stripped, ""


def _heartbeat_int(value: object, *, reason: str) -> tuple[int, str]:
    parsed, parse_reason = scheduler_int(value, default=_ZERO_INT, minimum=0, reason=reason)
    if parse_reason != "":
        return _ZERO_INT, parse_reason
    return parsed, ""


def _safe_flag_from_type(flags: object, name: str) -> int:
    class_dict = None
    try:
        class_dict = type.__getattribute__(type(flags), "__dict__")
    except (AttributeError, TypeError):
        class_dict = None
    if type(class_dict) is MappingProxyType:
        value = class_dict.get(name)
        if type(value) is int:
            return int.__int__(value)
    return _ZERO_INT


def safe_heartbeat_flag_values(flags: object) -> tuple[int, int, int]:
    """Return heartbeat flags without executing caller-owned descriptors."""
    if type(flags) is InMemoryHeartbeatFlags:
        running = scheduler_exact_attr(flags, "running", owner_type=InMemoryHeartbeatFlags)
        cancel = scheduler_exact_attr(flags, "cancel_request", owner_type=InMemoryHeartbeatFlags)
        poisoned = scheduler_exact_attr(flags, "poisoned", owner_type=InMemoryHeartbeatFlags)
        retire = scheduler_exact_attr(flags, "force_retire", owner_type=InMemoryHeartbeatFlags)
        run_i, _ = _heartbeat_int(running, reason="worker_heartbeat_running_flag_rejected")
        cancel_i, _ = _heartbeat_int(cancel, reason="worker_heartbeat_cancel_flag_rejected")
        poison_i, _ = _heartbeat_int(poisoned, reason="worker_heartbeat_poison_flag_rejected")
        retire_i, _ = _heartbeat_int(retire, reason="worker_heartbeat_retire_flag_rejected")
        return run_i, cancel_i, poison_i | retire_i
    running = _safe_flag_from_type(flags, "running")
    cancel = _safe_flag_from_type(flags, "cancel_request")
    poison = _safe_flag_from_type(flags, "poisoned_or_retire_mask")
    return running, cancel, poison


def safe_worker_heartbeat_inputs(
    *,
    meta: object,
    cfg: object,
    heartbeat_flags: object,
    completed_jobs: object,
    process_id: object,
    default_rss_limit: object,
) -> tuple[str, int, str, int, int, int, float, int, int, int, int, int, dict[str, object] | None, str]:
    if type(meta) is not dict:
        return "unknown", 0, "scan", 0, 0, 0, 0.0, 0, 0, 0, 0, 0, None, "unsupported_worker_heartbeat_meta"
    cfg_map = cfg if type(cfg) is dict else {}
    job_text, job_reason = _heartbeat_text(
        scheduler_mapping_value(meta, "job_id", _MISSING),
        default="unknown",
        missing_reason="missing_worker_heartbeat_job_id",
        unsupported_reason="unsupported_worker_heartbeat_job_id",
    )
    stage_text, stage_reason = _heartbeat_text(
        scheduler_mapping_value(meta, "stage", _MISSING),
        default="scan",
        missing_reason="missing_worker_heartbeat_stage",
        unsupported_reason="unsupported_worker_heartbeat_stage",
    )
    attempt, attempt_reason = _heartbeat_int(scheduler_mapping_value(meta, "attempt", 0), reason="worker_heartbeat_attempt_rejected")
    progress, progress_reason = _heartbeat_int(scheduler_mapping_value(meta, "progress_counter", 0), reason="worker_heartbeat_progress_rejected")
    bytes_processed, bytes_reason = _heartbeat_int(scheduler_mapping_value(meta, "bytes_processed", 0), reason="worker_heartbeat_bytes_rejected")
    last_progress_ns, last_reason = _heartbeat_int(scheduler_mapping_value(meta, "last_progress_ns", 0), reason="worker_heartbeat_last_progress_rejected")
    completed, completed_reason = _heartbeat_int(completed_jobs, reason="worker_heartbeat_completed_rejected")
    pid, pid_reason = _heartbeat_int(process_id, reason="worker_heartbeat_pid_rejected")
    running_flag, cancel_flag, poison_flag = safe_heartbeat_flag_values(heartbeat_flags)
    raw_rss_limit = scheduler_mapping_value(cfg_map, "worker_rss_limit_mb", default_rss_limit)
    rss_limit, rss_reason = scheduler_float(
        raw_rss_limit,
        default=_ZERO_FLOAT,
        minimum=0.0,
        reason="worker_heartbeat_rss_limit_rejected",
        non_finite_reason="worker_heartbeat_rss_limit_non_finite",
    )
    reason = next((r for r in (job_reason, stage_reason, attempt_reason, progress_reason, bytes_reason, last_reason, completed_reason, pid_reason, rss_reason) if r), "")
    return job_text, attempt, stage_text, progress, bytes_processed, last_progress_ns, rss_limit, completed, pid, running_flag, cancel_flag, poison_flag, meta, reason


def exact_active_worker_items(active_items: object) -> tuple[tuple[object, object], ...]:
    return active_worker_heartbeat_items_decision(active_items).items


def safe_bool_result(value: object) -> bool:
    result, _ = scheduler_bool(value, default=False, reason="worker_heartbeat_bool_result_rejected")
    return result


__all__ = (
    "exact_active_worker_items",
    "safe_bool_result",
    "safe_heartbeat_flag_values",
    "safe_worker_heartbeat_inputs",
)
