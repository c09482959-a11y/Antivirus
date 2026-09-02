"""No-hook primitives shared by worker heartbeat owners."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_text
from Virus_Scan.runtime.api import get_init_value
from Virus_Scan.scheduler.internal.owned_indexed_sequence import is_owned_indexed_sequence
from Virus_Scan.scheduler.workers.shared_heartbeat_evidence import record_shared_heartbeat_failure

HEARTBEAT_UNKNOWN_STAGE = "unknown"
_HEARTBEAT_TABLE_REJECTION_REASONS = (
    ("generation", "heartbeat_table_generation_rejected"),
    ("monotonic_ns", "heartbeat_table_monotonic_ns_rejected"),
    ("pid", "heartbeat_table_pid_rejected"),
    ("thread_id", "heartbeat_table_thread_id_rejected"),
    ("stage", "heartbeat_table_stage_rejected"),
    ("progress_counter", "heartbeat_table_progress_counter_rejected"),
    ("bytes_processed", "heartbeat_table_bytes_processed_rejected"),
    ("last_progress_ns", "heartbeat_table_last_progress_ns_rejected"),
    ("flags", "heartbeat_table_flags_rejected"),
    ("completed_jobs", "heartbeat_table_completed_jobs_rejected"),
    ("rss_mb", "heartbeat_table_rss_mb_rejected"),
)


def _init_flag(name: str, replacement_value: int, rejected_reason: str) -> int:
    value, reason = no_hook_exact_nonnegative_int(
        get_init_value(name),
        default=replacement_value,
        reason=rejected_reason,
    )
    if reason or value == 0:
        return replacement_value
    return value


HB_RUNNING = _init_flag("HB_RUNNING", 1, "HB_RUNNING_rejected")
HB_CANCEL_REQUEST = _init_flag("HB_CANCEL_REQUEST", 2, "HB_CANCEL_REQUEST_rejected")
HB_POISONED = _init_flag("HB_POISONED", 4, "HB_POISONED_rejected")
HB_STALLED = _init_flag("HB_STALLED", 8, "HB_STALLED_rejected")
HB_FORCE_RETIRE = _init_flag("HB_FORCE_RETIRE", 16, "HB_FORCE_RETIRE_rejected")

_STAGE_CODE_ITEMS = (
    (HEARTBEAT_UNKNOWN_STAGE, 0), ("queued", 1), ("assigned", 2), ("scan", 3),
    ("image", 4), ("archive", 5), ("dotnet", 6), ("yara", 7),
    ("raw", 8), ("complete", 9), ("failed", 10),
)


class UmigeCooperativeCancel(Exception):
    """Internal cooperative cancellation signal."""


def heartbeat_rejection(operation: str, job_id: object, generation: object, reason: str) -> None:
    record_shared_heartbeat_failure(
        operation=operation,
        job_id=job_id,
        generation=generation,
        exc=ValueError(reason),
    )


def safe_heartbeat_int(
    value: object,
    *,
    rejection_reason: str,
    non_finite_reason: str,
    replacement_value: int = 0,
) -> tuple[int, str]:
    return no_hook_exact_nonnegative_int(
        value,
        default=replacement_value,
        reason=rejection_reason,
        non_finite_reason=non_finite_reason,
    )


def heartbeat_table_array(table: dict[str, object], key: str, *, writable: bool) -> object:
    value = dict.get(table, key)
    if not is_owned_indexed_sequence(value, writable=writable):
        for known_key, rejected_reason in _HEARTBEAT_TABLE_REJECTION_REASONS:
            if known_key == key:
                raise ValueError(rejected_reason)
        raise ValueError("heartbeat_table_unknown_rejected")
    return value


@dataclass(frozen=True, slots=True)
class HeartbeatStageCodeDecision:
    """Replayable stage-code projection decision for heartbeat publication."""

    accepted: bool
    stage_code: int
    stage_name: str
    reason: str


def heartbeat_stage_code_decision(stage: object) -> HeartbeatStageCodeDecision:
    name, reason = no_hook_text(
        stage,
        missing_reason="heartbeat_stage_missing",
        unsupported_reason="heartbeat_stage_rejected",
    )
    if reason:
        return HeartbeatStageCodeDecision(accepted=False, stage_code=_STAGE_CODE_ITEMS[0][1], stage_name=HEARTBEAT_UNKNOWN_STAGE, reason=reason)
    normalized = str.__str__(name).strip().lower()
    for stage_name, stage_code in _STAGE_CODE_ITEMS:
        if stage_name == normalized:
            return HeartbeatStageCodeDecision(accepted=True, stage_code=stage_code, stage_name=stage_name, reason="")
    return HeartbeatStageCodeDecision(accepted=False, stage_code=_STAGE_CODE_ITEMS[0][1], stage_name=HEARTBEAT_UNKNOWN_STAGE, reason="heartbeat_stage_unknown")


def heartbeat_stage_code(stage: object) -> int:
    return heartbeat_stage_code_decision(stage).stage_code


def heartbeat_stage_name(code: object) -> str:
    target_code, reason = safe_heartbeat_int(
        code,
        rejection_reason="heartbeat_stage_code_rejected",
        non_finite_reason="heartbeat_stage_code_non_finite",
    )
    if reason:
        return HEARTBEAT_UNKNOWN_STAGE
    for stage_name, stage_code in _STAGE_CODE_ITEMS:
        if stage_code == target_code:
            return stage_name
    return HEARTBEAT_UNKNOWN_STAGE
