"""Validate and apply one shared heartbeat row."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict
from Virus_Scan.scheduler.contracts.evidence_record_support import (
    scheduler_mapping_items,
    scheduler_mapping_value,
)
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_float,
    scheduler_int,
    scheduler_text,
)
from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import InMemoryHeartbeatFlags
from Virus_Scan.scheduler.workers.inmemory_heartbeat_progress import (
    HeartbeatProgressSignature,
    heartbeat_progress_changed,
    heartbeat_progress_signature,
)

_ROW_ZERO_INT = 0
_ROW_ZERO_FLOAT = 0.0
_ROW_BLANK_TEXT = ""
_ROW_UNKNOWN_TEXT = "unknown"


def _row_int(row: object, field_name: str, *, default_value: object = _ROW_ZERO_INT) -> int:
    value, reason = scheduler_int(
        scheduler_mapping_value(row, field_name, default=default_value),
        default=_ROW_ZERO_INT,
        minimum=0,
        reason="shared_heartbeat_" + field_name + "_rejected",
    )
    if reason:
        raise ValueError(reason)
    return value



def _callback_number(
    callback: Callable[[], object], field_name: str, *, integer: bool
) -> int | float:
    raw_value = callback()
    if integer:
        int_value, int_reason = scheduler_int(
            raw_value,
            default=_ROW_ZERO_INT,
            minimum=0,
            reason="shared_heartbeat_" + field_name + "_rejected",
        )
        if int_reason:
            raise ValueError(int_reason)
        return int_value
    float_value, float_reason = scheduler_float(
        raw_value,
        default=_ROW_ZERO_FLOAT,
        minimum=0.0,
        reason="shared_heartbeat_" + field_name + "_rejected",
    )
    if float_reason:
        raise ValueError(float_reason)
    return float_value


def _poison_mask(heartbeat_flags: object) -> int:
    if type(heartbeat_flags) is InMemoryHeartbeatFlags:
        raw_value = scheduler_exact_attr(
            heartbeat_flags, "poisoned_or_retire_mask", owner_type=InMemoryHeartbeatFlags, default=_ROW_ZERO_INT
        )
    else:
        state = no_hook_plain_instance_dict(heartbeat_flags)
        if state is None:
            raise ValueError("shared_heartbeat_flags_rejected")
        raw_value = dict.get(state, "poisoned_or_retire_mask")
    value, reason = scheduler_int(
        raw_value,
        default=_ROW_ZERO_INT,
        minimum=0,
        reason="shared_heartbeat_poison_mask_rejected",
    )
    if reason:
        raise ValueError(reason)
    return value


@dataclass(frozen=True, slots=True)
class SharedHeartbeatRow:
    pid: int
    heartbeat_time: float
    progress_counter: int
    stage: str
    bytes_processed: int
    last_progress_ns: int
    flags: int
    rss_mb: float
    completed_jobs: int
    state: str
    poison_mask: int
    signature: HeartbeatProgressSignature
    made_progress: bool


def parse_shared_heartbeat_row(
    *,
    row: object,
    record: Mapping[str, object],
    heartbeat_flags: object,
    monotonic_ns: Callable[[], int],
    wall_time: Callable[[], float],
) -> SharedHeartbeatRow:
    if scheduler_mapping_items(row) is None:
        raise ValueError("shared_heartbeat_row_mapping_rejected")
    row_monotonic = _row_int(row, "monotonic_ns")
    parent_monotonic = _callback_number(
        monotonic_ns, "parent_monotonic_ns", integer=True
    )
    parent_wall = _callback_number(wall_time, "parent_wall_time", integer=False)
    heartbeat_time = parent_wall - max(
        0.0, (parent_monotonic - row_monotonic) / 1_000_000_000.0
    )
    pid = _row_int(
        row,
        "pid",
        default_value=scheduler_mapping_value(record, "pid", default=_ROW_ZERO_INT),
    )
    progress = _row_int(row, "progress_counter")
    stage, stage_row_reason = scheduler_text(
        scheduler_mapping_value(
            row,
            "stage",
            default=scheduler_mapping_value(record, "stage", default="scan"),
        ),
        replacement_text=_ROW_BLANK_TEXT,
        unsupported_reason="shared_heartbeat_stage_rejected",
    )
    if stage_row_reason or stage == "":
        raise ValueError(stage_row_reason or "shared_heartbeat_stage_blank")
    bytes_processed = _row_int(row, "bytes_processed")
    last_progress_ns = _row_int(row, "last_progress_ns")
    flags = _row_int(row, "flags")
    rss_mb, rss_reason = scheduler_float(
        scheduler_mapping_value(row, "rss_mb", default=_ROW_ZERO_FLOAT),
        default=_ROW_ZERO_FLOAT,
        minimum=0.0,
        reason="shared_heartbeat_rss_mb_rejected",
    )
    if rss_reason:
        raise ValueError(rss_reason)
    completed_jobs = _row_int(row, "completed_jobs")
    state, state_reason = scheduler_text(
        scheduler_mapping_value(record, "state", default=_ROW_BLANK_TEXT),
        replacement_text=_ROW_UNKNOWN_TEXT,
        unsupported_reason="shared_heartbeat_state_rejected",
    )
    if state_reason:
        raise ValueError(state_reason)
    signature = heartbeat_progress_signature(
        stage=stage,
        progress_counter=progress,
        bytes_processed=bytes_processed,
        last_progress_ns=last_progress_ns,
    )
    return SharedHeartbeatRow(
        pid,
        heartbeat_time,
        progress,
        stage,
        bytes_processed,
        last_progress_ns,
        flags,
        rss_mb,
        completed_jobs,
        state,
        _poison_mask(heartbeat_flags),
        signature,
        heartbeat_progress_changed(record, signature),
    )


__all__ = (
    "SharedHeartbeatRow",
    "parse_shared_heartbeat_row",
)
