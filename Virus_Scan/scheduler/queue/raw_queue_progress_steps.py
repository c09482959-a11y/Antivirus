"""Bounded raw-owner progress evidence steps."""
from __future__ import annotations

from Virus_Scan.contracts.env_config import float_env
from Virus_Scan.scheduler.queue.raw_queue_progress_evidence import (
    raw_progress_bool,
    raw_progress_expected,
    raw_progress_extra,
    raw_progress_float,
    raw_progress_mapping,
    raw_progress_path_mtime,
    raw_progress_quiet_seconds,
)


def raw_owner_progress_info() -> dict[str, object]:
    return {
        "has_accumulator": False,
        "complete": False,
        "recent": False,
        "age": None,
        "file_id": None,
    }


def load_raw_owner_progress_data(
    *,
    info: dict[str, object],
    data: object,
    fid: object,
    queue_dir: object,
    file_path: object,
    report: object,
) -> dict[str, object] | None:
    data_decision = raw_progress_mapping(data)
    raw_data = data_decision.value
    if not data_decision.available or raw_data is None:
        extra = data_decision.as_extra()
        info["progress_mapping_unavailable"] = extra
        report(
            "queue_raw_owner_progress_mapping_unavailable",
            ValueError(data_decision.reason),
            fatal=False,
            extra={**raw_progress_extra(queue_dir, file_path), **extra},
        )
        return None
    if dict.get(raw_data, "file_id") != fid:
        return None
    expected = raw_progress_expected(dict.get(raw_data, "expected", 0))
    if expected <= 0:
        return None
    info["has_accumulator"] = True
    return raw_data


def apply_raw_owner_completion(
    *,
    info: dict[str, object],
    complete: object,
    queue_dir: object,
    file_path: object,
    report: object,
) -> bool:
    complete_decision = raw_progress_bool(
        complete,
        field_name="raw_progress_complete",
        reason="raw_progress_complete_rejected",
    )
    info["complete"] = complete_decision.value
    if not complete_decision.accepted:
        extra = complete_decision.as_extra()
        info["complete_unavailable"] = extra
        report(
            "queue_raw_owner_progress_complete_unavailable",
            ValueError(complete_decision.reason),
            fatal=False,
            extra={**raw_progress_extra(queue_dir, file_path), **extra},
        )
    return complete_decision.value


def raw_owner_updated_timestamp(
    *,
    info: dict[str, object],
    data: dict[str, object],
    store_path: object,
    report: object,
) -> float:
    updated = raw_progress_float(dict.get(data, "updated_at"), 0.0)
    if updated > 0.0:
        return updated
    mtime = raw_progress_path_mtime(store_path)
    if mtime.available:
        return mtime.value
    info["mtime_unavailable"] = mtime.as_extra()
    report(
        "queue_raw_owner_progress_mtime_unavailable",
        ValueError(mtime.reason),
        fatal=False,
        extra=mtime.as_extra(),
    )
    return mtime.value


def raw_owner_quiet_seconds(quiet_sec: object) -> float:
    if quiet_sec is None:
        quiet_raw = float_env("UMIGE_RAW_RECOVERY_QUIET_SEC", 120.0, 0.0, None)
    else:
        quiet_raw = quiet_sec
    return raw_progress_quiet_seconds(quiet_raw)


def apply_raw_owner_recent(
    *,
    info: dict[str, object],
    age: float | None,
    quiet: float,
    queue_dir: object,
    file_path: object,
    raw_stage_progress_recent: object,
    report: object,
) -> None:
    recent_accum = type(age) is float and age < quiet
    recent_global = raw_stage_progress_recent(queue_dir, quiet_sec=quiet)
    recent_global_decision = raw_progress_bool(
        recent_global,
        field_name="raw_progress_recent_global",
        reason="raw_progress_recent_global_rejected",
    )
    if not recent_global_decision.accepted:
        extra = recent_global_decision.as_extra()
        info["recent_global_unavailable"] = extra
        report(
            "queue_raw_owner_progress_recent_global_unavailable",
            ValueError(recent_global_decision.reason),
            fatal=False,
            extra={**raw_progress_extra(queue_dir, file_path), **extra},
        )
    info["recent"] = recent_accum or recent_global_decision.value


__all__ = (
    "apply_raw_owner_completion",
    "apply_raw_owner_recent",
    "load_raw_owner_progress_data",
    "raw_owner_progress_info",
    "raw_owner_quiet_seconds",
    "raw_owner_updated_timestamp",
)
