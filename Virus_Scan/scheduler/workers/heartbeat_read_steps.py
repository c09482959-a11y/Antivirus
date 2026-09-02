"""Bounded shared heartbeat read helpers."""
from __future__ import annotations

import time

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float
from Virus_Scan.scheduler.internal.owned_indexed_sequence import (
    is_owned_indexed_sequence,
    owned_indexed_get,
    owned_indexed_length,
)
from Virus_Scan.scheduler.workers.heartbeat_support import (
    heartbeat_stage_name,
    heartbeat_table_array,
    safe_heartbeat_int,
)

_HEARTBEAT_READ_UNAVAILABLE = None
_HEARTBEAT_READ_FIELDS = (
    (
        "stage",
        "heartbeat_stage_rejected",
        "heartbeat_stage_non_finite",
        "heartbeat_table_stage_short",
    ),
    (
        "monotonic_ns",
        "heartbeat_monotonic_ns_rejected",
        "heartbeat_monotonic_ns_non_finite",
        "heartbeat_table_monotonic_ns_short",
    ),
    ("pid", "heartbeat_pid_rejected", "heartbeat_pid_non_finite", "heartbeat_table_pid_short"),
    (
        "thread_id",
        "heartbeat_thread_id_rejected",
        "heartbeat_thread_id_non_finite",
        "heartbeat_table_thread_id_short",
    ),
    (
        "progress_counter",
        "heartbeat_progress_counter_rejected",
        "heartbeat_progress_counter_non_finite",
        "heartbeat_table_progress_counter_short",
    ),
    (
        "bytes_processed",
        "heartbeat_bytes_processed_rejected",
        "heartbeat_bytes_processed_non_finite",
        "heartbeat_table_bytes_processed_short",
    ),
    (
        "last_progress_ns",
        "heartbeat_last_progress_ns_rejected",
        "heartbeat_last_progress_ns_non_finite",
        "heartbeat_table_last_progress_ns_short",
    ),
    ("flags", "heartbeat_flags_rejected", "heartbeat_flags_non_finite", "heartbeat_table_flags_short"),
    (
        "completed_jobs",
        "heartbeat_completed_jobs_rejected",
        "heartbeat_completed_jobs_non_finite",
        "heartbeat_table_completed_jobs_short",
    ),
)


def heartbeat_generation_value(heartbeat_table: dict[object, object], jid: int) -> int:
    generations = heartbeat_table_array(heartbeat_table, "generation", writable=False)
    if jid >= owned_indexed_length(generations):
        raise ValueError("heartbeat_job_id_out_of_range")
    generation, reason = safe_heartbeat_int(
        owned_indexed_get(generations, jid),
        rejection_reason="heartbeat_generation_rejected",
        non_finite_reason="heartbeat_generation_non_finite",
    )
    if reason:
        raise ValueError(reason)
    return generation


def generation_matches_expected(generation: int, expected_generation: object) -> bool:
    if expected_generation is None:
        return True
    expected, reason = safe_heartbeat_int(
        expected_generation,
        rejection_reason="heartbeat_expected_generation_rejected",
        non_finite_reason="heartbeat_expected_generation_non_finite",
    )
    if reason:
        raise ValueError(reason)
    return generation == expected


def heartbeat_field_value(
    heartbeat_table: dict[object, object],
    jid: int,
    field: tuple[str, str, str, str],
) -> tuple[str, int]:
    key, rejected, non_finite, short_reason = field
    array = heartbeat_table_array(heartbeat_table, key, writable=False)
    if jid >= owned_indexed_length(array):
        raise ValueError(short_reason)
    parsed, reason = safe_heartbeat_int(
        owned_indexed_get(array, jid),
        rejection_reason=rejected,
        non_finite_reason=non_finite,
    )
    if reason:
        raise ValueError(reason)
    return key, parsed


def heartbeat_read_values(heartbeat_table: dict[object, object], jid: int) -> dict[str, int]:
    values: dict[str, int] = {}
    for field in _HEARTBEAT_READ_FIELDS:
        key, parsed = heartbeat_field_value(heartbeat_table, jid, field)
        values[key] = parsed
    return values


def heartbeat_rss_value(heartbeat_table: dict[object, object], jid: int) -> float:
    rss_array = dict.get(heartbeat_table, "rss_mb")
    if rss_array is None:
        return 0.0
    if not is_owned_indexed_sequence(rss_array, writable=False):
        raise ValueError("heartbeat_table_rss_mb_rejected")
    if jid >= owned_indexed_length(rss_array):
        raise ValueError("heartbeat_table_rss_mb_rejected")
    rss_mb, reason = no_hook_finite_float(
        owned_indexed_get(rss_array, jid),
        default=0.0,
        minimum=0.0,
        reason="heartbeat_rss_mb_rejected",
    )
    if reason:
        raise ValueError(reason)
    return rss_mb


def heartbeat_row_payload(generation: int, values: dict[str, int], rss_mb: float) -> dict[str, object]:
    return {
        "generation": generation,
        "pid": values["pid"],
        "thread_id": values["thread_id"],
        "stage_code": values["stage"],
        "stage": heartbeat_stage_name(values["stage"]),
        "progress_counter": values["progress_counter"],
        "bytes_processed": values["bytes_processed"],
        "last_progress_ns": values["last_progress_ns"],
        "monotonic_ns": values["monotonic_ns"],
        "flags": values["flags"],
        "rss_mb": rss_mb,
        "completed_jobs": values["completed_jobs"],
        "time": time.time(),
    }


def read_heartbeat_payload(
    heartbeat_table: dict[object, object],
    jid: int,
    generation: object,
) -> dict[str, object] | None:
    actual_generation = heartbeat_generation_value(heartbeat_table, jid)
    if not generation_matches_expected(actual_generation, generation):
        return _HEARTBEAT_READ_UNAVAILABLE
    values = heartbeat_read_values(heartbeat_table, jid)
    if values["monotonic_ns"] <= 0:
        return _HEARTBEAT_READ_UNAVAILABLE
    return heartbeat_row_payload(
        actual_generation,
        values,
        heartbeat_rss_value(heartbeat_table, jid),
    )


__all__ = (
    "read_heartbeat_payload",
)
