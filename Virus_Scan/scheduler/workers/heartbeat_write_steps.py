"""Bounded shared heartbeat write helpers."""
from __future__ import annotations

import time
from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text
from Virus_Scan.scheduler.internal.owned_indexed_sequence import (
    is_owned_indexed_sequence,
    owned_indexed_length,
    owned_indexed_set,
)
from Virus_Scan.scheduler.workers.heartbeat_support import (
    heartbeat_stage_code,
    heartbeat_table_array,
    safe_heartbeat_int,
)
from Virus_Scan.scheduler.workers.heartbeat_write_fields import (
    HEARTBEAT_ARRAY_KEYS,
    heartbeat_int_fields,
    parsed_heartbeat_ints,
)


@dataclass(frozen=True)
class HeartbeatWriteValues:
    jid: int
    generation: int
    rss_mb: float
    values: dict[str, int]


def heartbeat_write_values(
    *,
    job_id: object,
    generation: object,
    pid: object,
    thread_id: object,
    stage: object,
    progress_counter: object,
    bytes_processed: object,
    last_progress_ns: object,
    flags: object,
    rss_mb: object,
    completed_jobs: object,
) -> HeartbeatWriteValues | str:
    jid, jid_reason = safe_heartbeat_int(
        job_id,
        rejection_reason="heartbeat_job_id_rejected",
        non_finite_reason="heartbeat_job_id_non_finite",
    )
    gen, gen_reason = safe_heartbeat_int(
        generation,
        rejection_reason="heartbeat_generation_rejected",
        non_finite_reason="heartbeat_generation_non_finite",
    )
    if jid_reason or gen_reason:
        return jid_reason or gen_reason
    now_ns = time.monotonic_ns()
    parsed, int_reason = parsed_heartbeat_ints(
        heartbeat_int_fields(
            now_ns=now_ns,
            pid=pid,
            thread_id=thread_id,
            progress_counter=progress_counter,
            bytes_processed=bytes_processed,
            last_progress_ns=last_progress_ns,
            flags=flags,
            completed_jobs=completed_jobs,
        )
    )
    if parsed is None:
        return int_reason
    rss_value, rss_reason = no_hook_finite_float(
        rss_mb, default=0.0, minimum=0.0, reason="heartbeat_rss_mb_rejected"
    )
    stage_text, stage_reason = no_hook_text(
        stage,
        missing_reason="heartbeat_stage_missing",
        unsupported_reason="heartbeat_stage_rejected",
    )
    if rss_reason or stage_reason:
        return rss_reason or stage_reason
    return HeartbeatWriteValues(
        jid=jid,
        generation=gen,
        rss_mb=rss_value,
        values={
            "monotonic_ns": now_ns,
            "generation": gen,
            "pid": parsed["pid"],
            "thread_id": parsed["thread_id"] & 0x7FFFFFFF,
            "stage": heartbeat_stage_code(stage_text),
            "progress_counter": parsed["progress_counter"],
            "bytes_processed": parsed["bytes_processed"],
            "last_progress_ns": parsed["last_progress_ns"],
            "flags": parsed["flags"],
            "completed_jobs": parsed["completed_jobs"],
        },
    )


def heartbeat_write_arrays(heartbeat_table: dict[object, object]) -> dict[str, object]:
    arrays: dict[str, object] = {}
    for key in HEARTBEAT_ARRAY_KEYS:
        arrays[key] = heartbeat_table_array(heartbeat_table, key, writable=True)
    return arrays


def validate_heartbeat_row_bounds(arrays: dict[str, object], jid: int) -> None:
    for key in HEARTBEAT_ARRAY_KEYS:
        if jid >= owned_indexed_length(arrays[key]):
            raise ValueError("heartbeat_job_id_out_of_range")


def write_core_heartbeat_arrays(arrays: dict[str, object], parsed: HeartbeatWriteValues) -> None:
    for key in HEARTBEAT_ARRAY_KEYS:
        owned_indexed_set(arrays[key], parsed.jid, parsed.values[key])


def write_optional_rss_array(heartbeat_table: dict[object, object], parsed: HeartbeatWriteValues) -> None:
    rss_array = dict.get(heartbeat_table, "rss_mb")
    if rss_array is None:
        return
    if not is_owned_indexed_sequence(rss_array, writable=True):
        raise ValueError("heartbeat_table_rss_mb_rejected")
    if parsed.jid >= owned_indexed_length(rss_array):
        raise ValueError("heartbeat_table_rss_mb_rejected")
    owned_indexed_set(rss_array, parsed.jid, parsed.rss_mb)


def write_heartbeat_row(heartbeat_table: dict[object, object], parsed: HeartbeatWriteValues) -> None:
    arrays = heartbeat_write_arrays(heartbeat_table)
    validate_heartbeat_row_bounds(arrays, parsed.jid)
    write_core_heartbeat_arrays(arrays, parsed)
    write_optional_rss_array(heartbeat_table, parsed)


__all__ = (
    "HeartbeatWriteValues",
    "heartbeat_write_values",
    "write_heartbeat_row",
)
