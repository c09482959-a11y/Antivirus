"""Canonical scheduler claim metadata read/remove/merge ownership.
Owns claim metadata lifecycle helpers without raw_queue imports.
"""
from __future__ import annotations
import json
from types import BuiltinFunctionType

from Virus_Scan.contracts.runtime_function_identity import RUNTIME_NATIVE_FUNCTION_TYPE
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace
from Virus_Scan.scheduler.queue.claim_meta_support import (
    CLAIM_META_REMOVE_FAILED,
    claim_marker,
    claim_meta_path_extra,
    claim_meta_path_value,
    claim_meta_remove_failed,
    claim_time,
    claim_time_suffix,
)

_SAFE_UNLINK_CALLABLE_TYPES = (RUNTIME_NATIVE_FUNCTION_TYPE, BuiltinFunctionType)


def unreadable_claim_meta_info(exc: object, *, now: object, marker: object) -> object:
    """Build deterministic queue_info for unreadable claim metadata."""
    heartbeat_time, time_reason = claim_time(now)
    marker_text, marker_reason = claim_marker(marker)
    queue_info = {
        "claim_meta_unreadable": True,
        "claim_meta_error": scheduler_exception_text(exc, max_length=500),
        "heartbeat_time": heartbeat_time,
        "progress_marker": marker_text,
    }
    if time_reason:
        queue_info["claim_meta_time_unavailable"] = time_reason
    if marker_reason:
        queue_info["claim_meta_marker_unavailable"] = marker_reason
    return {
        "queue_info": queue_info
    }
def invalid_claim_meta_info(exc: object, *, now: object, marker: object="claim_meta_invalid") -> object:
    """Build deterministic queue_info for invalid/corrupt claim metadata."""
    failure_time, time_reason = claim_time(now)
    marker_text, marker_reason = claim_marker(marker)
    queue_info = {
        "claim_meta_invalid": True,
        "claim_meta_error": scheduler_exception_text(exc, max_length=500),
        "heartbeat_time": failure_time,
        "progress_time": failure_time,
        "progress_marker": marker_text,
    }
    if time_reason:
        queue_info["claim_meta_time_unavailable"] = time_reason
    if marker_reason:
        queue_info["claim_meta_marker_unavailable"] = marker_reason
    return {
        "queue_info": queue_info
    }
def read_claim_meta(
    claim_path: object,
    *,
    claim_meta_path: object,
    now: object,
    report: object,
) -> object:
    """Read a claim sidecar with explicit corruption quarantine semantics.
    Returns an empty dict for absent metadata.  Unreadable, invalid, or corrupt
    metadata is surfaced as queue_info and reported; it is never treated as a
    silent absence of ownership.
    """
    current_raw = now()
    current, current_reason = claim_time(current_raw)
    if current_reason:
        failure = ValueError(current_reason)
        report("queue_claim_meta_clock_failed", failure, fatal=True)
        return unreadable_claim_meta_info(
            failure,
            now=current_raw,
            marker="claim_meta_clock_failed",
        )
    try:
        mp = claim_meta_path_value(claim_path, claim_meta_path)
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        report("queue_claim_meta_path_failed", exc, fatal=True)
        return unreadable_claim_meta_info(exc, now=current, marker="claim_meta_path_failed")
    try:
        if not mp.exists():
            return {}
    except OSError as exc:
        report("queue_claim_meta_exists_failed", exc, fatal=True, extra=claim_meta_path_extra(mp))
        return unreadable_claim_meta_info(exc, now=now(), marker="claim_meta_exists_failed")
    try:
        with mp.open("r", encoding="utf-8", errors="strict") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
        shape_error = ValueError("claim metadata was not a JSON object")
        report("queue_claim_meta_invalid_shape", shape_error, fatal=True, extra=claim_meta_path_extra(mp))
        return invalid_claim_meta_info(shape_error, now=now(), marker="claim_meta_invalid")
    except (json.JSONDecodeError, OSError, UnicodeError, ValueError) as exc:
        corrupt_now_raw = now()
        _corrupt_now, corrupt_time_reason = claim_time(corrupt_now_raw)
        if corrupt_time_reason:
            report(
                "queue_claim_meta_corrupt_clock_failed",
                ValueError(corrupt_time_reason),
                fatal=True,
            )
        try:
            corrupt = mp.with_name(mp.name + ".corrupt." + claim_time_suffix(corrupt_now_raw))
            queue_atomic_replace(mp, corrupt, log_context="queue_claim_meta_corrupt_quarantine")
        except (OSError, RuntimeError, TypeError, ValueError) as quarantine_exc:
            report("queue_claim_meta_corrupt_quarantine_failed", quarantine_exc, fatal=True, extra=claim_meta_path_extra(mp))
        report("queue_claim_meta_corrupt", exc, fatal=True, extra=claim_meta_path_extra(mp))
        info = invalid_claim_meta_info(exc, now=corrupt_now_raw, marker="claim_meta_corrupt_recovery")
        info["queue_info"]["claim_meta_corrupt"] = True
        return info
def remove_claim_meta(claim_path: object, *, claim_meta_path: object, safe_unlink: object, report: object) -> object:
    """Remove a claim sidecar through the caller's durable unlink primitive."""
    try:
        meta_path = claim_meta_path_value(claim_path, claim_meta_path)
        unlink_dependency = safe_unlink
        if type(unlink_dependency) not in _SAFE_UNLINK_CALLABLE_TYPES:
            raise ValueError("scheduler_claim_meta_unlink_callable_rejected")
        removed, reason = scheduler_bool(
            unlink_dependency(meta_path, log_context="queue_claim_meta_cleanup"),
            reason="scheduler_claim_meta_unlink_result_rejected",
        )
        if reason:
            report("queue_claim_meta_cleanup_result_rejected", ValueError(reason))
            return CLAIM_META_REMOVE_FAILED
        return removed
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return claim_meta_remove_failed(report, "queue_claim_meta_cleanup_failed", exc)
def merge_claim_meta_into_job(claim_path: object, job: object=None, **dependency_callbacks: object) -> object:
    """Return a copy of job with queue_info populated from the claim sidecar."""
    claim_meta_reader = dependency_callbacks["read_claim_meta"]
    job_items = no_hook_mapping_items(job)
    if job is not None and job_items is None:
        payload = {
            "queue_info": {
                "claim_meta_job_rejected": True,
                "value_type": no_hook_type_name(job),
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_record": True,
            }
        }
    else:
        payload = dict(job_items) if job_items is not None else {}
    meta = claim_meta_reader(claim_path)
    queue_info = {}
    payload_queue_items = no_hook_mapping_items(dict.get(payload, "queue_info"))
    if payload_queue_items is not None:
        queue_info.update(dict(payload_queue_items))
    meta_items = no_hook_mapping_items(meta)
    meta_snapshot = dict(meta_items) if meta_items is not None else {}
    meta_queue_items = no_hook_mapping_items(dict.get(meta_snapshot, "queue_info"))
    if meta_queue_items is not None:
        queue_info.update(dict(meta_queue_items))
    elif meta_items is not None:
        queue_info.update(meta_snapshot)
    elif meta is not None:
        queue_info.update({
            "claim_meta_result_rejected": True,
            "value_type": no_hook_type_name(meta),
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        })
    if queue_info:
        payload["queue_info"] = queue_info
    return payload
