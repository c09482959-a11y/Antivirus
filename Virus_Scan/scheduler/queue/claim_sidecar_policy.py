"""Canonical scheduler claim sidecar construction and active-claim protection.

Owns deterministic claim sidecar metadata and protection policy only.
"""

from __future__ import annotations

import time

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.queue.claim_sidecar_active_protection import (
    active_claim_is_protected_with_dependencies,
)
from Virus_Scan.scheduler.queue.claim_sidecar_policy_support import (
    CLAIM_SIDECAR_POLICY_WRITE_FAILED,
    active_claim_grace_seconds,
    policy_nonnegative_time,
    policy_pid,
)
from Virus_Scan.scheduler.queue.raw_queue_path_support import materialize_raw_queue_path
from Virus_Scan.scheduler.queue.text_reason_support import queue_text_or_empty_reason
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from collections.abc import Callable


def active_claim_grace_sec(
    environ: object | None = None,
    *,
    default: float = 60.0,
    minimum: float = 15.0,
    report: Callable[..., object] | None = None,
) -> float:
    """Return the active-claim grace window with explicit error reporting."""
    return active_claim_grace_seconds(environ, default=default, minimum=minimum, report=report)


def build_claim_sidecar_meta(
    claim_path: object,
    job: object,
    *,
    now: object,
    pid: object,
    worker_id: object = "worker",
    progress_marker: object = "claimed",
) -> tuple[dict[str, object], dict[str, object]]:
    """Build deterministic claim sidecar metadata without mutating the job."""
    claim = materialize_raw_queue_path(claim_path, reason="queue_claim_sidecar_path_rejected")
    claim_time = policy_nonnegative_time(now, reason="queue_claim_sidecar_time_rejected")
    worker_pid = policy_pid(pid)
    worker_text, worker_reason = queue_text_or_empty_reason(
        worker_id,
        missing_reason="queue_claim_worker_id_missing",
        unsupported_reason="queue_claim_worker_id_rejected",
        empty_reason="queue_claim_worker_id_empty",
    )
    progress_text, progress_reason = queue_text_or_empty_reason(
        progress_marker,
        missing_reason="queue_claim_progress_marker_missing",
        unsupported_reason="queue_claim_progress_marker_rejected",
        empty_reason="queue_claim_progress_marker_empty",
    )
    qi = {}
    if type(job) is dict:
        job_queue_info = dict.get(job, "queue_info")
        if type(job_queue_info) is dict:
            qi.update(job_queue_info)
    qi.update(
        {
            "worker_id": worker_text,
        "worker_pid": worker_pid,
        "claimed_time": claim_time,
        "heartbeat_time": claim_time,
        "progress_time": claim_time,
        "progress_marker": progress_text,
        "claimed_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(claim_time)),
            "heartbeat_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(claim_time)),
        }
    )
    if worker_reason:
        qi["worker_id_issue"] = worker_reason
        qi["worker_id_type"] = no_hook_type_name(worker_id)
    if progress_reason:
        qi["progress_marker_issue"] = progress_reason
        qi["progress_marker_type"] = no_hook_type_name(progress_marker)
    meta = {
        "queue_info": qi,
        "claim_job": claim.name,
        "claim_meta_version": 1,
    }
    if type(job) is dict:
        for key in (
            "file",
            "queue_file_id",
            "job_type",
            "file_id",
            "collector",
            "seq",
            "attempt",
            "index",
            "order",
        ):
            if key in job:
                meta[key] = job.get(key)
    return meta, qi


def active_claim_is_protected(
    path: object,
    job: object | None = None,
    *,
    now: float | None = None,
    grace: float | None = None,
    path_age: Callable[[Path, float], float | None],
    read_json: Callable[..., object],
    merge_claim_meta: Callable[[Path, object], object],
    pid_is_alive: Callable[[object], bool],
    queue_now: Callable[[], float],
    report: Callable[..., object],
) -> bool:
    """Return True when an active claim remains worker-owned."""
    return active_claim_is_protected_with_dependencies(
        path,
        job,
        now=now,
        grace=grace,
        path_age=path_age,
        read_json=read_json,
        merge_claim_meta=merge_claim_meta,
        pid_is_alive=pid_is_alive,
        queue_now=queue_now,
        report=report,
    )

def write_claim_sidecar_from_job(
    claim_path: object,
    job: object,
    *,
    worker_id: object = "worker",
    progress_marker: object = "claimed",
    now: Callable[[], object],
    pid: Callable[[], object],
    write_claim_meta: Callable[..., object],
    report: Callable[..., object],
    os_fspath: Callable[[object], object],
) -> bool:
    """Build and persist the initial claim sidecar for a claimed job."""
    del os_fspath  # Explicitly unused contract parameters.
    try:
        meta, queue_info = build_claim_sidecar_meta(
            claim_path,
            job,
            now=now(),
            pid=pid(),
            worker_id=worker_id,
            progress_marker=progress_marker,
        )
        ok = write_claim_meta(claim_path, meta, log_context="queue_claim_sidecar_write")
        if ok is True and type(job) is dict:
            job["queue_info"] = queue_info
        return ok is True
    except (OSError, RuntimeError, TypeError, ValueError, OverflowError) as exc:
        report(
            "queue_claim_sidecar_write_failed",
            exc,
            fatal=True,
            extra={
                "claim": scheduler_evidence_path(claim_path, field_name="claim")
                if claim_path is not None
                else "missing_claim"
            },
        )
        return CLAIM_SIDECAR_POLICY_WRITE_FAILED
