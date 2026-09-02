"""Queue-owned claim sidecar heartbeat lifecycle."""

from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_claim_meta_path as _queue_claim_meta_path
from Virus_Scan.scheduler.runtime.queue_json import queue_write_claim_meta
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace as _queue_atomic_replace, queue_safe_unlink as _queue_safe_unlink
from pathlib import Path
import json
import os
import time

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path


_CLAIM_HEARTBEAT_FAILED = False


def _umige_queue_now() -> float:
    """Scheduler queue heartbeat timestamp owner."""
    return float(time.time())


def _claim_heartbeat_failed(stage: str, exc: BaseException, *, claim_path: object = None, worker_id: object = None) -> bool:
    context: dict[str, object] = {
        "queue_claim_heartbeat_failed": True,
        "stage": str.__str__(stage),
        "exception_type": no_hook_type_name(exc),
        "error": scheduler_error_detail(exc),
        "final_json_must_record": True,
    }
    if claim_path is not None:
        context["claim_path_type"] = no_hook_type_name(claim_path)
    if worker_id is not None:
        context["worker_id_type"] = no_hook_type_name(worker_id)
    record_suppressed_failure(stage, exc, domain="scheduler", context=context)
    return _CLAIM_HEARTBEAT_FAILED


def _umige_read_claim_heartbeat_meta(claim_path: object) -> dict[str, object]:
    """Read active-claim heartbeat sidecar with explicit corruption markers."""
    try:
        mp = _queue_claim_meta_path(claim_path)
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        record_suppressed_failure('queue_claim_meta_path_failed', exc, domain='scheduler')
        return {"queue_info": {"claim_meta_unreadable": True, "claim_meta_error": scheduler_error_detail(exc), "heartbeat_time": _umige_queue_now(), "progress_marker": "claim_meta_path_failed"}}
    try:
        if not mp.exists():
            return {}
    except OSError as exc:
        record_suppressed_failure('queue_claim_meta_exists_failed', exc, domain='scheduler')
        return {"queue_info": {"claim_meta_unreadable": True, "claim_meta_error": scheduler_error_detail(exc), "heartbeat_time": _umige_queue_now(), "progress_marker": "claim_meta_exists_failed"}}
    try:
        with open(mp, "r", encoding="utf-8", errors="strict") as fh:
            data = json.load(fh)
        if type(data) is dict:
            return dict(data)
        invalid_shape = ValueError("claim metadata was not a JSON object")
        record_suppressed_failure('queue_claim_meta_invalid_shape', invalid_shape, domain='scheduler')
        return {"queue_info": {"claim_meta_invalid": True, "claim_meta_error": scheduler_error_detail(invalid_shape), "heartbeat_time": _umige_queue_now(), "progress_marker": "claim_meta_invalid"}}
    except (json.JSONDecodeError, OSError, UnicodeError, ValueError) as exc:
        now = _umige_queue_now()
        try:
            corrupt = mp.with_name(mp.name + ".corrupt.%d" % int(now * 1000000))
            _queue_atomic_replace(mp, corrupt, log_context="queue_claim_meta_corrupt_quarantine")
        except (OSError, RuntimeError, TypeError, ValueError) as quarantine_exc:
            record_suppressed_failure('queue_claim_meta_corrupt_quarantine_failed', quarantine_exc, domain='scheduler')
        record_suppressed_failure('queue_claim_meta_corrupt', exc, domain='scheduler')
        return {"queue_info": {"claim_meta_corrupt": True, "claim_meta_error": scheduler_error_detail(exc), "heartbeat_time": float(now), "progress_time": float(now), "progress_marker": "claim_meta_corrupt_recovery"}}


def _umige_remove_claim_heartbeat_meta(claim_path: object) -> bool:
    """Remove active-claim heartbeat sidecar for a missing/finished claim."""
    try:
        return bool(_queue_safe_unlink(_queue_claim_meta_path(claim_path), log_context="queue_claim_meta_cleanup"))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return _claim_heartbeat_failed("queue_claim_meta_cleanup_failed", exc, claim_path=claim_path)


def _umige_update_claim_heartbeat(claim_path: object, job: object = None, worker_id: object = "worker") -> bool:
    """Refresh claim sidecar heartbeat without rewriting active job JSON."""
    try:
        if claim_path is None:
            raise ValueError("queue_claim_heartbeat_path_missing")
        filesystem_path, path_reason = scheduler_filesystem_path(claim_path)
        if path_reason:
            raise ValueError(path_reason)
        cp = Path(filesystem_path)
        if not cp.exists():
            _umige_remove_claim_heartbeat_meta(cp)
            return _CLAIM_HEARTBEAT_FAILED
        meta: dict[str, object] = _umige_read_claim_heartbeat_meta(cp)
        qi_value = dict.get(meta, "queue_info")
        qi = dict(qi_value) if type(qi_value) is dict else {}
        job_info_value = dict.get(job, "queue_info") if type(job) is dict else None
        job_info = dict(job_info_value) if type(job_info_value) is dict else {}
        if not qi and job_info:
            qi.update(job_info)
        now = _umige_queue_now()
        worker_text, worker_reason = no_hook_text(
            worker_id,
            missing_reason="queue_claim_worker_id_missing",
            unsupported_reason="queue_claim_worker_id_rejected",
        )
        if worker_reason == "" and worker_text:
            safe_worker_id, worker_issue = worker_text, ""
        elif worker_reason:
            safe_worker_id, worker_issue = worker_reason, worker_reason
        else:
            safe_worker_id = "queue_claim_worker_id_empty"
            worker_issue = "queue_claim_worker_id_empty"
        qi.update({
            "worker_id": safe_worker_id,
            "worker_pid": int(os.getpid()),
            "heartbeat_time": float(now),
            "heartbeat_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        })
        if "claimed_time" not in qi:
            qi["claimed_time"] = float(now)
        if "claimed_iso" not in qi:
            qi["claimed_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        if "progress_time" not in qi:
            claimed_time = dict.get(qi, "claimed_time")
            if type(claimed_time) is int and type(claimed_time) is not bool:
                qi["progress_time"] = claimed_time + 0.0
            elif type(claimed_time) is float:
                qi["progress_time"] = float.__float__(claimed_time)
            else:
                qi["progress_time"] = float(now)
        if worker_issue:
            qi["worker_id_issue"] = worker_issue
            qi["worker_id_type"] = no_hook_type_name(worker_id)
        if "progress_marker" not in qi:
            qi["progress_marker"] = "heartbeat_only"
        meta["queue_info"] = qi
        meta["claim_job"] = cp.name
        meta["claim_meta_version"] = 1
        if type(job) is dict:
            for k in ("file", "queue_file_id", "job_type", "file_id", "collector", "seq", "attempt", "index", "order"):
                if k in job and k not in meta:
                    meta[k] = job.get(k)
        if not cp.exists():
            _umige_remove_claim_heartbeat_meta(cp)
            return _CLAIM_HEARTBEAT_FAILED
        return bool(queue_write_claim_meta(cp, meta, log_context="queue_heartbeat_sidecar_replace"))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return _claim_heartbeat_failed('queue_claim_heartbeat_failed', exc, claim_path=claim_path, worker_id=worker_id)



# Public heartbeat contract used outside the queue subdomain.
umige_update_claim_heartbeat = _umige_update_claim_heartbeat
