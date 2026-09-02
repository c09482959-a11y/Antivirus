"""Support owner for core JSON queue-failure diagnostic persistence."""

from pathlib import Path

from Virus_Scan.core import jsonio_queue_failure_io as _queue_failure_io

rewrite_queue_failure_claim = _queue_failure_io.rewrite_queue_failure_claim
write_queue_failure_diagnostic = _queue_failure_io.write_queue_failure_diagnostic


def queue_failure_claim_text(claim_path: object, *, core_path_text: object, record_degraded: object) -> object:
    if claim_path is None:
        return None
    claim_text, claim_reason = core_path_text(
        claim_path,
        field_name="queue_failure_claim_path",
    )
    if claim_reason:
        record_degraded(
            "queue_failure_claim_path_rejected",
            ValueError(claim_reason),
            domain="scheduler",
        )
        return None
    return claim_text


def queue_failure_payload(claim_text: object, *, read_json: object) -> dict[object, object]:
    payload: object = {}
    if claim_text is not None and Path(claim_text).exists():
        payload = read_json(claim_text, default={}) or {}
    if type(payload) is not dict:
        return {}
    return payload


def merge_queue_failure_job(
    payload: dict[object, object],
    job: object,
    *,
    mapping_items: object,
    unsupported_value: object,
) -> None:
    job_items = mapping_items(job)
    if job_items is not None:
        for key, value in job_items:
            if key not in payload or dict.get(payload, key) in (None, ""):
                payload[key] = value
        return
    if job is not None:
        payload["job_unavailable"] = unsupported_value(
            job,
            field_name="queue_failure_job",
            reason="queue_failure_job_mapping_rejected",
        )


def queue_failure_error_info(
    payload: dict[object, object],
    error_info: object,
    *,
    mapping_items: object,
    queue_failure_info: object,
    unsupported_value: object,
    make_json_safe_func: object,
    time_module: object,
) -> object:
    error_items = mapping_items(error_info)
    if error_items is not None and len(error_items) > 0:
        return dict(error_items)
    if error_info is not None and error_items is None:
        payload["error_info_unavailable"] = unsupported_value(
            error_info,
            field_name="queue_failure_error_info",
            reason="queue_failure_error_info_mapping_rejected",
        )
    history = dict.get(payload, "queue_reclaim_history") or []
    last = history[-1] if _queue_failure_last_history_is_mapping(history) else None
    if last:
        return _queue_failure_info_from_history(last, mapping_items, time_module)
    return _queue_failure_info_from_payload(payload, queue_failure_info, make_json_safe_func)


def _queue_failure_last_history_is_mapping(history: object) -> bool:
    return type(history) is list and len(history) > 0 and type(history[-1]) is dict


def _queue_failure_info_from_history(last: object, mapping_items: object, time_module: object) -> object:
    last_items = mapping_items(last)
    error_info = dict(last_items) if last_items is not None else {}
    if "stage" not in error_info:
        error_info["stage"] = "queue_reclaim_failed"
    if "exception_type" not in error_info:
        error_info["exception_type"] = "QueueReclaimFailure"
    if "error" not in error_info:
        error_info["error"] = "queue job failed after reclaim/retry"
    if "time" not in error_info:
        error_info["time"] = time_module.strftime("%Y-%m-%dT%H:%M:%SZ", time_module.gmtime())
    return error_info


def _queue_failure_info_from_payload(payload: dict[object, object], queue_failure_info: object, make_json_safe_func: object) -> object:
    queue_info = dict.get(payload, "queue_info")
    qinfo = queue_info if type(queue_info) is dict else {}
    worker_pid = dict.get(qinfo, "worker_pid") if qinfo else dict.get(payload, "worker_pid")
    safe_worker_pid = make_json_safe_func(worker_pid, "worker_pid") if worker_pid is not None else None
    attempt = dict.get(payload, "attempt")
    safe_attempt = make_json_safe_func(attempt, "attempt") if attempt is not None else None
    return queue_failure_info(
        stage="queue_finalize_without_diagnostics",
        exception_type="MissingQueueFailureInfo",
        error="queue job was sent to failed/ without explicit failure_info; synthesized during finalization",
        worker_pid=safe_worker_pid,
        attempt=safe_attempt,
    )
