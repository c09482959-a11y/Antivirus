"""Queue failure diagnostic persistence for scheduler JSON claims."""
from __future__ import annotations

from pathlib import Path
import time

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_failure_diagnostics_dir
from Virus_Scan.scheduler.runtime.queue_filesystem_common import queue_filesystem_path_text
from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS, record_queue_json_degraded
from Virus_Scan.scheduler.runtime.queue_json_failure_info import queue_default_failure_info, _queue_failure_field
from Virus_Scan.scheduler.runtime.queue_json_publication import read_json_file, queue_write_json_replace
from Virus_Scan.scheduler.runtime.queue_json_safety import make_json_safe

QUEUE_FAILURE_RECORDED = True
QUEUE_FAILURE_NOT_RECORDED = False


def record_process_queue_failure(
    queue_dir: object,
    claim_path: object,
    job: object = None,
    error_info: object = None,
) -> bool:
    """Persist explicit scheduler queue failure diagnostics before finalization."""
    try:
        claim_text, claim_reason = queue_filesystem_path_text(claim_path)
        if claim_reason:
            record_queue_json_degraded("queue_failure_claim_path_rejected", ValueError(claim_reason), domain="scheduler")
        payload: dict[str, object] = {}
        if claim_text != "" and Path(claim_text).exists():
            raw_payload = read_json_file(claim_text, default={}) or {}
            payload = raw_payload if type(raw_payload) is dict else {}
        job_items = no_hook_mapping_items(job)
        if job_items is not None:
            for key, value in job_items:
                if key not in payload or dict.get(payload, key) in (None, ""):
                    payload[key] = value
        payload["queue_failure"] = True
        error_items = no_hook_mapping_items(error_info)
        mapped_error = (error_info if type(error_info) is dict else None) if error_items is None else dict(error_items)
        if mapped_error is not None and len(mapped_error) > 0:
            failure_info = mapped_error
        else:
            history = dict.get(payload, "queue_reclaim_history") or []
            last = history[-1] if type(history) is list and len(history) > 0 and type(history[-1]) is dict else None
            if last is not None:
                materialized_last = materialize_scheduler_mapping(last)
                failure_info = materialized_last if type(materialized_last) is dict else queue_default_failure_info(
                    "queue_reclaim_failed",
                    exception_type="QueueReclaimFailure",
                    error="queue reclaim history was not materializable",
                )
                _queue_failure_field(failure_info, "stage", "queue_reclaim_failed")
                _queue_failure_field(failure_info, "exception_type", "QueueReclaimFailure")
                _queue_failure_field(failure_info, "error", "queue job failed after reclaim/retry")
                _queue_failure_field(failure_info, "time", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            else:
                raw_qinfo = dict.get(payload, "queue_info")
                qinfo = raw_qinfo if type(raw_qinfo) is dict else {}
                qinfo_worker_pid = dict.get(qinfo, "worker_pid")
                worker_pid = qinfo_worker_pid or dict.get(payload, "worker_pid")
                failure_info = queue_default_failure_info(
                    "queue_finalize_without_diagnostics",
                    exception_type="MissingQueueFailureInfo",
                    error="queue job was sent to failed/ without explicit failure_info; synthesized during finalization",
                    worker_pid=worker_pid,
                    attempt=dict.get(payload, "attempt"),
                )
        payload["failure_info"] = make_json_safe(failure_info)
        if claim_text == "":
            claim_written = QUEUE_FAILURE_RECORDED
        else:
            ok = queue_write_json_replace(
                claim_text,
                payload,
                tmp_suffix=".failure.tmp",
                verify=True,
                log_context="queue_failure_claim_rewrite",
            )
            if not ok:
                record_queue_json_degraded("queue_failure_claim_rewrite_failed", ValueError("queue_failure_claim_rewrite_failed"), domain="scheduler")
                return QUEUE_FAILURE_NOT_RECORDED
            verify = read_json_file(claim_text, default={}) or {}
            verify_failure_info = dict.get(verify, "failure_info") if type(verify) is dict else None
            claim_written = type(verify) is dict and type(verify_failure_info) is dict and len(verify_failure_info) > 0
        diag_dir = queue_failure_diagnostics_dir(queue_dir)
        name = Path(claim_text).name if claim_text != "" else "unknown_" + int.__str__(time.time_ns()) + ".json"
        diag_written = queue_write_json_replace(
            diag_dir / name,
            payload,
            tmp_suffix=".tmp",
            verify=True,
            log_context="queue_diag_move",
        )
        if diag_written is True and claim_written is True:
            return QUEUE_FAILURE_RECORDED
        record_queue_json_degraded("queue_failure_diagnostic_write_incomplete", ValueError("queue_failure_diagnostic_write_incomplete"), domain="scheduler")
        return QUEUE_FAILURE_NOT_RECORDED
    except QUEUE_JSON_EXCEPTIONS as exc:
        try:
            log_error("queue failure diagnostic write failed: " + no_hook_type_name(exc))
        except QUEUE_JSON_EXCEPTIONS as logging_exc:
            record_queue_json_degraded("queue_failure_logging_failed", logging_exc, domain="telemetry")
        record_queue_json_degraded("queue_failure_diagnostic_write_exception", ValueError("queue_failure_diagnostic_write_exception"), domain="scheduler")
        return QUEUE_FAILURE_NOT_RECORDED

