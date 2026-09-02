"""Queue-owned durable process-queue job publication."""
from __future__ import annotations

import json
from pathlib import Path


from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as record_scheduler_suppressed
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace as _queue_atomic_replace, queue_safe_unlink as _queue_safe_unlink
from Virus_Scan.scheduler.runtime.queue_json import make_json_safe, validate_persistent_record_semantics, verify_persistent_json_file
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path, scheduler_text
from Virus_Scan.runtime.api import flush_open_writable_file


_DURABLE_WRITE_FAILED = False


def _write_queue_job_json_durable(tmp: object, final: object, job: object, *, log_context: str = "queue_tmp_to_final") -> bool:
    """Durably publish a pending queue job or fail closed."""
    tmp = Path(tmp)
    final = Path(final)
    safe_log_context, context_reason = scheduler_text(
        log_context,
        replacement_text="queue_tmp_to_final",
        unsupported_reason="queue_job_log_context_rejected",
    )
    tmp_context = safe_log_context + "_tmp"
    tmp_cleanup_context = safe_log_context + "_tmp_cleanup"
    durability_cleanup_context = safe_log_context + "_durability_cleanup"
    path_extra = {
        "tmp": scheduler_evidence_path(tmp, field_name="queue_job_tmp"),
        "final": scheduler_evidence_path(final, field_name="queue_job_final"),
    }
    if context_reason:
        path_extra = dict(path_extra, log_context_issue=context_reason)
    try:
        expected = make_json_safe(job)
        validate_persistent_record_semantics(expected, context=safe_log_context)
        with Path(tmp).open("w", encoding="utf-8") as fh:
            json.dump(expected, fh, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            fh.flush()
            flush_open_writable_file(fh.fileno())
        verify_persistent_json_file(tmp, expected=expected, context=tmp_context, require_match=True)
        if not _queue_atomic_replace(tmp, final, log_context=safe_log_context):
            try:
                _queue_safe_unlink(tmp, log_context=tmp_cleanup_context)
            except (OSError, RuntimeError, TypeError, ValueError) as cleanup_exc:
                record_scheduler_suppressed("queue_job_tmp_cleanup_failed", cleanup_exc)
            return _DURABLE_WRITE_FAILED
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        try:
            _queue_safe_unlink(tmp, log_context=durability_cleanup_context)
        except (OSError, RuntimeError, TypeError, ValueError) as cleanup_exc:
            record_scheduler_suppressed("queue_job_tmp_cleanup_failed", cleanup_exc, extra=path_extra)
        record_scheduler_suppressed("queue_job_durable_write_failed", exc, extra=path_extra, fatal=True)
        return _DURABLE_WRITE_FAILED
    else:
        return True


__all__ = ("_write_queue_job_json_durable",)
