"""Queue-owned reclaimed-pending publication and quarantine handling."""
from __future__ import annotations

import json
from typing import Mapping, NoReturn

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.evidence.process_queue_errors import record_scheduler_suppressed
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_exception_text
from Virus_Scan.scheduler.runtime.queue_filesystem import (
    queue_safe_unlink as _queue_safe_unlink,
)
from Virus_Scan.scheduler.runtime.queue_json import queue_write_json_replace, read_json_file
from Virus_Scan.scheduler.queue.reclaim_publication_quarantine import quarantine_failed_reclaimed_pending_job
from Virus_Scan.scheduler.queue.reclaim_publication_support import (
    OrphanRecoveryActionEvidenceAppendRequest,
    append_action_evidence,
    exact_bool,
    filesystem_path,
    job_identifier,
    owned_job_record,
    path_evidence,
)


_RECLAIMED_PENDING_READBACK_MISSING_RETRY_METADATA = "reclaimed pending readback missing retry metadata"
_RECLAIMED_PENDING_VERIFIED_WRITE_FAILED = "reclaimed pending verified write failed"


def _raise_reclaimed_pending_readback_missing_retry_metadata() -> NoReturn:
    raise RuntimeError(_RECLAIMED_PENDING_READBACK_MISSING_RETRY_METADATA)


def _raise_reclaimed_pending_verified_write_failed() -> NoReturn:
    raise RuntimeError(_RECLAIMED_PENDING_VERIFIED_WRITE_FAILED)


def _publish_reclaimed_pending_job(
    queue_dir: object,
    pending_path: object,
    job: object,
    *,
    source_path: object = None,
    reason: str = "reclaim_annotate_pending",
    evidence_records: list[Mapping[str, object]] | None = None,
    safe_unlink: object=_queue_safe_unlink,
    record_suppressed: object=record_scheduler_suppressed,
) -> bool:
    """Publish reclaimed retry metadata or quarantine the pending artifact fail-closed.

    The canonical queue-publication writer is the sole reclaimed-job writer.
    """
    published = False
    pending_path = filesystem_path(pending_path, field_name="reclaim_pending_path")
    queue_path = filesystem_path(queue_dir, field_name="reclaim_queue_dir")
    job_record = owned_job_record(job)
    job_id = job_identifier(job_record)
    source_path_text = path_evidence(source_path, field_name="reclaim_source_path")
    pending_path_text = path_evidence(pending_path, field_name="reclaim_pending_path")
    try:
        if exact_bool(queue_write_json_replace(pending_path, job, tmp_suffix=".reclaim.tmp", verify=True, log_context=reason)):
            loaded = read_json_file(pending_path, default=None)
            if type(loaded) is dict:
                loaded_queue_info = dict.get(loaded, "queue_info")
                qi = loaded_queue_info if type(loaded_queue_info) is dict else {}
                if dict.get(loaded, "reclaimed_from_active") is True and dict.get(qi, "retry_pending_active") is True:
                    return True
            _raise_reclaimed_pending_readback_missing_retry_metadata()
        _raise_reclaimed_pending_verified_write_failed()
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        failure_info = {
            "stage": "reclaim_annotation_failed",
            "exception_type": no_hook_type_name(exc),
            "error": scheduler_exception_text(exc),
            "source_path": source_path_text,
            "pending_path": pending_path_text,
            "unsafe_to_continue": True,
        }
        record_suppressed(
            "queue_reclaim_annotation_failed",
            exc,
            extra={"pending_path": pending_path_text, "source_path": source_path_text},
            fatal=True,
        )
        append_action_evidence(
            OrphanRecoveryActionEvidenceAppendRequest(
                evidence_records=evidence_records,
                stage="queue_reclaim_annotation_failed",
                action="publish_reclaimed_pending_job",
                source_path=source_path,
                destination_path=pending_path,
                error=exc,
                error_source="reclaim_publication._publish_reclaimed_pending_job",
                job_id=job_id,
            )
        )
        quarantine_failed_reclaimed_pending_job(
            qdir=queue_path / "quarantine",
            pending_path=pending_path,
            failure_info=failure_info,
            job_record=job_record,
            job_id=job_id,
            safe_unlink=safe_unlink,
            record_suppressed=record_suppressed,
            evidence_records=evidence_records,
            pending_path_text=pending_path_text,
        )
    return published


__all__ = ("_publish_reclaimed_pending_job",)
