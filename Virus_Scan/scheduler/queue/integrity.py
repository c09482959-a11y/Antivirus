"""Canonical raw queue integrity verification and repair helpers."""
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path, scheduler_path_text
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names
from Virus_Scan.scheduler.queue.integrity_contracts import QueueIdentityRecord
from Virus_Scan.scheduler.queue.integrity_record_support import identity_text
from Virus_Scan.scheduler.queue.integrity_evidence import (
    QueueExpectedFileCountDecision,
    QueueIdentityFailureRecordsDecision,
    queue_expected_file_count_decision,
    queue_identity_failure_records_decision,
)
from Virus_Scan.scheduler.queue.integrity_repair_support import verify_queue_integrity_with_dependencies
QUEUE_IDENTITY_COLLECTION_FAILED = "__queue_identity_collection_failed__"


@dataclass(frozen=True, slots=True)
class QueueIntegrityVerificationRequest:
    """Internal request for one queue-integrity verification pass."""

    queue_dir: object
    all_files: object
    phase: object
    repair: object
    ensure_dirs: object
    cleanup_diagnostic_tmp_files: object
    identity_collector: object
    active_claim_is_protected: object
    quarantine_job: object
    queue_now: object
    report: object


def _identity_collection_failed_records(groups: object) -> QueueIdentityFailureRecordsDecision:
    return queue_identity_failure_records_decision(
        groups,
        failure_key=QUEUE_IDENTITY_COLLECTION_FAILED,
    )


def _expected_file_count(files: object) -> QueueExpectedFileCountDecision:
    return queue_expected_file_count_decision(files)

def collect_jobs_by_identity(
    queue_dir: object,
    *,
    job_dirs: Callable[..., tuple[object, object, object, object]],
    safe_listdir: Callable[..., object],
    is_job_json_name: Callable[..., bool],
    read_json: Callable[..., object],
    job_identity: Callable[..., object],
    merge_claim_meta: Callable[..., object],
    report: Callable[..., object],
) -> object:
    """Return identity -> queue records, failing closed on incomplete scans."""
    groups = {}
    try:
        pending, active, done, failed = job_dirs(queue_dir)
        for state, d in (("pending", pending), ("active", active), ("done", done), ("failed", failed)):
            safe_path, path_reason = scheduler_filesystem_path(d)
            if path_reason:
                raise TypeError("queue directory rejected for " + state + ": " + path_reason)
            directory = Path(safe_path)
            for name in queue_listdir_names(safe_listdir(directory), context=directory):
                name_text = identity_text(name)
                if not is_job_json_name(name_text):
                    continue
                p = directory / name_text
                job = read_json(p, default={})
                if type(job) is not dict:
                    continue
                if state == "active":
                    job = merge_claim_meta(p, job)
                ident = identity_text(job_identity(job, name_text))
                record = QueueIdentityRecord.from_observation(state=state, path=p, name=name_text, job=job)
                if ident not in groups:
                    groups[ident] = []
                groups[ident].append(record.as_dict())
    except (OSError, TypeError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        queue_dir_text, queue_dir_reason = scheduler_path_text(queue_dir)
        queue_dir_evidence: dict[str, object] = {
            "queue_dir_available": queue_dir_reason == "",
            "queue_dir_text": queue_dir_text if queue_dir_reason == "" else "",
            "queue_dir_reason": queue_dir_reason,
        }
        if queue_dir_reason != "":
            queue_dir_evidence["queue_dir_rejected"] = unsupported_scheduler_value_evidence(
                queue_dir,
                field_name="queue_dir",
            )
        error_evidence = {
            "queue_identity_collection_failed": True,
            "queue_integrity_unavailable": True,
            "scheduler_failure_state": "queue_identity_collection_failed",
            "error_type": no_hook_type_name(exc),
            "error_detail": scheduler_error_detail(exc, max_length=500),
            "queue_dir_evidence": queue_dir_evidence,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }
        report("queue_identity_collection_failed", exc, fatal=True, extra={"queue_dir_evidence": queue_dir_evidence})
        return {
            QUEUE_IDENTITY_COLLECTION_FAILED: [
                {
                    "state": "queue_identity_collection_failed",
                    "path": "",
                    "name": "queue_identity_collection_failed",
                    "job": {"queue_info": error_evidence},
                    **error_evidence,
                }
            ]
        }
    return groups
def verify_and_repair_queue_integrity(
    request: QueueIntegrityVerificationRequest,
) -> object:
    """Verify queue integrity through the canonical immutable request owner."""
    return verify_queue_integrity_with_dependencies(
        request.queue_dir,
        all_files=request.all_files,
        phase=request.phase,
        repair=request.repair if type(request.repair) is bool else False,
        failure_key=QUEUE_IDENTITY_COLLECTION_FAILED,
        ensure_dirs=request.ensure_dirs,
        cleanup_diagnostic_tmp_files=request.cleanup_diagnostic_tmp_files,
        identity_collector=request.identity_collector,
        active_claim_is_protected=request.active_claim_is_protected,
        quarantine_job=request.quarantine_job,
        queue_now=request.queue_now,
        report=request.report,
    )


