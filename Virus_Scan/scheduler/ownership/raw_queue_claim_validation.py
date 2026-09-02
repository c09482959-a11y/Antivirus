"""Canonical claim-job validation for the raw/process queue boundary."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_materialize, no_hook_type_name
from Virus_Scan.scheduler.evidence.process_queue_errors import (
    processqueue_default_failure_info,
    record_scheduler_suppressed,
)
from Virus_Scan.scheduler.ownership.raw_queue_claim_raw import validate_raw_claim
from Virus_Scan.scheduler.ownership.raw_queue_claim_values import claim_text
from Virus_Scan.scheduler.queue.raw_accumulator_store import RawAccumulatorStore
from Virus_Scan.scheduler.runtime.queue_filesystem import global_raw_file_id


def repair_and_validate_claim_job(
    queue_dir: object,
    job: object,
    *,
    failure_info: Callable[..., dict[str, object]] = processqueue_default_failure_info,
    file_id_for_path: Callable[[object], str] = global_raw_file_id,
    accumulator_factory: Callable[[object, str], object] = RawAccumulatorStore,
    report: Callable[..., object] = record_scheduler_suppressed,
    worker_pid: int = 0,
) -> tuple[dict[str, object], dict[str, object] | None]:
    """Normalize one exact queue job and return optional terminal evidence."""
    if type(job) is not dict:
        evidence = {
            "queue_job_unreadable": True,
            "queue_job_unavailable_reason": "queue_claim_job_not_exact_mapping",
            "queue_job_type": no_hook_type_name(job),
            "queue_failure": True,
        }
        return evidence, failure_info(
            stage="queue_claim_invalid_job",
            exception_type="InvalidQueueJob",
            error="pending queue job JSON was unreadable or not an object after retry",
            worker_pid=worker_pid,
            attempt=None,
            extra=evidence,
        )
    normalized = dict.copy(job)
    job_type, job_type_reason = claim_text(
        dict.get(normalized, "job_type"), field="job_type", report=report
    )
    job_type = job_type.strip().lower()
    if (
        job_type == "raw_stage"
        or "file_id" in normalized
        or "raw_file_id" in normalized
        or "collector" in normalized
    ):
        return validate_raw_claim(
            queue_dir,
            normalized,
            job_type_reason=job_type_reason,
            failure_info=failure_info,
            file_id_for_path=file_id_for_path,
            accumulator_factory=accumulator_factory,
            report=report,
            worker_pid=worker_pid,
        )
    normalized["job_type"] = job_type if job_type and not job_type_reason else "file"
    file_path, file_reason = claim_text(
        dict.get(normalized, "file"), field="file", report=report
    )
    if file_path:
        normalized["file"] = file_path
    if file_path and not file_reason:
        return normalized, None
    return normalized, failure_info(
        stage="queue_claim_invalid_file_job",
        exception_type="InvalidFileQueueJob",
        error="file queue job was missing required file field",
        worker_pid=worker_pid,
        attempt=no_hook_materialize(
            dict.get(normalized, "attempt"), reason_prefix="queue_claim_attempt"
        ),
        extra={
            "job_type": normalized["job_type"],
            "queue_artifact": True,
            "file_unavailable_reason": file_reason or "queue_claim_file_missing",
        },
    )


__all__ = ("repair_and_validate_claim_job",)
