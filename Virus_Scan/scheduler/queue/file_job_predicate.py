"""Queue-owned file-job admission predicates."""
from __future__ import annotations

import math
from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.evidence.process_queue_errors import record_scheduler_suppressed
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_value_snapshot


@dataclass(frozen=True)
class FileJobPredicateDecision:
    """Replayable queue-owned file-job predicate outcome."""

    is_file_job: bool
    reason: str
    field_name: str



def _record_file_job_predicate_rejection(field_name: str, value: object, reason: str) -> None:
    record_scheduler_suppressed(
        "process_queue_file_job_predicate_rejected",
        ValueError(reason),
        extra={
            "field_name": field_name,
            "reason": reason,
            "value_type": no_hook_type_name(value),
            "value": scheduler_value_snapshot(value, field_name=field_name),
        },
        fatal=False,
    )



def _coerce_file_job_type(job_type_value: object) -> tuple[str, str]:
    job_type = ""
    job_type_reason = ""
    if job_type_value is None:
        job_type = "file"
    elif type(job_type_value) is bool:
        job_type = "file" if job_type_value is False else "true"
    elif type(job_type_value) is int and job_type_value == 0:
        job_type = "file"
    elif type(job_type_value) is float and not math.isfinite(job_type_value):
        job_type_reason = "process_queue_file_job_type_rejected"
    elif type(job_type_value) is float and job_type_value == 0.0:
        job_type = "file"
    elif type(job_type_value) is str and str.__str__(job_type_value) == "":
        job_type = "file"
    elif type(job_type_value) in {bytes, bytearray} and len(job_type_value) == 0:
        job_type = "file"
    else:
        job_type, job_type_reason = no_hook_text(
            job_type_value,
            missing_reason="process_queue_file_job_type_missing",
            unsupported_reason="process_queue_file_job_type_rejected",
        )
    return job_type, job_type_reason


def _coerce_file_job_collector(collector_value: object) -> tuple[bool, str]:
    collector = False
    collector_reason = ""
    if collector_value is None:
        collector = False
    elif type(collector_value) is bool:
        collector = collector_value
    elif type(collector_value) is int:
        collector = collector_value != 0
    elif type(collector_value) is float and not math.isfinite(collector_value):
        collector_reason = "process_queue_file_job_collector_rejected"
    elif type(collector_value) is float:
        collector = collector_value != 0.0
    elif type(collector_value) is str:
        collector = str.__str__(collector_value) != ""
    elif type(collector_value) in {bytes, bytearray}:
        collector = len(collector_value) != 0
    else:
        collector_reason = "process_queue_file_job_collector_rejected"
    return collector, collector_reason


def process_queue_file_job_decision(job: object) -> FileJobPredicateDecision:
    """Return the replayable queue-owned file-job predicate decision."""
    if type(job) is not dict:
        return FileJobPredicateDecision(
            is_file_job=False,
            reason="process_queue_file_job_record_rejected",
            field_name="job",
        )
    job_type_value = dict.get(job, "job_type")
    job_type, job_type_reason = _coerce_file_job_type(job_type_value)
    if job_type_reason:
        _record_file_job_predicate_rejection(
            "job_type",
            job_type_value,
            job_type_reason,
        )
        return FileJobPredicateDecision(
            is_file_job=False,
            reason=job_type_reason,
            field_name="job_type",
        )
    if job_type == "raw_stage":
        return FileJobPredicateDecision(
            is_file_job=False,
            reason="process_queue_file_job_raw_stage",
            field_name="job_type",
        )
    collector_value = dict.get(job, "collector")
    collector, collector_reason = _coerce_file_job_collector(collector_value)
    if collector_reason:
        _record_file_job_predicate_rejection(
            "collector",
            collector_value,
            collector_reason,
        )
        return FileJobPredicateDecision(
            is_file_job=False,
            reason=collector_reason,
            field_name="collector",
        )
    return FileJobPredicateDecision(
        is_file_job=not collector,
        reason=(
            "process_queue_file_job_collector_present"
            if collector
            else "process_queue_file_job_admitted"
        ),
        field_name="collector" if collector else "",
    )


def process_queue_is_file_job(job: object) -> bool:
    """Return whether an admitted process-queue record is a normal file job.

    Queue ownership controls this predicate because it determines which pending
    records are eligible for file-worker claiming. The public API preserves the
    historical bool contract while the decision owner above records the exact
    unavailable or rejected state instead of hiding it behind local defaults.
    """
    return process_queue_file_job_decision(job).is_file_job


__all__ = (
    "FileJobPredicateDecision",
    "process_queue_file_job_decision",
    "process_queue_is_file_job",
)
