"""Queue-owned claim failure/quarantine helpers."""
from __future__ import annotations

from pathlib import Path
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.scheduler.runtime.queue_json import make_json_safe
from Virus_Scan.scheduler.evidence.process_queue_errors import (
    processqueue_default_failure_info,
    record_scheduler_suppressed,
)
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path


def claim_failure_info(stage: str, exc: BaseException, *, worker_pid: int, attempt: object = None) -> dict[str, object]:
    return processqueue_default_failure_info(
        stage=stage,
        exception_type=no_hook_type_name(exc),
        error=scheduler_error_detail(exc),
        worker_pid=worker_pid,
        attempt=attempt,
    )


def job_with_claim_failure(job: object, failure_info: Mapping[str, object]) -> dict[str, object]:
    job_items = no_hook_mapping_items(job)
    source = dict(job_items) if job_items is not None else {
        "queue_job_unreadable": True,
        "queue_job_type": no_hook_type_name(job),
    }
    failure_items = no_hook_mapping_items(failure_info)
    safe_failure = (
        make_json_safe(dict(failure_items))
        if failure_items is not None
        else {
            "stage": "queue_claim_failure_info_rejected",
            "failure_info_type": no_hook_type_name(failure_info),
            "queue_failure": True,
        }
    )
    return {
        **source,
        "failure_info": dict.get(source, "failure_info", safe_failure),
        "queue_failure": dict.get(source, "queue_failure", True),
    }


def _claim_reason_text(value: object, *, missing_reason: str, unsupported_reason: str, empty_reason: str) -> tuple[str, str]:
    text, issue = no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)
    if issue == "" and text:
        return text, ""
    if issue:
        return issue, issue
    return empty_reason, empty_reason



def _claim_telemetry_stage(value: object, reason_text: str) -> tuple[str, str]:
    text, issue = no_hook_text(
        value,
        missing_reason="queue_claim_telemetry_stage_missing",
        unsupported_reason="queue_claim_telemetry_stage_rejected",
    )
    if issue == "" and text:
        return text, ""
    if issue == "queue_claim_telemetry_stage_missing":
        return str.__str__(reason_text) + "_quarantine_failed", issue
    if issue:
        return issue, issue
    return "queue_claim_telemetry_stage_empty", "queue_claim_telemetry_stage_empty"


def quarantine_invalid_claim(path: object, *, reason: str, job: object, identity: object, quarantine: object, telemetry_stage: str | None = None) -> None:
    safe_reason, reason_issue = _claim_reason_text(
        reason,
        missing_reason="queue_claim_quarantine_reason_missing",
        unsupported_reason="queue_claim_quarantine_reason_rejected",
        empty_reason="queue_claim_quarantine_reason_empty",
    )
    job_items = no_hook_mapping_items(job)
    safe_job = dict(job_items) if job_items is not None else {
        "queue_job_unreadable": True,
        "queue_job_type": no_hook_type_name(job),
    }
    try:
        quarantine(path, reason=safe_reason, job=safe_job, identity=identity)
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as exc:
        telemetry_reason, telemetry_issue = _claim_telemetry_stage(telemetry_stage, safe_reason)
        record_scheduler_suppressed(
            telemetry_reason,
            exc,
            extra={
                "claim_path_type": no_hook_type_name(path),
                "quarantine_reason_unavailable": reason_issue or None,
                "telemetry_stage_unavailable": telemetry_issue or None,
            },
            fatal=True,
        )


def validation_reason(validation_error: object, default: str) -> str:
    del default  # Explicitly unused contract parameters.
    items = no_hook_mapping_items(validation_error)
    if items is None:
        return "queue_claim_validation_error_rejected"
    value = dict.get(dict(items), "stage")
    stage_text, stage_issue = _claim_reason_text(
        value,
        missing_reason="queue_claim_validation_stage_missing",
        unsupported_reason="queue_claim_validation_stage_rejected",
        empty_reason="queue_claim_validation_stage_empty",
    )
    return stage_text if stage_issue == "" else stage_issue


def path_name(path: object) -> str:
    safe_path, reason = scheduler_filesystem_path(path)
    if reason:
        return "queue_claim_path_unavailable"
    return Path(safe_path).name


__all__ = (
    "claim_failure_info",
    "job_with_claim_failure",
    "path_name",
    "quarantine_invalid_claim",
    "validation_reason",
)
