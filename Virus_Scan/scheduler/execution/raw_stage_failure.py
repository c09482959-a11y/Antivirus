"""Execution-owned raw-stage failure result construction.

This module owns degraded raw-stage result construction used by both process
queue raw jobs and in-memory raw scans.  Keeping this behavior in a small
execution-owned module avoids a circular dependency between scan-job execution
and in-memory raw dependency construction while preserving a single canonical
implementation.
"""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_error_detail, scheduler_tag_texts


def _bounded_raw_failure_text(value: object, default: str) -> str:
    text, reason = no_hook_text(value, missing_reason="raw_stage_failure_text_missing", unsupported_reason="raw_stage_failure_text_rejected")
    if reason or text == "":
        return default
    return text[:2000]








def raw_stage_failure_result(
    out: object,
    collector: object,
    exc: BaseException | None,
    *,
    stage: str = "raw_stage_execute",
    scanner_degraded_tags: Callable[[object], object],
) -> dict[str, object]:
    """Return canonical degraded raw-stage result for collector/runtime failures."""
    if type(out) is not dict:
        out = {
            "raw_stage_output_unavailable": unsupported_scheduler_value_evidence(
                out,
                field_name="raw_stage_failure_output",
            )
        }
    err_text = "raw stage failed" if exc is None else scheduler_error_detail(exc, max_length=2000)
    raw_collector = collector if collector is not None else dict.get(out, "collector")
    coll = _bounded_raw_failure_text(raw_collector, "raw_stage")
    failure_stage = _bounded_raw_failure_text(stage, "raw_stage_execute")
    exception_type = no_hook_type_name(exc) if isinstance(exc, BaseException) else "RawStageFailure"
    out["error"] = str.__add__(str.__add__(coll, ":"), err_text)
    out["failure_stage"] = failure_stage
    out["exception_type"] = exception_type
    out["tags"] = scanner_degraded_tags(scheduler_tag_texts(dict.get(out, "tags")))
    out["suspicious"] = False
    for key in (
        "raw_stage_failed",
        "queue_failure",
        "scheduler_failure",
        "scan_incomplete",
        "had_degraded_stage",
        "file_failed",
        "final_json_must_record",
        "checkpoint_must_record",
        "replay_must_record",
        "replay_must_reproduce",
    ):
        out[key] = True
    out["allow_learning"] = False
    out["scheduler_failure_reason"] = "raw_stage_failed"
    out["scheduler_failure_stage"] = failure_stage
    out["scheduler_failure_source"] = "scheduler.execution.raw_stage_failure"
    out["scheduler_failure_message"] = err_text
    evidence = SchedulerEvidenceRecord(
        stage=failure_stage,
        state="failed",
        error_category="raw_stage_failed",
        error_source="scheduler.execution.raw_stage_failure",
        message=err_text,
        context={
            "collector": coll,
            "exception_type": exception_type,
            "raw_stage_failed": True,
            "queue_failure": True,
            "scheduler_failure": True,
            "scan_incomplete": True,
            "allow_learning": False,
        },
        job_id=_bounded_raw_failure_text(dict.get(out, "file_id"), ""),
        path=_bounded_raw_failure_text(dict.get(out, "file"), ""),
        retry_state_affected=True,
        timeout_state_affected=isinstance(exc, TimeoutError),
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=False,
    ).as_dict()
    existing_failure_evidence = dict.get(out, "scheduler_failure_evidence")
    if type(existing_failure_evidence) is list:
        out["scheduler_failure_evidence"] = [*existing_failure_evidence, evidence]
    elif type(existing_failure_evidence) is tuple:
        out["scheduler_failure_evidence"] = [*existing_failure_evidence, evidence]
    else:
        out["scheduler_failure_evidence"] = [evidence]
    out["scan_integrity"] = {
        "raw_stage_failed": True,
        "queue_failure": True,
        "scheduler_failure": True,
        "scan_incomplete": True,
        "had_degraded_stage": True,
        "file_failed": True,
        "allow_learning": False,
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
        "failure_stage": failure_stage,
        "exception_type": exception_type,
    }
    existing_errors = dict.get(out, "errors")
    if type(existing_errors) is list:
        out["errors"] = [*existing_errors, out["error"]]
    elif type(existing_errors) is tuple:
        out["errors"] = [*existing_errors, out["error"]]
    else:
        out["errors"] = [out["error"]]
    return out


__all__ = ("raw_stage_failure_result",)
