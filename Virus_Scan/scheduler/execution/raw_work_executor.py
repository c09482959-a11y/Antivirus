"""Canonical raw work execution helpers.

The scheduler raw-work execution owner exposes deterministic module-level
operations: execute a callable into an execution envelope, and normalize a
raw-stage result into the same envelope.  No singleton executor object or
runtime dispatch layer is retained.
"""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value, scheduler_mapping_items_tuple, scheduler_str_key_mapping_from_items
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_sequence_items,
    no_hook_type_name,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.execution.raw_sequence_decision import (
    RawSequenceDecision,
    raw_sequence_decision,
)
from Virus_Scan.scheduler.execution.raw_execution_envelope import RawExecutionEnvelope
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.execution.raw_work_executor_support import (
    raw_execution_attempt,
    raw_execution_text,
    raw_result_error_text,
)
from Virus_Scan.scheduler.execution.raw_work_executor_types import (
    RawBoundaryIssues,
    RawCallable,
    RawCollectorResult,
    RawEnvelopeResult,
    raw_envelope_failure_result,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_error_detail,
    scheduler_path_text,
    scheduler_tag_texts,
)


def _raw_seq(value: object) -> int | None:
    return raw_sequence_decision(value).seq


def execute_raw_callable(
    file_path: object,
    stage: object,
    fn: RawCallable,
    *args: object,
    **kwargs: object,
) -> RawExecutionEnvelope:
    """Execute raw scanner work and return a deterministic envelope."""
    safe_file, file_reason = scheduler_path_text(file_path)
    safe_stage, stage_reason = raw_execution_text(
        stage, default_text="raw", field_name="stage"
    )
    context: RawBoundaryIssues = {}
    if file_reason:
        context["file_path_unavailable"] = raw_envelope_failure_result(
            file_path, field_name="file", reason=file_reason
        )
    if stage_reason:
        context["stage_unavailable"] = raw_envelope_failure_result(
            stage, field_name="stage", reason=stage_reason
        )
    try:
        result = fn(*args, **kwargs)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        error = scheduler_error_detail(exc)
        failure_result: RawEnvelopeResult = {
            "raw_execution_failed": True,
            "exception_type": no_hook_type_name(exc),
            "error": error,
            "scheduler_failure_reason": "raw_callable_exception",
        }
        if context:
            failure_result["raw_execution_context"] = context
        return RawExecutionEnvelope(safe_file, safe_stage, False, failure_result, error)
    success_result: RawEnvelopeResult = {"result": result}
    if context:
        success_result["raw_execution_context"] = context
    return RawExecutionEnvelope(safe_file, safe_stage, True, success_result)


def envelope_from_raw_result(job: object, result: object) -> RawExecutionEnvelope:
    """Normalize a raw-stage job/result pair into the accumulator envelope."""
    job_items = scheduler_mapping_items_tuple(job)
    result_items = scheduler_mapping_items_tuple(result)
    file_value = scheduler_mapping_item_value(job_items, "file", "")
    collector_value = scheduler_mapping_item_value(job_items, "collector", "raw_stage")
    safe_file, file_reason = scheduler_path_text(file_value)
    safe_collector, collector_reason = raw_execution_text(
        collector_value, default_text="raw_stage", field_name="collector"
    )
    error_value = scheduler_mapping_item_value(result_items, "error", "")
    error_text, error_reason = raw_result_error_text(error_value)
    if error_reason and error_value is not None:
        error_text = "raw result error rejected without caller hooks"
    attempt_value = scheduler_mapping_item_value(job_items, "attempt", 0)
    attempt, attempt_reason = raw_execution_attempt(attempt_value)
    seq = _raw_seq(scheduler_mapping_item_value(job_items, "seq", None))
    if result_items is None:
        result_snapshot: RawEnvelopeResult = raw_envelope_failure_result(
            result,
            field_name="raw_result",
            reason="non_materializable_raw_result_mapping",
        )
        error_text = error_text or "raw result mapping rejected without caller hooks"
    else:
        result_snapshot = scheduler_str_key_mapping_from_items(result_items)
    boundary_issues: RawBoundaryIssues = {}
    if job_items is None:
        boundary_issues["job_unavailable"] = raw_envelope_failure_result(
            job, field_name="raw_job", reason="non_materializable_raw_job_mapping"
        )
    if file_reason:
        boundary_issues["file_unavailable"] = raw_envelope_failure_result(
            file_value, field_name="file", reason=file_reason
        )
    if collector_reason:
        boundary_issues["collector_unavailable"] = raw_envelope_failure_result(
            collector_value, field_name="collector", reason=collector_reason
        )
    if error_reason:
        boundary_issues["error_unavailable"] = raw_envelope_failure_result(
            error_value, field_name="error", reason=error_reason
        )
    if attempt_reason:
        boundary_issues["attempt_unavailable"] = raw_envelope_failure_result(
            attempt_value, field_name="attempt", reason=attempt_reason
        )
    if boundary_issues:
        result_snapshot["raw_execution_boundary_evidence"] = boundary_issues
    return RawExecutionEnvelope(
        file=safe_file,
        collector=safe_collector,
        ok=not bool(error_text),
        result=result_snapshot,
        error=error_text,
        attempt=attempt,
        seq=seq,
    )


def normalize_raw_collector_value(value: object) -> RawCollectorResult:
    """Normalize raw collector return values so tuple returns never pollute tags."""
    if type(value) is dict:
        materialized = materialize_scheduler_mapping(value)
        if type(materialized) is dict:
            return materialized
        return {"meta": {"raw_collector_mapping_rejected": materialized}}
    meta: RawBoundaryIssues = {}
    if type(value) is tuple:
        first = value[0] if len(value) > 0 else []
        second = value[1] if len(value) > 1 else None
        tags = scheduler_tag_texts(first)
        if first is not None and not tags and no_hook_sequence_items(first) == ():
            meta["raw_collector_tags_unavailable"] = raw_envelope_failure_result(
                first, field_name="raw_collector_tags", reason="raw_collector_tags_rejected"
            )
        if type(second) is dict:
            meta_value = materialize_scheduler_mapping(second)
            if type(meta_value) is dict:
                meta.update(meta_value)
            else:
                meta["raw_collector_meta_unavailable"] = meta_value
        elif type(second) is bool:
            result: RawCollectorResult = {"tags": list(tags), "suspicious": second}
            if meta:
                result["meta"] = meta
            return result
        elif second is not None:
            meta["raw_collector_aux_unavailable"] = raw_envelope_failure_result(
                second, field_name="raw_collector_aux", reason="raw_collector_aux_rejected"
            )
        normalized: RawCollectorResult = {"tags": list(tags)}
        if meta:
            normalized["meta"] = meta
        return normalized
    items = no_hook_sequence_items(value)
    if items:
        return {"tags": list(scheduler_tag_texts(items))}
    return {
        "tags": [],
        "meta": {
            "raw_collector_value_unavailable": raw_envelope_failure_result(
                value, field_name="raw_collector_value", reason="raw_collector_value_rejected"
            ),
        },
    }
__all__ = ("RawSequenceDecision", "envelope_from_raw_result", "execute_raw_callable", "normalize_raw_collector_value", "raw_sequence_decision")
