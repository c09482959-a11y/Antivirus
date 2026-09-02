"""Canonical no-hook support for process-queue partial-output publication."""

from __future__ import annotations

from pathlib import Path


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path

_PARTIAL_OUTPUT_OWNER_CONTEXT = "process_queue_partial_output"


def process_queue_partial_context_text(context: object) -> tuple[str, str]:
    """Return exact caller-owned context text, or an explicit rejection reason."""
    text = ""
    accepted_type = True
    if type(context) is str:
        text = str.__str__(context)
    elif type(context) is bytes or type(context) is bytearray:
        text = bytes(context).decode("utf-8", "replace")
    else:
        accepted_type = False
    reason = "" if text else "partial_output_context_missing"
    if not accepted_type:
        reason = "partial_output_context_rejected"
    return text, reason


def process_queue_partial_context_log_prefix(context: object) -> tuple[str, str]:
    text, reason = process_queue_partial_context_text(context)
    if reason:
        return _PARTIAL_OUTPUT_OWNER_CONTEXT, reason
    return text, ""


def process_queue_partial_output_message(field: str) -> str:
    if type(field) is not str or str.__str__(field) == "":
        return "process queue partial output field was unavailable"
    return "process queue partial output " + str.__str__(field) + " was unavailable"


def process_queue_partial_rejection_log_message(context: str, field: str, reason: str) -> str:
    """Return no-hook rejection log text for partial-output source failures."""
    context_text, context_reason = process_queue_partial_context_log_prefix(context)
    message = context_text + ": " + str.__str__(field) + " rejected without caller hooks: " + str.__str__(reason)
    if context_reason:
        return message + " context_reason=" + context_reason
    return message


def process_queue_partial_output_failure(
    *,
    reason: str,
    field: str,
    value: object,
    context: str,
    fatal: bool = False,
) -> SchedulerEvidenceRecord:
    """Build immutable scheduler evidence without invoking caller-owned hooks."""
    context_text, context_reason = process_queue_partial_context_text(context)
    evidence_context = {
        "field": field,
        "reason": reason,
        "value_type": no_hook_type_name(value),
    }
    if context_reason:
        evidence_context["context_reason"] = context_reason
    else:
        evidence_context["context"] = context_text
    return SchedulerEvidenceRecord(
        stage="process_queue_partial_output",
        state="failed" if fatal else "degraded",
        error_category=reason,
        error_source="scheduler.evidence.process_queue_partial_output",
        message=process_queue_partial_output_message(field),
        context=evidence_context,
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=fatal,
    )


def process_queue_partial_read_path(
    output: object,
    *,
    context: str,
) -> tuple[str | Path | None, SchedulerEvidenceRecord | None, str]:
    """Return an exact scheduler path, optional evidence, and rejection reason."""
    safe_output, reason = scheduler_filesystem_path(output)
    if reason:
        return None, process_queue_partial_output_failure(
            reason=reason,
            field="partial_output_source",
            value=output,
            context=context,
        ), reason
    if safe_output == "":
        return None, None, ""
    if type(safe_output) is str:
        return safe_output, None, ""
    return Path(safe_output), None, ""


__all__ = (
    "process_queue_partial_context_log_prefix",
    "process_queue_partial_context_text",
    "process_queue_partial_output_failure",
    "process_queue_partial_output_message",
    "process_queue_partial_rejection_log_message",
    "process_queue_partial_read_path",
)
